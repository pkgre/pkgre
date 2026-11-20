//! Offline whole-catalog validation for the `check` command.

use std::path::Path;

use anyhow::{Context, Result};

use crate::artifact::ArtifactMap;
use crate::lock::validate_routed_rows;
use crate::policy::validate_catalog;
use crate::projection::{CatalogProjection, ProjectionLimits, ProjectionUsage};
use crate::schema::Catalog;

/// A projection limit is reported once its usage reaches `1 / NEAR_LIMIT_DIVISOR` of its budget.
const NEAR_LIMIT_DIVISOR: u64 = 2;

/// What one successful `check` established about the catalog it validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckSummary {
    /// Retained state of the serving projection built from the catalog.
    pub usage: ProjectionUsage,
    /// Projection limits the catalog was checked against.
    pub limits: ProjectionLimits,
}

impl CheckSummary {
    /// Returns `name=usage/limit` for every projection limit this catalog has reached half of.
    ///
    /// Limits are reported in the order of their `ProjectionLimits` fields, so a log line stays
    /// stable as a catalog grows toward its budgets.
    #[must_use]
    pub fn margins(&self) -> String {
        [
            ("approvals", self.usage.approvals, self.limits.max_approvals),
            ("routes", self.usage.routes, self.limits.max_routes),
            (
                "inline_body_bytes",
                self.usage.inline_body_bytes,
                self.limits.max_inline_body_bytes,
            ),
            (
                "inline_bytes",
                self.usage.inline_bytes,
                self.limits.max_inline_bytes,
            ),
            ("archives", self.usage.archives, self.limits.max_archives),
            (
                "archive_body_bytes",
                self.usage.archive_body_bytes,
                self.limits.max_archive_body_bytes,
            ),
            (
                "archive_bytes",
                self.usage.archive_bytes,
                self.limits.max_archive_bytes,
            ),
            (
                "snapshot_body_bytes",
                self.usage.snapshot_body_bytes,
                self.limits.max_snapshot_body_bytes,
            ),
        ]
        .into_iter()
        .filter(|(_, usage, limit)| usage.saturating_mul(NEAR_LIMIT_DIVISOR) >= *limit)
        .map(|(name, usage, limit)| format!("{name}={usage}/{limit}"))
        .collect::<Vec<_>>()
        .join(" ")
    }
}

/// Validates one catalog as `lock` and the serving origin would, without network access.
///
/// Runs the strict catalog load, policy validation, and object-store verification, then the
/// routed-row hash and dependency-edge checks that `lock` performs, and finally builds the
/// serving projection under the production projection limits. The archive store that the serving
/// body mode needs is neither required nor read: every retained archive body comes from the
/// catalog's own object store.
///
/// # Errors
///
/// Returns an error for any invalid, stale, or unservable catalog: a malformed declaration or
/// generated lock, a missing or mismatched object, a routed-row hash that differs from the lock, a
/// dependency edge its source category does not permit, or a catalog that exceeds a production
/// projection limit.
pub fn check(root: &Path) -> Result<CheckSummary> {
    check_with_limits(root, ProjectionLimits::PRODUCTION)
}

/// Runs every `check` stage under explicit projection limits.
///
/// `check` itself always passes [`ProjectionLimits::PRODUCTION`]; tests lower the limits so that a
/// small catalog can cross one.
fn check_with_limits(root: &Path, limits: ProjectionLimits) -> Result<CheckSummary> {
    let catalog = Catalog::load(root)?;
    let policy = validate_catalog(&catalog)?;
    let artifacts = ArtifactMap::load(&catalog)?;
    validate_routed_rows(&catalog, &policy, &artifacts)?;
    let projection = CatalogProjection::from_catalog_with_limits(&catalog, &artifacts, limits)
        .with_context(|| format!("project serving catalog {}", root.display()))?;
    Ok(CheckSummary {
        usage: projection.usage(),
        limits,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use anyhow::bail;
    use semver::Version;
    use serde_json::json;

    use super::*;
    use crate::artifact::sha256_bytes;
    use crate::download::router_download_template;
    use crate::lock::{self, ResolvedPackage, Resolver};
    use crate::schema::LockedSource;
    use crate::update::UtcTimestamp;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn a_valid_catalog_passes_under_the_production_limits() {
        let temporary = TemporaryDirectory::new("pkgre-check-valid");
        let root = temporary.path().join("catalog");
        write_catalog(&root);
        reconcile(&root);

        let summary = check(&root).unwrap();

        let archive_bytes = fixture_archive("leaf-core", "1.0.0").len() as u64
            + fixture_archive("matrix-middle", "1.0.0").len() as u64;
        assert_eq!(summary.limits, ProjectionLimits::PRODUCTION);
        assert_eq!(summary.usage.approvals, 2);
        assert_eq!(summary.usage.archives, 2);
        assert_eq!(summary.usage.archive_bytes, archive_bytes);
        assert_eq!(
            summary.usage.snapshot_body_bytes,
            summary.usage.archive_bytes + summary.usage.inline_bytes
        );
        assert_eq!(summary.margins(), "");
    }

    #[test]
    fn a_stale_routed_row_hash_is_refused_exactly_as_lock_refuses_it() {
        let temporary = TemporaryDirectory::new("pkgre-check-stale-row");
        let root = temporary.path().join("catalog");
        write_catalog(&root);
        reconcile(&root);
        let lock_path = root.join("main.lock");
        let lock = fs::read_to_string(&lock_path).unwrap();
        fs::write(&lock_path, with_stale_index_row_hash(&lock)).unwrap();

        let failure = check(&root).unwrap_err();
        let lock_failure = lock::reconcile(&root).unwrap_err();

        assert!(
            format!("{failure:#}").starts_with("routed index-row hash mismatch for "),
            "{failure:#}"
        );
        assert_eq!(format!("{failure:#}"), format!("{lock_failure:#}"));
    }

    #[test]
    fn a_dependency_edge_outside_the_allowed_categories_is_refused() {
        let temporary = TemporaryDirectory::new("pkgre-check-forbidden-edge");
        let root = temporary.path().join("catalog");
        write_catalog(&root);
        reconcile(&root);
        let registry_path = root.join("main.toml");
        let registry = fs::read_to_string(&registry_path).unwrap();
        let reduced = registry.replace(
            "may-depend-on = [\"main/matrix\", \"main/general\"]",
            "may-depend-on = [\"main/matrix\"]",
        );
        assert_ne!(reduced, registry);
        fs::write(&registry_path, reduced).unwrap();

        let failure = check(&root).unwrap_err();

        assert!(
            format!("{failure:#}").contains("may not depend on leaf-core in main/general"),
            "{failure:#}"
        );
    }

    #[test]
    fn a_catalog_over_a_projection_limit_is_refused() {
        let temporary = TemporaryDirectory::new("pkgre-check-projection-limit");
        let root = temporary.path().join("catalog");
        write_catalog(&root);
        reconcile(&root);
        let limits = ProjectionLimits {
            max_archives: 1,
            ..ProjectionLimits::PRODUCTION
        };

        let failure = check_with_limits(&root, limits).unwrap_err();

        assert!(
            format!("{failure:#}").contains("retained archives 2 exceeds configured limit 1"),
            "{failure:#}"
        );
    }

    #[test]
    fn margins_report_every_limit_that_is_half_spent_and_no_other() {
        let limits = ProjectionLimits::PRODUCTION;
        let half = CheckSummary {
            usage: half_of(limits),
            limits,
        };
        assert_eq!(
            half.margins(),
            "approvals=5000/10000 routes=10000/20000 inline_body_bytes=8388608/16777216 \
             inline_bytes=67108864/134217728 archives=5000/10000 \
             archive_body_bytes=52428800/104857600 archive_bytes=268435456/536870912 \
             snapshot_body_bytes=268435456/536870912"
        );

        let below = CheckSummary {
            usage: just_below_half_of(limits),
            limits,
        };
        assert_eq!(below.margins(), "");

        let production = CheckSummary {
            usage: ProjectionUsage {
                approvals: 833,
                routes: 1508,
                inline_bytes: 2_085_191,
                archives: 833,
                archive_bytes: 138_448_077,
                snapshot_body_bytes: 140_533_268,
                ..ProjectionUsage::default()
            },
            limits,
        };
        assert_eq!(production.margins(), "");

        let many_archives = CheckSummary {
            usage: ProjectionUsage {
                archives: 5_000,
                ..ProjectionUsage::default()
            },
            limits,
        };
        assert_eq!(many_archives.margins(), "archives=5000/10000");
    }

    fn half_of(limits: ProjectionLimits) -> ProjectionUsage {
        ProjectionUsage {
            approvals: limits.max_approvals / 2,
            routes: limits.max_routes / 2,
            inline_body_bytes: limits.max_inline_body_bytes / 2,
            inline_bytes: limits.max_inline_bytes / 2,
            archives: limits.max_archives / 2,
            archive_body_bytes: limits.max_archive_body_bytes / 2,
            archive_bytes: limits.max_archive_bytes / 2,
            snapshot_body_bytes: limits.max_snapshot_body_bytes / 2,
        }
    }

    fn just_below_half_of(limits: ProjectionLimits) -> ProjectionUsage {
        let half = half_of(limits);
        ProjectionUsage {
            approvals: half.approvals - 1,
            routes: half.routes - 1,
            inline_body_bytes: half.inline_body_bytes - 1,
            inline_bytes: half.inline_bytes - 1,
            archives: half.archives - 1,
            archive_body_bytes: half.archive_body_bytes - 1,
            archive_bytes: half.archive_bytes - 1,
            snapshot_body_bytes: half.snapshot_body_bytes - 1,
        }
    }

    /// Returns the exact archive bytes the fixture resolver produces for one identity.
    fn fixture_archive(package_name: &str, version: &str) -> Vec<u8> {
        format!("fixture archive for {package_name} {version}\n").into_bytes()
    }

    /// Writes one schema-5 catalog whose two Git-tag packages form a permitted dependency edge.
    fn write_catalog(root: &Path) {
        fs::create_dir_all(root).unwrap();
        let index = crate::policy::canonical_registry_index("main");
        let download = router_download_template("main");
        let mut registry = format!(
            "schema = 5\n\n[registry]\nname = \"main\"\nindex = {index:?}\n\
             download = {download:?}\naudience = \"public\"\ncargo-version = \"1.95.0\"\n\n"
        );
        registry.push_str(concat!(
            "[categories.general]\n",
            "may-depend-on = [\"main/general\"]\n\n",
            "[categories.general.publish.leaf-core]\n",
            "git = \"https://github.com/pkgre/leaf-core\"\n",
            "tags = [\"leaf-core/v1.0.0\"]\n\n",
            "[categories.matrix]\n",
            "may-depend-on = [\"main/matrix\", \"main/general\"]\n\n",
            "[categories.matrix.publish.matrix-middle]\n",
            "git = \"https://github.com/pkgre/matrix-middle\"\n",
            "tags = [\"matrix-middle/v1.0.0\"]\n",
        ));
        fs::write(root.join("main.toml"), registry).unwrap();
    }

    /// Reconciles the written declarations into generated locks and objects without a network.
    fn reconcile(root: &Path) {
        lock::reconcile_admitted_with(root, &[], &FixtureResolver).unwrap();
    }

    /// Replaces the first locked routed-row hash with a different valid digest.
    fn with_stale_index_row_hash(lock: &str) -> String {
        const KEY: &str = "index-row-sha256 = \"";
        let start = lock.find(KEY).unwrap() + KEY.len();
        let digest = &lock[start..start + 64];
        let mut stale = digest.to_owned();
        stale.replace_range(..1, if digest.starts_with('0') { "1" } else { "0" });
        format!("{}{stale}{}", &lock[..start], &lock[start + 64..])
    }

    /// Resolves every declared Git tag to a small synthetic package and archive.
    struct FixtureResolver;

    impl Resolver for FixtureResolver {
        fn resolve_mirror(&self, _: &str, _: &Version) -> Result<ResolvedPackage> {
            bail!("fixture resolves no crates.io identities")
        }

        fn resolve_git_tag_group(
            &self,
            repository: &str,
            tag: &str,
            packages: &[&str],
            _published: &[crate::package::PublishedPackage<'_>],
            cargo_version: &Version,
            _native: Option<&crate::package::NativeCatalog<'_>>,
        ) -> Result<Vec<ResolvedPackage>> {
            let version = Version::parse(
                tag.rsplit('/')
                    .next()
                    .expect("validated tag is nonempty")
                    .trim_start_matches('v'),
            )?;
            let mut resolved = Vec::with_capacity(packages.len());
            for package_name in packages {
                let archive_bytes = fixture_archive(package_name, &version.to_string());
                let mut source_row_bytes = serde_json::to_vec(&json!({
                    "name": package_name,
                    "vers": version.to_string(),
                    "deps": fixture_dependencies(package_name),
                    "cksum": sha256_bytes(&archive_bytes),
                    "features": {},
                    "yanked": false,
                }))?;
                source_row_bytes.push(b'\n');
                resolved.push(ResolvedPackage {
                    name: (*package_name).to_owned(),
                    version: version.clone(),
                    archive_bytes,
                    source_row_bytes,
                    published_at: Some(UtcTimestamp::parse("2026-01-01T00:00:00Z")?),
                    source: LockedSource::GitTag {
                        git: repository.to_owned(),
                        tag: tag.to_owned(),
                        tag_oid: "0".repeat(40),
                        commit: "1".repeat(40),
                        package: (*package_name).to_owned(),
                        path: PathBuf::from("."),
                        cargo_version: cargo_version.clone(),
                    },
                });
            }
            Ok(resolved)
        }
    }

    fn fixture_dependencies(package_name: &str) -> Vec<serde_json::Value> {
        let packages: &[&str] = match package_name {
            "matrix-middle" => &["leaf-core"],
            _ => &[],
        };
        packages
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "req": "^1.0.0",
                    "features": [],
                    "optional": false,
                    "default_features": true,
                    "target": null,
                    "kind": "normal",
                    "registry": null,
                    "package": null,
                })
            })
            .collect()
    }

    struct TemporaryDirectory {
        path: PathBuf,
    }

    impl TemporaryDirectory {
        fn new(prefix: &str) -> Self {
            let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{sequence}", std::process::id()));
            match fs::remove_dir_all(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove stale test directory: {error}"),
            }
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}
