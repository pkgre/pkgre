//! Format-preserving mirror declaration edits for admitted updates.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, ensure};
use semver::Version;
use toml_edit::{DocumentMut, Item};

use crate::category::CategoryId;
use crate::schema::{CategoryDeclaration, RegistryInput, load_registry_inputs, version_identity};

use super::UpdateCandidate;

static EDIT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Appends one exact candidate to its existing mirror declaration without rewriting unrelated TOML.
pub(crate) fn append_mirror_version(root: &Path, candidate: &UpdateCandidate) -> Result<()> {
    let category_id = candidate
        .category
        .parse::<CategoryId>()
        .context("parse update candidate category")?;
    ensure!(
        category_id.registry() == candidate.registry,
        "candidate category {} does not belong to registry {:?}",
        candidate.category,
        candidate.registry
    );
    let inputs = load_registry_inputs(root).context("load staged declarations for update edit")?;
    let input = inputs
        .iter()
        .find(|input| input.file.registry.name == candidate.registry)
        .with_context(|| format!("candidate registry {:?} is absent", candidate.registry))?;
    let category = input
        .file
        .categories
        .get(category_id.local())
        .with_context(|| format!("candidate category {} is absent", candidate.category))?;
    let declared = category.mirror.get(&candidate.name).with_context(|| {
        format!(
            "candidate package {:?} is not a mirror declaration in {}",
            candidate.name, candidate.category
        )
    })?;
    ensure!(
        !declared.iter().any(|version| {
            version_identity(version) == version_identity(&candidate.candidate.version)
        }),
        "candidate identity {} {} is already declared",
        candidate.name,
        candidate.candidate.version
    );

    edit_mirror_declaration(
        &category.declared_in,
        path_is_registry_input(input, category),
        &category_id,
        candidate,
    )
}

fn path_is_registry_input(input: &RegistryInput, category: &CategoryDeclaration) -> bool {
    category.declared_in == input.path
}

fn edit_mirror_declaration(
    path: &Path,
    inline: bool,
    category_id: &CategoryId,
    candidate: &UpdateCandidate,
) -> Result<()> {
    let bytes =
        fs::read(path).with_context(|| format!("read candidate declaration {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("candidate declaration is not UTF-8: {}", path.display()))?;
    let mut document = text
        .parse::<DocumentMut>()
        .with_context(|| format!("parse editable TOML {}", path.display()))?;
    let item = if inline {
        nested_item_mut(
            &mut document,
            &["categories", category_id.local(), "mirror", &candidate.name],
            path,
        )?
    } else {
        nested_item_mut(&mut document, &["mirror", &candidate.name], path)?
    };
    insert_canonical_version(item, path, &candidate.name, &candidate.candidate.version)?;
    replace_regular_file(path, document.to_string().as_bytes())
}

fn insert_canonical_version(
    item: &mut Item,
    path: &Path,
    name: &str,
    candidate: &Version,
) -> Result<()> {
    let versions = item.as_array_mut().with_context(|| {
        format!(
            "mirror declaration for {name:?} is not an array in {}",
            path.display()
        )
    })?;
    let mut parsed = versions
        .iter()
        .map(|value| {
            value
                .as_str()
                .with_context(|| {
                    format!(
                        "mirror version for {name:?} is not a string in {}",
                        path.display()
                    )
                })?
                .parse::<Version>()
                .with_context(|| {
                    format!(
                        "mirror version for {name:?} is not SemVer in {}",
                        path.display()
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        parsed.windows(2).all(|window| window[0] < window[1]),
        "mirror versions for {name:?} are not in canonical SemVer order in {}",
        path.display()
    );
    ensure!(
        !parsed
            .iter()
            .any(|version| version_identity(version) == version_identity(candidate)),
        "candidate identity {name} {candidate} is already present in editable TOML"
    );
    let insertion = parsed
        .binary_search(candidate)
        .unwrap_or_else(std::convert::identity);
    versions.insert(insertion, candidate.to_string());
    parsed.insert(insertion, candidate.clone());
    ensure!(
        parsed.windows(2).all(|window| window[0] < window[1]),
        "candidate {name} {candidate} cannot be inserted in strict SemVer order"
    );
    Ok(())
}

fn nested_item_mut<'a>(
    document: &'a mut DocumentMut,
    path: &[&str],
    source: &Path,
) -> Result<&'a mut Item> {
    let (first, remaining) = path.split_first().context("empty editable TOML path")?;
    let mut item = document.get_mut(first).with_context(|| {
        format!(
            "missing TOML key {:?} while editing {}",
            path.join("."),
            source.display()
        )
    })?;
    for key in remaining {
        item = item
            .as_table_like_mut()
            .and_then(|table| table.get_mut(key))
            .with_context(|| {
                format!(
                    "missing TOML key {:?} while editing {}",
                    path.join("."),
                    source.display()
                )
            })?;
    }
    Ok(item)
}

fn replace_regular_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect declaration {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "declaration is not a regular file: {}",
        path.display()
    );
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("declaration filename is not valid UTF-8")?;
    let temporary = temporary_path(parent, filename)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("create edited declaration {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write edited declaration {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync edited declaration {}", temporary.display()))?;
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "install edited declaration {} as {}",
                temporary.display(),
                path.display()
            )
        })?;
        File::open(parent)
            .with_context(|| format!("open declaration directory {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("sync declaration directory {}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(parent: &Path, filename: &str) -> Result<PathBuf> {
    for _ in 0..100 {
        let sequence = EDIT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{filename}.pkgre-edit-{}-{sequence}",
            std::process::id()
        ));
        match fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect edit path {}", candidate.display()));
            }
        }
    }
    anyhow::bail!(
        "could not allocate an edit path beside {}",
        parent.display()
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::update::{
        ArchiveSummary, DependencyDelta, PackageActivity, PlannedIdentity, SourceEvidence,
        UpdateDecision, UtcTimestamp,
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn inline_edit_preserves_comments_and_inserts_in_semver_order() {
        let root = temporary_directory("inline");
        let input = concat!(
            "# keep-root\n",
            "schema = 3\n\n",
            "[registry]\n",
            "name = \"universe\"\n",
            "index = \"sparse+https://rust.pkg.re/universe/\"\n",
            "download = \"https://static.crates.io/crates\"\n",
            "cargo-version = \"1.95.0\"\n\n",
            "[categories.general]\n",
            "may-depend-on = [\"universe/general\"]\n\n",
            "[categories.general.mirror]\n",
            "# keep-package\n",
            "demo = [\"1.0.0\", \"1.2.0\"] # keep-tail\n",
        );
        fs::write(root.join("universe.toml"), input).unwrap();

        append_mirror_version(&root, &candidate("1.1.0")).unwrap();

        let output = fs::read_to_string(root.join("universe.toml")).unwrap();
        assert_eq!(
            output,
            input.replace(
                "demo = [\"1.0.0\", \"1.2.0\"]",
                "demo = [\"1.0.0\", \"1.1.0\", \"1.2.0\"]"
            )
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_edit_changes_only_referenced_category_file() {
        let root = temporary_directory("external");
        fs::create_dir_all(root.join("categories/universe")).unwrap();
        let registry = concat!(
            "schema = 3\n\n",
            "[registry]\n",
            "name = \"universe\"\n",
            "index = \"sparse+https://rust.pkg.re/universe/\"\n",
            "download = \"https://static.crates.io/crates\"\n",
            "cargo-version = \"1.95.0\"\n\n",
            "[categories.general]\n",
            "file = \"categories/universe/general.toml\"\n",
        );
        let category = concat!(
            "schema = 3\n",
            "may-depend-on = [\"universe/general\"]\n\n",
            "[mirror]\n",
            "# retained\n",
            "demo = [\"1.0.0\"]\n",
        );
        fs::write(root.join("universe.toml"), registry).unwrap();
        fs::write(root.join("categories/universe/general.toml"), category).unwrap();

        append_mirror_version(&root, &candidate("1.1.0")).unwrap();

        assert_eq!(
            fs::read_to_string(root.join("universe.toml")).unwrap(),
            registry
        );
        assert_eq!(
            fs::read_to_string(root.join("categories/universe/general.toml")).unwrap(),
            category.replace("demo = [\"1.0.0\"]", "demo = [\"1.0.0\", \"1.1.0\"]")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_route_identity_and_order_leave_declaration_unchanged() {
        let cases = [
            (
                "wrong-registry",
                "pkgre",
                "universe/general",
                "demo",
                "1.1.0",
            ),
            (
                "wrong-category",
                "universe",
                "universe/other",
                "demo",
                "1.1.0",
            ),
            (
                "wrong-package",
                "universe",
                "universe/general",
                "other",
                "1.1.0",
            ),
            ("duplicate", "universe", "universe/general", "demo", "1.0.0"),
            (
                "build-duplicate",
                "universe",
                "universe/general",
                "demo",
                "1.0.0+other",
            ),
        ];
        for (label, registry, category, name, version) in cases {
            let root = temporary_directory(label);
            let input = inline_registry("[\"1.0.0+source\", \"1.2.0\"]");
            fs::write(root.join("universe.toml"), &input).unwrap();
            let mut candidate = candidate(version);
            candidate.registry = registry.to_owned();
            candidate.category = category.to_owned();
            candidate.name = name.to_owned();
            assert!(append_mirror_version(&root, &candidate).is_err(), "{label}");
            assert_eq!(
                fs::read_to_string(root.join("universe.toml")).unwrap(),
                input
            );
            fs::remove_dir_all(root).unwrap();
        }

        let root = temporary_directory("order");
        let input = inline_registry("[\"1.2.0\", \"1.0.0\"]");
        fs::write(root.join("universe.toml"), &input).unwrap();
        assert!(append_mirror_version(&root, &candidate("1.1.0")).is_err());
        assert_eq!(
            fs::read_to_string(root.join("universe.toml")).unwrap(),
            input
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn external_declaration_symlink_is_rejected_without_mutation() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory("symlink");
        fs::create_dir_all(root.join("categories/universe")).unwrap();
        fs::write(
            root.join("universe.toml"),
            concat!(
                "schema = 3\n\n",
                "[registry]\n",
                "name = \"universe\"\n",
                "index = \"sparse+https://rust.pkg.re/universe/\"\n",
                "download = \"https://static.crates.io/crates\"\n",
                "cargo-version = \"1.95.0\"\n\n",
                "[categories.general]\n",
                "file = \"categories/universe/general.toml\"\n",
            ),
        )
        .unwrap();
        let category = concat!(
            "schema = 3\n",
            "may-depend-on = [\"universe/general\"]\n\n",
            "[mirror]\n",
            "demo = [\"1.0.0\"]\n",
        );
        fs::write(root.join("target.toml"), category).unwrap();
        symlink(
            root.join("target.toml"),
            root.join("categories/universe/general.toml"),
        )
        .unwrap();
        assert!(append_mirror_version(&root, &candidate("1.1.0")).is_err());
        assert_eq!(
            fs::read_to_string(root.join("target.toml")).unwrap(),
            category
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn inline_registry(versions: &str) -> String {
        format!(
            concat!(
                "schema = 3\n\n",
                "[registry]\n",
                "name = \"universe\"\n",
                "index = \"sparse+https://rust.pkg.re/universe/\"\n",
                "download = \"https://static.crates.io/crates\"\n",
                "cargo-version = \"1.95.0\"\n\n",
                "[categories.general]\n",
                "may-depend-on = [\"universe/general\"]\n\n",
                "[categories.general.mirror]\n",
                "demo = {}\n",
            ),
            versions
        )
    }

    fn candidate(version: &str) -> UpdateCandidate {
        UpdateCandidate {
            registry: "universe".to_owned(),
            category: "universe/general".to_owned(),
            name: "demo".to_owned(),
            activity: PackageActivity::Active,
            lane: None,
            base: None,
            candidate: PlannedIdentity {
                version: Version::parse(version).unwrap(),
                published_at: UtcTimestamp::parse("2025-01-01T00:00:00Z").unwrap(),
                source_row_sha256: "01".repeat(32),
                crate_sha256: "02".repeat(32),
            },
            sparse_index_sha256: "03".repeat(32),
            decision_history_sha256: "04".repeat(32),
            age_seconds: 30 * 24 * 60 * 60,
            dormant_gap: None,
            base_archive: None,
            candidate_archive: ArchiveSummary {
                analysis_sha256: "05".repeat(32),
                compressed_bytes: 1,
                unpacked_bytes: 1,
                files: 1,
                build_surface: BTreeMap::new(),
                vcs_commit: None,
                vcs_path: None,
            },
            archive_delta: None,
            dependencies: DependencyDelta {
                added: Vec::new(),
                removed: Vec::new(),
                new_packages: Vec::new(),
            },
            api: None,
            source: SourceEvidence::Unavailable {
                reason: "not-promoted".to_owned(),
            },
            decision: UpdateDecision::Automatic,
            reasons: Vec::new(),
            approvals: Vec::new(),
        }
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pkgre-update-declaration-{name}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }
}
