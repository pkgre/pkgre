//! The crates.io-native declarations that stand beside one catalog.
//!
//! `lock`, the reconciliation of `update-apply`, and `reproduce-git-tags` read
//! `<catalog>/../self-publish/crates-io.toml` only to learn which
//! self-publishing repositories keep crates.io manifests, and then the active
//! identities of the catalog that such a repository's release tag may name.
//! They never read `crates-io.lock`, since none of them writes an entry, and a
//! catalog without the directory declares no native repository.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::config::CratesIoConfig;
use super::state::{CONFIG_FILE, STATE_DIRECTORY};
use crate::package::{NativeCatalog, NativeIdentity, NativeLocked};
use crate::schema::{Approval, PackageState, Source};

/// The self-publishing declarations of one catalog repository, as a command
/// that packages or reproduces a release tag reads them.
#[derive(Debug)]
pub(crate) struct NativeRepositories {
    /// The human declarations, when the repository declares any.
    config: Option<CratesIoConfig>,
}

impl NativeRepositories {
    /// Loads the declarations that stand beside one catalog.
    ///
    /// A catalog whose repository has no `self-publish/` directory, or one
    /// without `crates-io.toml`, declares no native repository. A malformed
    /// file fails the command, since a repository's mode is permanent and a
    /// command that cannot read it cannot know what its release tags hold.
    ///
    /// # Errors
    ///
    /// Returns an error for a catalog root that cannot be resolved, for one
    /// without a parent directory, for a self-publishing directory or file that
    /// is not one, or for a malformed declaration.
    pub(crate) fn load_beside(catalog_root: &Path) -> Result<Self> {
        // A caller may name the catalog by a path such as `.`, or one with a
        // trailing `.`; resolving it first makes its parent the repository that
        // holds `self-publish/`, which is what the declarations stand beside.
        let catalog = fs::canonicalize(catalog_root)
            .with_context(|| format!("resolve catalog root {}", catalog_root.display()))?;
        let repository = catalog.parent().with_context(|| {
            format!(
                "catalog root {} has no parent directory to hold self-publish/",
                catalog.display()
            )
        })?;
        let directory = repository.join(STATE_DIRECTORY);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self { config: None }),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect self-publishing directory {}", directory.display())
                });
            }
        };
        ensure!(
            metadata.file_type().is_dir(),
            "self-publishing directory is not a real directory: {}",
            directory.display()
        );
        let path = directory.join(CONFIG_FILE);
        let config = match fs::symlink_metadata(&path) {
            Ok(_) => Some(CratesIoConfig::load(&path)?),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect self-publishing config {}", path.display()));
            }
        };
        Ok(Self { config })
    }

    /// Returns the catalog facts that one native tag is packaged against, or
    /// `None` when the repository's release tags keep `pkgre` manifests.
    ///
    /// `root` is the catalog's own directory, whose `objects/rows` hold the
    /// source rows of every identity the lock rule admits; `approvals` are the
    /// identities that catalog locks, all of which the tag's lock rule may
    /// name.
    pub(crate) fn catalog<'a>(
        &self,
        root: &'a Path,
        approvals: &'a [Approval],
        registry: &str,
        repository: &str,
        tag: &str,
    ) -> Option<NativeCatalog<'a>> {
        let config = self.config.as_ref()?;
        if !config.is_native(repository) {
            return None;
        }
        let mut identities = Vec::new();
        let mut locked = Vec::new();
        for approval in approvals.iter().filter(|approval| {
            approval.registry == registry && approval.state == PackageState::Active
        }) {
            if let Source::GitTag {
                repository: origin,
                tag: origin_tag,
                ..
            } = &approval.source
            {
                if origin.as_str() == repository && origin_tag.as_str() == tag {
                    // A crate of the tag being reproduced is bound by the
                    // archive the catalog locked for it alone: `lock` never lets
                    // a native tag name one of its own crates from crates.io, so
                    // it is not an identity the tag's lock rule may admit.
                    locked.push(NativeLocked {
                        name: &approval.name,
                        version: &approval.version,
                        archive_sha256: &approval.archive_sha256,
                        source_row_sha256: &approval.index_record_sha256,
                    });
                    continue;
                }
                if !config.is_native(origin) {
                    continue;
                }
            }
            identities.push(NativeIdentity {
                name: &approval.name,
                version: &approval.version,
                crate_sha256: &approval.archive_sha256,
                source_row_sha256: &approval.index_record_sha256,
            });
        }
        Some(NativeCatalog {
            root,
            identities,
            locked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::TemporaryDirectory;
    use semver::Version;

    /// The repository that the tests declare native.
    const REPOSITORY: &str = "https://example.invalid/example";

    /// Writes one `self-publish/crates-io.toml` beside a catalog root.
    fn write_config(catalog: &Path, contents: &str) {
        let directory = catalog.parent().unwrap().join(STATE_DIRECTORY);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(CONFIG_FILE), contents).unwrap();
    }

    #[test]
    fn a_catalog_without_a_self_publishing_directory_declares_no_native_repository() {
        let temporary = TemporaryDirectory::new("pkgre-native-declarations").unwrap();
        let catalog = temporary.path().join("catalog");
        fs::create_dir_all(&catalog).unwrap();

        let repositories = NativeRepositories::load_beside(&catalog).unwrap();

        assert!(
            repositories
                .catalog(&catalog, &[], "main", REPOSITORY, "v1.0.0")
                .is_none()
        );
    }

    #[test]
    fn a_self_publishing_directory_without_a_config_declares_no_native_repository() {
        let temporary = TemporaryDirectory::new("pkgre-native-no-config").unwrap();
        let catalog = temporary.path().join("catalog");
        fs::create_dir_all(&catalog).unwrap();
        fs::create_dir_all(catalog.parent().unwrap().join(STATE_DIRECTORY)).unwrap();

        let repositories = NativeRepositories::load_beside(&catalog).unwrap();

        assert!(
            repositories
                .catalog(&catalog, &[], "main", REPOSITORY, "v1.0.0")
                .is_none()
        );
    }

    #[test]
    fn a_malformed_self_publishing_config_fails_the_command() {
        let temporary = TemporaryDirectory::new("pkgre-native-malformed").unwrap();
        let catalog = temporary.path().join("catalog");
        fs::create_dir_all(&catalog).unwrap();
        write_config(&catalog, "schema = 1\n");

        let error = NativeRepositories::load_beside(&catalog).unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("self-publishing config"), "{message}");
        assert!(
            message.contains("must declare at least one crates.io owner"),
            "{message}"
        );
    }

    #[test]
    fn a_catalog_named_by_a_dotted_path_finds_the_declarations() {
        let temporary = TemporaryDirectory::new("pkgre-native-dotted").unwrap();
        let catalog = temporary.path().join("catalog");
        fs::create_dir_all(&catalog).unwrap();
        write_config(
            &catalog,
            &format!(
                "schema = 1\nowners = [\"example\"]\n\n[[repositories]]\ngit = {REPOSITORY:?}\ntag-prefix = \"v\"\nmanifests = \"crates-io\"\n"
            ),
        );

        let repositories = NativeRepositories::load_beside(&catalog.join(".")).unwrap();

        assert!(
            repositories
                .catalog(&catalog, &[], "main", REPOSITORY, "v1.0.0")
                .is_some(),
            "a catalog named with a trailing dot resolves to the directory whose parent holds self-publish/"
        );
    }

    #[test]
    fn a_pkgre_mode_repository_declares_no_native_catalog() {
        let temporary = TemporaryDirectory::new("pkgre-native-pkgre-mode").unwrap();
        let catalog = temporary.path().join("catalog");
        fs::create_dir_all(&catalog).unwrap();
        write_config(
            &catalog,
            &format!(
                "schema = 1\nowners = [\"example\"]\n\n[[repositories]]\ngit = {REPOSITORY:?}\ntag-prefix = \"v\"\n"
            ),
        );

        let repositories = NativeRepositories::load_beside(&catalog).unwrap();

        assert!(
            repositories
                .catalog(&catalog, &[], "main", REPOSITORY, "v1.0.0")
                .is_none(),
            "a repository without manifests = \"crates-io\" keeps pkgre manifests"
        );
    }

    /// Returns one active identity that a tag of `REPOSITORY` publishes, in
    /// `registry`, as a catalog locks it.
    fn native_tag_approval(registry: &str, name: &str, tag: &str) -> Approval {
        Approval {
            registry: registry.to_owned(),
            category: format!("{registry}/pkgre").parse().unwrap(),
            name: name.to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            archive_sha256: "01".repeat(32),
            index_record_sha256: "02".repeat(32),
            index_row_sha256: "03".repeat(32),
            admission_sha256: None,
            admitted_at: crate::update::time::UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            state: PackageState::Active,
            source: Source::GitTag {
                repository: REPOSITORY.to_owned(),
                tag: tag.to_owned(),
                tag_oid: "11".repeat(20),
                commit: "22".repeat(20),
                package: name.to_owned(),
                subdir: std::path::PathBuf::from("."),
                cargo_version: Version::parse("1.95.0").unwrap(),
            },
            declared_in: std::path::PathBuf::from("main.lock"),
        }
    }

    #[test]
    fn a_native_catalog_names_only_the_identities_of_its_own_registry() {
        let temporary = TemporaryDirectory::new("pkgre-native-registry-filter").unwrap();
        let catalog = temporary.path().join("catalog");
        fs::create_dir_all(&catalog).unwrap();
        write_config(
            &catalog,
            &format!(
                "schema = 1\nowners = [\"example\"]\n\n[[repositories]]\ngit = {REPOSITORY:?}\ntag-prefix = \"v\"\nmanifests = \"crates-io\"\n"
            ),
        );
        // Both are earlier releases of the repository, so both are identities
        // the tag's lock rule may name, and only the registry separates them.
        let approvals = [
            native_tag_approval("main", "native-main", "v0.9.0"),
            native_tag_approval("staging", "native-staging", "v0.9.0"),
        ];

        let repositories = NativeRepositories::load_beside(&catalog).unwrap();
        let native = repositories
            .catalog(&catalog, &approvals, "main", REPOSITORY, "v1.0.0")
            .unwrap();
        let names = native
            .identities
            .iter()
            .map(|identity| identity.name)
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            ["native-main"],
            "an identity of another registry is not one the tag's lock rule may name"
        );
    }
}
