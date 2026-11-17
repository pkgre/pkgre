//! The catalog facts that the self-publishing state is checked and derived
//! against.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;

use super::config::CratesIoConfig;
use crate::schema::{Catalog, Source, load_registry_inputs};

/// The only catalog registry that `self-publish/` names.
pub(crate) const CATALOG_REGISTRY: &str = "main";
/// Directory of the catalog's own state.
pub(crate) const CATALOG_DIRECTORY: &str = "registry";

/// The catalog facts the self-publishing state is checked against.
#[derive(Clone, Debug, Default)]
pub(crate) struct CatalogSnapshot {
    /// The declared index of `registry/main`, as the catalog spells it.
    pub(crate) registry_index: String,
    /// Every identity of `registry/main.lock`, active or removed.
    pub(crate) identities: Vec<CatalogIdentity>,
    /// Package names that `registry/main` mirrors.
    pub(crate) mirrors: Vec<String>,
    /// Package names that `registry/main` publishes from a Git tag.
    pub(crate) publish_names: Vec<String>,
    /// Publish declarations of `registry/main`, as name and repository.
    pub(crate) publish_declarations: Vec<(String, String)>,
}

/// One package identity of `registry/main.lock`, active or removed.
#[derive(Clone, Debug)]
pub(crate) struct CatalogIdentity {
    /// Cargo package name.
    pub(crate) name: String,
    /// Exact Cargo version.
    pub(crate) version: Version,
    /// SHA-256 of the identity's archive in `registry/main.lock`.
    pub(crate) crate_sha256: String,
    /// Whether the catalog removed the identity.
    pub(crate) removed: bool,
    /// The Git publication of the identity, absent for a mirrored identity.
    pub(crate) release: Option<GitRelease>,
    /// Cargo package names of the dependencies that the retained source row
    /// names, which a release's own crates depend on.
    pub(crate) dependencies: Vec<String>,
}

/// One Git publication of a package identity.
#[derive(Clone, Debug)]
pub(crate) struct GitRelease {
    /// Credential-free HTTPS repository of the release.
    pub(crate) git: String,
    /// Immutable release tag.
    pub(crate) tag: String,
    /// Exact tag object ID; equals the commit for a lightweight tag.
    pub(crate) tag_oid: String,
    /// Full peeled commit object ID of the release tag.
    pub(crate) commit: String,
    /// Exact Cargo version that packaged the archive.
    pub(crate) cargo_version: Version,
}

impl CatalogSnapshot {
    /// Loads the facts of a repository's catalog registry.
    ///
    /// `repository` is the directory that holds `registry/` and, when declared,
    /// `self-publish/`.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, malformed, non-canonical, unsupported, or
    /// stale catalog.
    pub(crate) fn load(repository: &Path) -> Result<Self> {
        let registry = repository.join(CATALOG_DIRECTORY);
        match std::fs::symlink_metadata(&registry) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                anyhow::bail!(
                    "repository {} has no {CATALOG_DIRECTORY} directory; the argument is the directory that holds {CATALOG_DIRECTORY}/ and self-publish/",
                    repository.display()
                );
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect catalog directory {}", registry.display()));
            }
        }
        // Publish declarations carry the repository URLs of names that have no
        // identity yet; the catalog model keeps only their names.
        let inputs = load_registry_inputs(&registry)
            .with_context(|| format!("load catalog {}", registry.display()))?;
        let declarations = self::publish_declarations(&inputs);
        let registry_index = inputs
            .iter()
            .find(|input| input.file.registry.name == CATALOG_REGISTRY)
            .map(|input| input.file.registry.index.clone())
            .with_context(|| {
                format!(
                    "catalog {} declares no registry {CATALOG_REGISTRY}",
                    registry.display()
                )
            })?;
        let catalog = Catalog::load(&registry)
            .with_context(|| format!("load catalog {}", registry.display()))?;
        Self::from_catalog(&catalog, declarations, registry_index)
    }

    /// Takes the facts of one strictly loaded catalog.
    ///
    /// # Errors
    ///
    /// Returns an error for a retained source row that cannot be read or parsed.
    pub(crate) fn from_catalog(
        catalog: &Catalog,
        publish_declarations: Vec<(String, String)>,
        registry_index: String,
    ) -> Result<Self> {
        let mut identities = Vec::new();
        for approval in &catalog.approvals {
            if approval.registry != CATALOG_REGISTRY {
                continue;
            }
            let release = match &approval.source {
                Source::CratesIo => None,
                Source::GitTag {
                    repository,
                    tag,
                    tag_oid,
                    commit,
                    cargo_version,
                    ..
                } => Some(GitRelease {
                    git: repository.clone(),
                    tag: tag.clone(),
                    tag_oid: tag_oid.clone(),
                    commit: commit.clone(),
                    cargo_version: cargo_version.clone(),
                }),
            };
            identities.push(CatalogIdentity {
                name: approval.name.clone(),
                version: approval.version.clone(),
                crate_sha256: approval.archive_sha256.clone(),
                removed: approval.is_removed(),
                release,
                dependencies: source_row_dependencies(catalog, &approval.index_record_sha256)
                    .with_context(|| {
                        format!(
                            "read the source row of {} {}",
                            approval.name, approval.version
                        )
                    })?,
            });
        }
        let mirrors = catalog
            .mirror_names
            .iter()
            .filter(|key| key.registry == CATALOG_REGISTRY)
            .map(|key| key.name.clone())
            .collect();
        let publish_names = catalog
            .publish_names
            .iter()
            .filter(|key| key.registry == CATALOG_REGISTRY)
            .map(|key| key.name.clone())
            .collect();
        Ok(Self {
            registry_index,
            identities,
            mirrors,
            publish_names,
            publish_declarations,
        })
    }

    /// Returns the identity of one exact crate version.
    pub(crate) fn identity(&self, name: &str, version: &Version) -> Option<&CatalogIdentity> {
        self.identities
            .iter()
            .find(|identity| identity.name == name && identity.version == *version)
    }

    /// Returns whether `registry/main` mirrors the package name.
    pub(crate) fn is_mirror(&self, name: &str) -> bool {
        self.mirrors.iter().any(|mirror| mirror == name)
    }
}

/// Returns the Cargo package names that one retained source row names.
///
/// The row is the one the catalog keeps under the identity's
/// `source-row-sha256`, so this reads the dependencies the release itself
/// declared, without the network.
///
/// # Errors
///
/// Returns an error for a row that cannot be read or parsed.
fn source_row_dependencies(catalog: &Catalog, source_row_sha256: &str) -> Result<Vec<String>> {
    let path = catalog
        .root
        .join("objects")
        .join("rows")
        .join(format!("{source_row_sha256}.json"));
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read retained source row {}", path.display()))?;
    let row: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse retained source row {}", path.display()))?;
    let dependencies = row
        .get("deps")
        .and_then(serde_json::Value::as_array)
        .with_context(|| format!("retained source row {} has no deps", path.display()))?;
    let mut names = Vec::new();
    for dependency in dependencies {
        let name = dependency
            .get("package")
            .and_then(serde_json::Value::as_str)
            .or_else(|| dependency.get("name").and_then(serde_json::Value::as_str))
            .with_context(|| {
                format!(
                    "a dependency of retained source row {} names no package",
                    path.display()
                )
            })?;
        names.push(name.to_owned());
    }
    Ok(names)
}

/// Returns the publish declarations of the catalog registry.
fn publish_declarations(inputs: &[crate::schema::RegistryInput]) -> Vec<(String, String)> {
    inputs
        .iter()
        .filter(|input| input.file.registry.name == CATALOG_REGISTRY)
        .flat_map(|input| input.file.category_values())
        .flat_map(|category| category.publish.iter())
        .map(|(name, declaration)| (name.clone(), declaration.git.clone()))
        .collect()
}

/// Returns the release-tag prefix and Git publication of a self-publishing identity.
pub(crate) fn release_of<'a>(
    config: &'a CratesIoConfig,
    identity: &'a CatalogIdentity,
) -> Option<(&'a str, &'a GitRelease)> {
    let release = identity.release.as_ref()?;
    let prefix = config.prefix_for(&release.git)?;
    Some((prefix, release))
}

/// Returns whether a Git identity comes from a release tag of its repository.
pub(crate) fn is_release_tag(
    prefix: &str,
    identity: &CatalogIdentity,
    release: &GitRelease,
) -> bool {
    release.tag == format!("{prefix}{}", identity.version)
}

/// Returns the identities that come from a release tag of a self-publishing
/// repository, with their releases.
pub(crate) fn self_published_identities<'a>(
    catalog: &'a CatalogSnapshot,
    config: &'a CratesIoConfig,
) -> Vec<(&'a CatalogIdentity, &'a GitRelease)> {
    catalog
        .identities
        .iter()
        .filter_map(|identity| {
            let release = identity.release.as_ref()?;
            let prefix = config.prefix_for(&release.git)?;
            is_release_tag(prefix, identity, release).then_some((identity, release))
        })
        .collect()
}

/// Returns the release that every identity of one tag agrees on.
///
/// # Errors
///
/// Returns an error when one identity has no Git publication, or when the
/// identities of the tag disagree on their commit or on the Cargo version that
/// packaged them.
pub(crate) fn release_of_group(
    git: &str,
    tag: &str,
    identities: &[CatalogIdentity],
) -> Result<GitRelease> {
    let mut releases = identities
        .iter()
        .filter_map(|identity| identity.release.clone());
    let release = releases
        .next()
        .with_context(|| format!("the release tag {tag:?} of {git:?} has no Git publication"))?;
    for other in releases {
        ensure!(
            other.git == release.git
                && other.tag == release.tag
                && other.commit == release.commit
                && other.cargo_version == release.cargo_version,
            "the identities of tag {tag:?} of {git:?} disagree on their commit or on the Cargo version that packaged them"
        );
    }
    Ok(release)
}

/// Returns the package names that a self-publishing repository publishes.
///
/// A publish declaration counts even before its first tag, so that a name can be
/// declared and validated ahead of the crate's first release.
pub(crate) fn published_names<'a>(
    catalog: &'a CatalogSnapshot,
    config: &'a CratesIoConfig,
) -> BTreeSet<&'a str> {
    let mut names = catalog
        .identities
        .iter()
        .filter(|identity| release_of(config, identity).is_some())
        .map(|identity| identity.name.as_str())
        .collect::<BTreeSet<_>>();
    names.extend(
        catalog
            .publish_declarations
            .iter()
            .filter(|(_, git)| config.repository(git).is_some())
            .map(|(name, _)| name.as_str()),
    );
    names
}
