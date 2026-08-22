//! Curated-registry catalog policy validation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::schema::{Approval, Catalog, Source};

const CNAME: &str = "rust.pkg.re";
const DOWNLOAD: &str = "https://rust.pkg.re/crates/{sha256-checksum}.crate";
pub(crate) const CARGO_VERSION: &str = "1.95.0";
pub(crate) const REGISTRIES: [(&str, &str, &[&str]); 3] = [
    ("core", "sparse+https://rust.pkg.re/core/", &["core"]),
    (
        "matrix",
        "sparse+https://rust.pkg.re/matrix/",
        &["core", "matrix"],
    ),
    (
        "pkgre",
        "sparse+https://rust.pkg.re/pkgre/",
        &["core", "matrix", "pkgre"],
    ),
];

/// Validated registry topology used to route dependency records.
#[derive(Debug)]
pub struct Policy {
    /// Canonical sparse URL keyed by registry alias.
    pub registry_urls: BTreeMap<String, String>,
    /// Permitted dependency homes keyed by registry alias.
    pub dependency_layers: BTreeMap<String, BTreeSet<String>>,
}

impl Policy {
    /// Returns whether a package in `from` may depend on a package in `to`.
    #[must_use]
    pub fn permits_dependency(&self, from: &str, to: &str) -> bool {
        self.dependency_layers
            .get(from)
            .is_some_and(|layers| layers.contains(to))
    }
}

/// Validates catalog topology, naming, identity, source, and routing policy.
///
/// # Errors
///
/// Returns an error for any policy violation.
pub fn validate_catalog(catalog: &Catalog) -> Result<Policy> {
    ensure!(catalog.registries.cname == CNAME, "CNAME must be {CNAME:?}");
    ensure!(
        catalog.registries.download == DOWNLOAD,
        "download template must be {DOWNLOAD:?}"
    );
    ensure!(
        catalog.registries.cargo_version.to_string() == CARGO_VERSION,
        "pkgre cargo-version must be {CARGO_VERSION}"
    );
    ensure!(
        catalog.registries.registries.len() == REGISTRIES.len(),
        "catalog must declare exactly core, matrix, and pkgre registries"
    );

    let expected = REGISTRIES
        .iter()
        .map(|(name, index, layers)| {
            (
                (*name).to_owned(),
                ((*index).to_owned(), string_set(layers.iter().copied())),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut registry_urls = BTreeMap::new();
    let mut dependency_layers = BTreeMap::new();
    for registry in &catalog.registries.registries {
        validate_registry_alias(&registry.name)?;
        let actual_layers = string_set(registry.may_depend_on.iter().map(String::as_str));
        ensure!(
            actual_layers.len() == registry.may_depend_on.len(),
            "registry {:?} repeats a dependency layer",
            registry.name
        );
        let (expected_index, expected_layers) = expected
            .get(&registry.name)
            .with_context(|| format!("unexpected registry {:?}", registry.name))?;
        ensure!(
            &registry.index == expected_index,
            "registry {:?} index must be {expected_index:?}",
            registry.name
        );
        ensure!(
            registry.download == DOWNLOAD,
            "registry {:?} download template must be {DOWNLOAD:?}",
            registry.name
        );
        ensure!(
            registry.cargo_version.to_string() == CARGO_VERSION,
            "registry {:?} cargo-version must be {CARGO_VERSION}",
            registry.name
        );
        ensure!(
            &actual_layers == expected_layers,
            "registry {:?} dependency layers must be {:?}",
            registry.name,
            expected_layers
        );
        ensure!(
            registry_urls
                .insert(registry.name.clone(), registry.index.clone())
                .is_none(),
            "duplicate registry {:?}",
            registry.name
        );
        dependency_layers.insert(registry.name.clone(), actual_layers);
    }
    ensure!(
        registry_urls.len() == expected.len(),
        "catalog must declare core, matrix, and pkgre exactly once"
    );

    validate_homes(catalog, &registry_urls)?;
    validate_approvals(catalog, &registry_urls)?;

    Ok(Policy {
        registry_urls,
        dependency_layers,
    })
}

fn validate_homes(catalog: &Catalog, registry_urls: &BTreeMap<String, String>) -> Result<()> {
    let mut collision_keys = BTreeMap::<String, &str>::new();
    for (package, registry) in &catalog.homes.homes {
        validate_package_name(package)
            .with_context(|| format!("invalid package home name {package:?}"))?;
        ensure!(
            registry_urls.contains_key(registry),
            "package {package:?} has unknown home {registry:?}"
        );
        let key = package_collision_key(package);
        if let Some(previous) = collision_keys.insert(key, package) {
            ensure!(
                previous == package,
                "package names {previous:?} and {package:?} collide under Cargo normalization"
            );
        }
    }
    Ok(())
}

fn validate_approvals(catalog: &Catalog, registry_urls: &BTreeMap<String, String>) -> Result<()> {
    let mut identities = BTreeSet::new();
    let mut source_rows = BTreeSet::new();
    let mut git_tags = BTreeSet::new();
    for approval in &catalog.approvals {
        validate_approval(approval, catalog, registry_urls)?;
        let identity = (
            package_collision_key(&approval.name),
            version_identity(&approval.version),
        );
        ensure!(
            identities.insert(identity),
            "duplicate approval for {} {} (build metadata does not distinguish versions)",
            approval.name,
            approval.version
        );
        ensure!(
            source_rows.insert(approval.index_record_sha256.as_str()),
            "source-row hash {} is used by more than one package identity",
            approval.index_record_sha256
        );
        if let Source::GitTag {
            repository, tag, ..
        } = &approval.source
        {
            ensure!(
                git_tags.insert((repository.as_str(), tag.as_str())),
                "Git tag {tag:?} from {repository:?} is used by more than one package identity"
            );
        }
    }
    Ok(())
}

fn validate_approval(
    approval: &Approval,
    catalog: &Catalog,
    registry_urls: &BTreeMap<String, String>,
) -> Result<()> {
    validate_package_name(&approval.name)
        .with_context(|| format!("invalid approved package name {:?}", approval.name))?;
    ensure!(
        registry_urls.contains_key(&approval.registry),
        "approval for {} {} names unknown registry {:?} in {}",
        approval.name,
        approval.version,
        approval.registry,
        approval.declared_in.display()
    );
    let home =
        catalog.homes.homes.get(&approval.name).with_context(|| {
            format!("approved package {:?} has no declared home", approval.name)
        })?;
    ensure!(
        home == &approval.registry,
        "approval for {} {} is in {:?}, but its declared home is {home:?}",
        approval.name,
        approval.version,
        approval.registry
    );
    validate_sha256(&approval.archive_sha256).with_context(|| {
        format!(
            "invalid archive hash for {} {}",
            approval.name, approval.version
        )
    })?;
    validate_sha256(&approval.index_record_sha256).with_context(|| {
        format!(
            "invalid source-row hash for {} {}",
            approval.name, approval.version
        )
    })?;
    validate_sha256(&approval.index_row_sha256).with_context(|| {
        format!(
            "invalid routed index-row hash for {} {}",
            approval.name, approval.version
        )
    })?;

    match &approval.source {
        Source::CratesIo => ensure!(
            approval.registry != "pkgre",
            "crates.io imports cannot be approved in the pkgre registry"
        ),
        Source::GitTag {
            repository,
            tag,
            tag_oid,
            commit,
            package,
            subdir,
            cargo_version,
        } => {
            ensure!(
                approval.registry == "pkgre",
                "Git-tag packages must be approved in the pkgre registry"
            );
            ensure!(
                package == &approval.name,
                "Git-tag source package {package:?} does not match approval name {:?}",
                approval.name
            );
            validate_https_repository(repository)?;
            validate_git_tag(tag)?;
            validate_git_object_id(tag_oid).context("invalid Git tag object ID")?;
            validate_git_object_id(commit).context("invalid peeled Git commit ID")?;
            validate_relative_path(subdir, true)
                .with_context(|| format!("invalid package subdirectory {}", subdir.display()))?;
            ensure!(
                cargo_version.to_string() == CARGO_VERSION,
                "Git publication {} {} used unsupported Cargo {}",
                approval.name,
                approval.version,
                cargo_version
            );
            validate_tag_version(tag, &approval.version)?;
        }
    }
    Ok(())
}

fn validate_tag_version(tag: &str, version: &Version) -> Result<()> {
    let component = tag.rsplit('/').next().expect("validated tag is nonempty");
    let plain = version.to_string();
    ensure!(
        component == plain || component == format!("v{plain}"),
        "Git tag final component {component:?} must equal {plain:?} or {:?}",
        format!("v{plain}")
    );
    Ok(())
}

/// Validates one Cargo package name under the stricter curated-registry policy.
///
/// # Errors
///
/// Returns an error unless the name is 1–64 ASCII alphanumeric, `-`, or `_` characters and starts with an alphanumeric character.
pub fn validate_package_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "package name is empty");
    ensure!(name.len() <= 64, "package name exceeds 64 bytes");
    ensure!(name.is_ascii(), "package name is not ASCII");
    ensure!(
        name.as_bytes()[0].is_ascii_alphanumeric(),
        "package name must start with an ASCII alphanumeric character"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "package name contains a character other than ASCII alphanumeric, `-`, or `_`"
    );
    Ok(())
}

/// Validates a lowercase hexadecimal SHA-256 digest.
///
/// # Errors
///
/// Returns an error unless `value` is exactly 64 lowercase hexadecimal characters.
pub fn validate_sha256(value: &str) -> Result<()> {
    ensure!(value.len() == 64, "SHA-256 must contain 64 characters");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "SHA-256 must be lowercase hexadecimal"
    );
    Ok(())
}

/// Validates a catalog-relative path without traversal or platform-specific components.
///
/// `allow_dot` permits `.` as the entire path to denote the repository root.
///
/// # Errors
///
/// Returns an error for empty, absolute, traversing, or non-normal paths.
pub fn validate_relative_path(path: &Path, allow_dot: bool) -> Result<()> {
    if allow_dot && path == Path::new(".") {
        return Ok(());
    }
    ensure!(!path.as_os_str().is_empty(), "path is empty");
    ensure!(!path.is_absolute(), "path is absolute");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "path contains `.` or `..` or a platform prefix"
    );
    ensure!(
        path.components().all(|component| match component {
            Component::Normal(value) => value.to_str().is_some_and(|part| {
                !part.is_empty()
                    && part.is_ascii()
                    && !part.contains(['\\', '\0'])
                    && part != ".git"
            }),
            _ => false,
        }),
        "path contains a non-UTF-8, non-ASCII, backslash, NUL, or .git component"
    );
    Ok(())
}

fn validate_registry_alias(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            }),
        "invalid registry alias {name:?}"
    );
    Ok(())
}

pub(crate) fn validate_https_repository(repository: &str) -> Result<()> {
    ensure!(
        repository.starts_with("https://"),
        "Git repository must use HTTPS: {repository:?}"
    );
    let rest = &repository["https://".len()..];
    ensure!(
        !rest.is_empty(),
        "Git repository HTTPS URL has no authority"
    );
    ensure!(
        repository.is_ascii()
            && !repository.bytes().any(|byte| byte.is_ascii_whitespace())
            && !rest.contains(['?', '#', '@']),
        "Git repository URL must be ASCII and contain no credentials, whitespace, query, or fragment"
    );
    ensure!(
        !repository.ends_with('/'),
        "Git repository URL must not end in `/`"
    );
    Ok(())
}

pub(crate) fn validate_git_tag(tag: &str) -> Result<()> {
    ensure!(!tag.is_empty(), "Git tag is empty");
    ensure!(tag.len() <= 255, "Git tag exceeds 255 bytes");
    ensure!(tag.is_ascii(), "Git tag is not ASCII");
    ensure!(
        tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')
        }),
        "Git tag contains a disallowed character"
    );
    ensure!(
        tag.as_bytes()[0].is_ascii_alphanumeric(),
        "Git tag must start with an ASCII alphanumeric character"
    );
    ensure!(
        !tag.contains("..")
            && !tag.contains("//")
            && !tag.contains("/.")
            && !tag.ends_with(['.', '/'])
            && tag
                .split('/')
                .all(|component| !component.as_bytes().ends_with(b".lock")),
        "Git tag is not a safe ref name"
    );
    Ok(())
}

pub(crate) fn validate_git_object_id(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40 || value.len() == 64,
        "Git object ID must contain 40 or 64 characters"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Git object ID must be lowercase hexadecimal"
    );
    Ok(())
}

pub(crate) fn validate_git_commit(commit: &str) -> Result<()> {
    validate_git_object_id(commit)
}

fn package_collision_key(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

fn version_identity(version: &Version) -> (u64, u64, u64, String) {
    (
        version.major,
        version.minor,
        version.patch,
        version.pre.to_string(),
    )
}

fn string_set<'a>(values: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{HomesFile, PackageState, RegistriesFile, Registry};

    #[test]
    fn package_names_are_strict_and_collision_key_matches_cargo() {
        validate_package_name("serde-json_2").unwrap();
        assert!(validate_package_name("-serde").is_err());
        assert!(validate_package_name("sérde").is_err());
        assert_eq!(
            package_collision_key("Serde-JSON"),
            package_collision_key("serde_json")
        );
    }

    #[test]
    fn digest_requires_canonical_lowercase_sha256() {
        validate_sha256(&"01".repeat(32)).unwrap();
        assert!(validate_sha256(&"AB".repeat(32)).is_err());
        assert!(validate_sha256("00").is_err());
    }

    #[test]
    fn relative_paths_reject_traversal_and_git_metadata() {
        validate_relative_path(Path::new("objects/rows/serde.json"), false).unwrap();
        validate_relative_path(Path::new("."), true).unwrap();
        assert!(validate_relative_path(Path::new("../secret"), false).is_err());
        assert!(validate_relative_path(Path::new("repo/.git/config"), false).is_err());
    }

    fn valid_catalog() -> Catalog {
        Catalog {
            root: Path::new("catalog").to_path_buf(),
            registries: RegistriesFile {
                schema: crate::schema::SCHEMA_VERSION,
                cname: CNAME.to_owned(),
                download: DOWNLOAD.to_owned(),
                cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                registries: REGISTRIES
                    .iter()
                    .map(|(name, index, layers)| Registry {
                        name: (*name).to_owned(),
                        index: (*index).to_owned(),
                        download: DOWNLOAD.to_owned(),
                        may_depend_on: layers.iter().map(|value| (*value).to_owned()).collect(),
                        cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                    })
                    .collect(),
            },
            homes: HomesFile {
                schema: crate::schema::SCHEMA_VERSION,
                homes: BTreeMap::from([("pkgre-indexer".to_owned(), "pkgre".to_owned())]),
            },
            approvals: vec![Approval {
                registry: "pkgre".to_owned(),
                name: "pkgre-indexer".to_owned(),
                version: Version::parse("0.1.0").unwrap(),
                archive_sha256: "01".repeat(32),
                index_record_sha256: "02".repeat(32),
                index_row_sha256: "03".repeat(32),
                state: PackageState::Active,
                source: Source::GitTag {
                    repository: "https://github.com/pkgre/pkgre".to_owned(),
                    tag: "indexer/v0.1.0".to_owned(),
                    tag_oid: "04".repeat(20),
                    commit: "05".repeat(20),
                    package: "pkgre-indexer".to_owned(),
                    subdir: Path::new("indexer").to_path_buf(),
                    cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                },
                declared_in: Path::new("pkgre.lock").to_path_buf(),
            }],
        }
    }

    #[test]
    fn exact_topology_and_first_party_source_are_accepted() {
        let policy = validate_catalog(&valid_catalog()).unwrap();
        assert!(policy.permits_dependency("pkgre", "core"));
        assert!(!policy.permits_dependency("core", "matrix"));
    }

    #[test]
    fn topology_cannot_add_a_hidden_dependency_layer() {
        let mut catalog = valid_catalog();
        catalog.registries.registries[0]
            .may_depend_on
            .push("matrix".to_owned());
        assert!(validate_catalog(&catalog).is_err());
    }

    #[test]
    fn tags_and_object_ids_are_unambiguous() {
        validate_git_tag("indexer/v0.1.0").unwrap();
        assert!(validate_git_tag("--upload-pack=x").is_err());
        validate_git_object_id(&"01".repeat(20)).unwrap();
        assert!(validate_git_object_id(&"AB".repeat(20)).is_err());
    }
}
