//! Curated-registry catalog policy validation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::category::CategoryId;
use crate::schema::{
    Approval, Catalog, MIRROR_DOWNLOAD, NameSource, PUBLISH_DOWNLOAD, PackageHome, Registry, Source,
};

const CNAME: &str = "rust.pkg.re";
pub(crate) const CARGO_VERSION: &str = "1.95.0";
pub(crate) const REGISTRIES: [(&str, &str); 2] = [
    ("pkgre", "sparse+https://rust.pkg.re/pkgre/"),
    ("universe", "sparse+https://rust.pkg.re/universe/"),
];
pub(crate) const CATEGORY_DEPENDENCIES: [(&str, &[&str]); 9] = [
    ("pkgre/tooling", &["pkgre/tooling", "universe/general"]),
    ("universe/acp", &["universe/acp", "universe/general"]),
    (
        "universe/filesystem",
        &["universe/filesystem", "universe/general"],
    ),
    ("universe/general", &["universe/general"]),
    ("universe/matrix", &["universe/matrix", "universe/general"]),
    (
        "universe/mcp",
        &["universe/mcp", "universe/sse", "universe/general"],
    ),
    ("universe/sse", &["universe/sse", "universe/general"]),
    (
        "universe/terminal",
        &["universe/terminal", "universe/general"],
    ),
    ("universe/yaml", &["universe/yaml", "universe/general"]),
];

/// Validated registry and category topology used to route and authorize dependencies.
#[derive(Debug)]
pub struct Policy {
    /// Canonical sparse URL keyed by registry alias.
    pub registry_urls: BTreeMap<String, String>,
    /// Permitted direct dependency categories keyed by source category.
    pub category_dependencies: BTreeMap<CategoryId, BTreeSet<CategoryId>>,
}

impl Policy {
    /// Returns whether a package in `from` may directly depend on a package in `to`.
    #[must_use]
    pub fn permits_dependency(&self, from: &CategoryId, to: &CategoryId) -> bool {
        self.category_dependencies
            .get(from)
            .is_some_and(|categories| categories.contains(to))
    }
}

/// Returns the compiled canonical category dependency topology.
pub(crate) fn canonical_category_dependencies() -> BTreeMap<CategoryId, BTreeSet<CategoryId>> {
    CATEGORY_DEPENDENCIES
        .iter()
        .map(|(category, dependencies)| {
            (
                category
                    .parse()
                    .expect("compiled category identity is canonical"),
                dependencies
                    .iter()
                    .map(|dependency| {
                        dependency
                            .parse()
                            .expect("compiled dependency category identity is canonical")
                    })
                    .collect(),
            )
        })
        .collect()
}

/// Validates catalog topology, naming, identity, source, and routing policy.
///
/// # Errors
///
/// Returns an error for any policy violation.
pub fn validate_catalog(catalog: &Catalog) -> Result<Policy> {
    ensure!(catalog.registries.cname == CNAME, "CNAME must be {CNAME:?}");
    ensure!(
        catalog.registries.schema == crate::schema::SCHEMA_VERSION,
        "registry topology schema must be {}",
        crate::schema::SCHEMA_VERSION
    );
    ensure!(
        catalog.homes.schema == crate::schema::SCHEMA_VERSION,
        "package-home schema must be {}",
        crate::schema::SCHEMA_VERSION
    );
    ensure!(
        catalog.registries.cargo_version.to_string() == CARGO_VERSION,
        "pkgre cargo-version must be {CARGO_VERSION}"
    );
    ensure!(
        catalog.registries.registries.len() == REGISTRIES.len(),
        "catalog must declare exactly universe and pkgre registries"
    );

    let expected_registries = REGISTRIES
        .iter()
        .map(|(name, index)| ((*name).to_owned(), (*index).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut registry_urls = BTreeMap::new();
    for registry in &catalog.registries.registries {
        validate_registry_alias(&registry.name)?;
        let expected_index = expected_registries
            .get(&registry.name)
            .with_context(|| format!("unexpected registry {:?}", registry.name))?;
        ensure!(
            &registry.index == expected_index,
            "registry {:?} index must be {expected_index:?}",
            registry.name
        );
        validate_registry_download(catalog, registry)?;
        ensure!(
            registry.cargo_version.to_string() == CARGO_VERSION,
            "registry {:?} cargo-version must be {CARGO_VERSION}",
            registry.name
        );
        ensure!(
            registry_urls
                .insert(registry.name.clone(), registry.index.clone())
                .is_none(),
            "duplicate registry {:?}",
            registry.name
        );
    }
    ensure!(
        registry_urls == expected_registries,
        "catalog must declare universe and pkgre exactly once"
    );

    let expected_categories = canonical_category_dependencies();
    let mut category_dependencies = BTreeMap::new();
    for (category, dependencies) in &catalog.categories {
        ensure!(
            registry_urls.contains_key(category.registry()),
            "category {category} names an unknown registry"
        );
        let actual = dependencies.iter().cloned().collect::<BTreeSet<_>>();
        ensure!(
            actual.len() == dependencies.len(),
            "category {category} repeats a may-depend-on target"
        );
        for dependency in &actual {
            ensure!(
                catalog.categories.contains_key(dependency),
                "category {category} may depend on unknown category {dependency}"
            );
        }
        let expected = expected_categories
            .get(category)
            .with_context(|| format!("unexpected category {category}"))?;
        ensure!(
            &actual == expected,
            "category {category} may-depend-on must be {expected:?}"
        );
        category_dependencies.insert(category.clone(), actual);
    }
    ensure!(
        category_dependencies == expected_categories,
        "catalog must declare the exact canonical category topology"
    );

    validate_homes(catalog, &registry_urls, &category_dependencies)?;
    validate_approvals(catalog, &registry_urls)?;

    Ok(Policy {
        registry_urls,
        category_dependencies,
    })
}

fn validate_registry_download(catalog: &Catalog, registry: &Registry) -> Result<()> {
    let mut has_mirror = false;
    let mut has_publish = false;
    for (name, home) in &catalog.homes.homes {
        if home.registry != registry.name {
            continue;
        }
        match catalog
            .name_sources
            .get(name)
            .with_context(|| format!("package {name:?} has no permanent source class"))?
        {
            NameSource::Mirror => has_mirror = true,
            NameSource::Publish => has_publish = true,
        }
    }
    ensure!(
        !(has_mirror && has_publish),
        "registry {:?} cannot mix mirror and publish sources because Cargo provides one dl URL per registry",
        registry.name
    );
    let expected = if has_mirror {
        MIRROR_DOWNLOAD
    } else if has_publish || registry.name == "pkgre" {
        PUBLISH_DOWNLOAD
    } else {
        MIRROR_DOWNLOAD
    };
    ensure!(
        registry.download == expected,
        "registry {:?} download must be {expected:?} for its source class",
        registry.name
    );
    Ok(())
}

fn validate_homes(
    catalog: &Catalog,
    registry_urls: &BTreeMap<String, String>,
    categories: &BTreeMap<CategoryId, BTreeSet<CategoryId>>,
) -> Result<()> {
    let mut collision_keys = BTreeMap::<String, &str>::new();
    let mut inhabited_categories = BTreeSet::new();
    for (package, home) in &catalog.homes.homes {
        validate_package_name(package)
            .with_context(|| format!("invalid package home name {package:?}"))?;
        validate_package_home(package, home, registry_urls, categories)?;
        inhabited_categories.insert(home.category.clone());
        let source = catalog
            .name_sources
            .get(package)
            .with_context(|| format!("package {package:?} has no permanent source class"))?;
        match source {
            NameSource::Mirror => ensure!(
                home.registry == "universe",
                "mirrored package {package:?} must use the universe registry"
            ),
            NameSource::Publish => ensure!(
                home.registry == "pkgre",
                "first-party package {package:?} must use the pkgre registry"
            ),
        }
        let key = package_collision_key(package);
        if let Some(previous) = collision_keys.insert(key, package) {
            ensure!(
                previous == package,
                "package names {previous:?} and {package:?} collide under Cargo normalization"
            );
        }
    }
    ensure!(
        inhabited_categories.len() == categories.len()
            && categories
                .keys()
                .all(|category| inhabited_categories.contains(category)),
        "every category must reserve at least one package name"
    );
    ensure!(
        catalog.name_sources.len() == catalog.homes.homes.len()
            && catalog
                .name_sources
                .keys()
                .all(|name| catalog.homes.homes.contains_key(name)),
        "permanent source classes differ from package homes"
    );
    Ok(())
}

fn validate_package_home(
    package: &str,
    home: &PackageHome,
    registry_urls: &BTreeMap<String, String>,
    categories: &BTreeMap<CategoryId, BTreeSet<CategoryId>>,
) -> Result<()> {
    ensure!(
        registry_urls.contains_key(&home.registry),
        "package {package:?} has unknown registry home {:?}",
        home.registry
    );
    ensure!(
        home.category.registry() == home.registry,
        "package {package:?} category {} does not belong to registry {:?}",
        home.category,
        home.registry
    );
    ensure!(
        categories.contains_key(&home.category),
        "package {package:?} has unknown category home {}",
        home.category
    );
    Ok(())
}

fn validate_approvals(catalog: &Catalog, registry_urls: &BTreeMap<String, String>) -> Result<()> {
    let mut identities = BTreeSet::new();
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
        home.registry == approval.registry && home.category == approval.category,
        "approval for {} {} is in {}/{}, but its declared home is {}/{}",
        approval.name,
        approval.version,
        approval.registry,
        approval.category,
        home.registry,
        home.category
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
            approval.registry == "universe",
            "crates.io imports must be approved in the universe registry"
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

pub(crate) fn validate_tag_version(tag: &str, version: &Version) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{HomesFile, PackageState, RegistriesFile};

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
        let categories = canonical_category_dependencies()
            .into_iter()
            .map(|(category, dependencies)| (category, dependencies.into_iter().collect()))
            .collect::<BTreeMap<_, Vec<_>>>();
        let mut homes = BTreeMap::new();
        let mut name_sources = BTreeMap::new();
        for category in categories.keys() {
            let (name, source) = if category.registry() == "pkgre" {
                ("pkgre-indexer".to_owned(), NameSource::Publish)
            } else {
                (format!("reserved-{}", category.local()), NameSource::Mirror)
            };
            homes.insert(
                name.clone(),
                PackageHome {
                    registry: category.registry().to_owned(),
                    category: category.clone(),
                },
            );
            name_sources.insert(name, source);
        }
        Catalog {
            root: Path::new("catalog").to_path_buf(),
            registries: RegistriesFile {
                schema: crate::schema::SCHEMA_VERSION,
                cname: CNAME.to_owned(),
                cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                registries: REGISTRIES
                    .iter()
                    .map(|(name, index)| Registry {
                        name: (*name).to_owned(),
                        index: (*index).to_owned(),
                        download: if *name == "pkgre" {
                            PUBLISH_DOWNLOAD.to_owned()
                        } else {
                            MIRROR_DOWNLOAD.to_owned()
                        },
                        cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                    })
                    .collect(),
            },
            categories,
            homes: HomesFile {
                schema: crate::schema::SCHEMA_VERSION,
                homes,
            },
            name_sources,
            approvals: vec![Approval {
                registry: "pkgre".to_owned(),
                category: "pkgre/tooling".parse().unwrap(),
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
    fn exact_topology_and_category_policy_are_accepted() {
        let policy = validate_catalog(&valid_catalog()).unwrap();
        assert!(policy.permits_dependency(
            &"pkgre/tooling".parse().unwrap(),
            &"universe/general".parse().unwrap()
        ));
        assert!(policy.permits_dependency(
            &"universe/mcp".parse().unwrap(),
            &"universe/sse".parse().unwrap()
        ));
        assert!(!policy.permits_dependency(
            &"universe/general".parse().unwrap(),
            &"universe/matrix".parse().unwrap()
        ));
    }

    #[test]
    fn registry_source_classes_require_matching_downloads() {
        let mut mirror_download = valid_catalog();
        let universe = mirror_download
            .registries
            .registries
            .iter_mut()
            .find(|registry| registry.name == "universe")
            .unwrap();
        universe.download = PUBLISH_DOWNLOAD.to_owned();
        let error = validate_catalog(&mirror_download).unwrap_err();
        assert!(format!("{error:#}").contains("for its source class"));

        let mut publish_download = valid_catalog();
        let pkgre = publish_download
            .registries
            .registries
            .iter_mut()
            .find(|registry| registry.name == "pkgre")
            .unwrap();
        pkgre.download = MIRROR_DOWNLOAD.to_owned();
        let error = validate_catalog(&publish_download).unwrap_err();
        assert!(format!("{error:#}").contains("for its source class"));
    }

    #[test]
    fn one_registry_cannot_mix_mirror_and_publish_name_anchors() {
        let mut catalog = valid_catalog();
        catalog.homes.homes.insert(
            "reserved-mirror".to_owned(),
            PackageHome {
                registry: "pkgre".to_owned(),
                category: "pkgre/tooling".parse().unwrap(),
            },
        );
        catalog
            .name_sources
            .insert("reserved-mirror".to_owned(), NameSource::Mirror);
        let error = validate_catalog(&catalog).unwrap_err();
        assert!(format!("{error:#}").contains(
            "cannot mix mirror and publish sources because Cargo provides one dl URL per registry"
        ));
    }

    #[test]
    fn topology_cannot_add_a_hidden_category_edge() {
        let mut catalog = valid_catalog();
        catalog
            .categories
            .get_mut(&"universe/general".parse().unwrap())
            .unwrap()
            .push("universe/matrix".parse().unwrap());
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
