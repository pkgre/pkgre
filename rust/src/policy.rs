//! Curated-registry catalog policy validation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::category::CategoryId;
use crate::download::router_download_template;
use crate::schema::{
    Approval, Catalog, MIRROR_DOWNLOAD, PUBLISH_DOWNLOAD, PackageHome, PackageKey, Registry, Source,
};

const CNAME: &str = "rust.pkg.re";
pub(crate) const CARGO_VERSION: &str = "1.95.0";
pub(crate) const SCHEMA3_REGISTRIES: [(&str, &str); 2] = [
    ("pkgre", "sparse+https://rust.pkg.re/pkgre/"),
    ("universe", "sparse+https://rust.pkg.re/universe/"),
];
pub(crate) const SCHEMA3_CATEGORY_DEPENDENCIES: [(&str, &[&str]); 9] = [
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

/// Returns the historical canonical schema-3 category dependency topology.
pub(crate) fn canonical_category_dependencies() -> BTreeMap<CategoryId, BTreeSet<CategoryId>> {
    SCHEMA3_CATEGORY_DEPENDENCIES
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
        "main cargo-version must be {CARGO_VERSION}"
    );
    ensure!(
        !catalog.registries.registries.is_empty(),
        "catalog must declare the main registry"
    );

    let mut registry_urls = BTreeMap::new();
    for registry in &catalog.registries.registries {
        validate_registry_alias(&registry.name)?;
        let expected_index = canonical_registry_index(&registry.name);
        ensure!(
            registry.index == expected_index,
            "registry {:?} index must be {expected_index:?}",
            registry.name
        );
        validate_registry_download(catalog, registry)?;
        ensure!(
            registry.cargo_version == catalog.registries.cargo_version,
            "registry {:?} cargo-version must match main cargo-version {}",
            registry.name,
            catalog.registries.cargo_version
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
        registry_urls.contains_key("main"),
        "catalog must declare exactly one main registry"
    );

    ensure!(!catalog.categories.is_empty(), "catalog has no categories");
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
        category_dependencies.insert(category.clone(), actual);
    }

    validate_homes(catalog, &registry_urls, &category_dependencies)?;
    validate_approvals(catalog, &registry_urls)?;

    Ok(Policy {
        registry_urls,
        category_dependencies,
    })
}

/// Returns the one canonical sparse index URL for a catalog registry identity.
#[must_use]
pub fn canonical_registry_index(name: &str) -> String {
    if name == "main" {
        "sparse+https://rust.pkg.re/".to_owned()
    } else {
        format!("sparse+https://rust.pkg.re/{name}/")
    }
}

fn validate_registry_download(catalog: &Catalog, registry: &Registry) -> Result<()> {
    let has_mirror = catalog
        .mirror_names
        .iter()
        .any(|key| key.registry == registry.name);
    let has_publish = catalog
        .publish_names
        .iter()
        .any(|key| key.registry == registry.name);
    let router = router_download_template(&registry.name);
    if registry.download == router {
        return Ok(());
    }
    ensure!(
        !(has_mirror && has_publish),
        "registry {:?} mixes mirror and publish sources and therefore requires download {router:?}",
        registry.name
    );
    let expected = if has_publish {
        PUBLISH_DOWNLOAD
    } else {
        MIRROR_DOWNLOAD
    };
    ensure!(
        registry.download == expected,
        "registry {:?} download must be {expected:?} for its source class, or {router:?} for the immutable router",
        registry.name
    );
    Ok(())
}

fn validate_homes(
    catalog: &Catalog,
    registry_urls: &BTreeMap<String, String>,
    categories: &BTreeMap<CategoryId, BTreeSet<CategoryId>>,
) -> Result<()> {
    let mut collision_keys = BTreeMap::<(String, String), &str>::new();
    let mut inhabited_categories = BTreeSet::new();
    for (package, home) in &catalog.homes.homes {
        validate_package_name(&package.name)
            .with_context(|| format!("invalid package home name {:?}", package.name))?;
        validate_package_home(package, home, registry_urls, categories)?;
        inhabited_categories.insert(home.category.clone());
        let key = (
            package.registry.clone(),
            package_collision_key(&package.name),
        );
        if let Some(previous) = collision_keys.insert(key, &package.name) {
            ensure!(
                previous == package.name.as_str(),
                "package names {previous:?} and {:?} collide under Cargo normalization in registry {:?}",
                package.name,
                package.registry
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
    for name in catalog.mirror_names.union(&catalog.publish_names) {
        ensure!(
            catalog.homes.homes.contains_key(name),
            "source declaration for package {name:?} has no package home"
        );
    }
    for package in catalog.homes.homes.keys() {
        ensure!(
            catalog.mirror_names.contains(package) || catalog.publish_names.contains(package),
            "package {package:?} has no retained mirror or publish source declaration"
        );
    }
    Ok(())
}

fn validate_package_home(
    package: &PackageKey,
    home: &PackageHome,
    registry_urls: &BTreeMap<String, String>,
    categories: &BTreeMap<CategoryId, BTreeSet<CategoryId>>,
) -> Result<()> {
    ensure!(
        package.registry == home.registry,
        "package {:?} is keyed below registry {:?}, but its home names registry {:?}",
        package.name,
        package.registry,
        home.registry
    );
    ensure!(
        registry_urls.contains_key(&home.registry),
        "package {:?} has unknown registry home {:?}",
        package.name,
        home.registry
    );
    ensure!(
        home.category.registry() == home.registry,
        "package {:?} category {} does not belong to registry {:?}",
        package.name,
        home.category,
        home.registry
    );
    ensure!(
        categories.contains_key(&home.category),
        "package {:?} has unknown category home {}",
        package.name,
        home.category
    );
    Ok(())
}

fn validate_approvals(catalog: &Catalog, registry_urls: &BTreeMap<String, String>) -> Result<()> {
    let mut identities = BTreeSet::new();
    for approval in &catalog.approvals {
        validate_approval(approval, catalog, registry_urls)?;
        let identity = (
            approval.registry.clone(),
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
    let key = PackageKey::new(&approval.registry, &approval.name);
    let home = catalog.homes.homes.get(&key).with_context(|| {
        format!(
            "approved package {}/{} has no declared home",
            approval.registry, approval.name
        )
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

    let source_declared = match &approval.source {
        Source::CratesIo => catalog.mirror_names.contains(&key),
        Source::GitTag { .. } => catalog.publish_names.contains(&key),
    };
    ensure!(
        source_declared,
        "approval source for {} {} has no retained matching source declaration",
        approval.name,
        approval.version
    );
    match &approval.source {
        Source::CratesIo => {}
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
                cargo_version == &catalog.registries.cargo_version,
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

/// Validates a lowercase Cargo registry alias.
///
/// # Errors
///
/// Returns an error unless the alias is nonempty and contains only lowercase ASCII alphanumeric, `-`, or `_` characters.
pub fn validate_registry_alias(name: &str) -> Result<()> {
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
        let categories = BTreeMap::from([
            (
                "main/general".parse().unwrap(),
                vec!["main/general".parse().unwrap()],
            ),
            (
                "main/pkgre".parse().unwrap(),
                vec![
                    "main/general".parse().unwrap(),
                    "main/pkgre".parse().unwrap(),
                ],
            ),
        ]);
        let homes = BTreeMap::from([
            (
                PackageKey::new("main", "mirror-crate"),
                PackageHome {
                    registry: "main".to_owned(),
                    category: "main/general".parse().unwrap(),
                },
            ),
            (
                PackageKey::new("main", "pkgre-indexer"),
                PackageHome {
                    registry: "main".to_owned(),
                    category: "main/pkgre".parse().unwrap(),
                },
            ),
        ]);
        Catalog {
            root: Path::new("catalog").to_path_buf(),
            registries: RegistriesFile {
                schema: crate::schema::SCHEMA_VERSION,
                cname: CNAME.to_owned(),
                cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                registries: vec![Registry {
                    name: "main".to_owned(),
                    index: canonical_registry_index("main"),
                    download: router_download_template("main"),
                    cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                }],
            },
            categories,
            homes: HomesFile {
                schema: crate::schema::SCHEMA_VERSION,
                homes,
            },
            mirror_names: BTreeSet::from([PackageKey::new("main", "mirror-crate")]),
            publish_names: BTreeSet::from([PackageKey::new("main", "pkgre-indexer")]),
            approvals: vec![Approval {
                registry: "main".to_owned(),
                category: "main/pkgre".parse().unwrap(),
                name: "pkgre-indexer".to_owned(),
                version: Version::parse("0.1.0").unwrap(),
                archive_sha256: "01".repeat(32),
                index_record_sha256: "02".repeat(32),
                index_row_sha256: "03".repeat(32),
                admission_sha256: None,
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
                declared_in: Path::new("main.lock").to_path_buf(),
            }],
        }
    }

    #[test]
    fn declared_topology_and_category_policy_are_enforced() {
        let policy = validate_catalog(&valid_catalog()).unwrap();
        assert!(policy.permits_dependency(
            &"main/pkgre".parse().unwrap(),
            &"main/general".parse().unwrap()
        ));
        assert!(!policy.permits_dependency(
            &"main/general".parse().unwrap(),
            &"main/pkgre".parse().unwrap()
        ));

        let mut unknown = valid_catalog();
        unknown
            .categories
            .get_mut(&"main/general".parse().unwrap())
            .unwrap()
            .push("main/missing".parse().unwrap());
        assert!(validate_catalog(&unknown).is_err());
    }

    #[test]
    fn source_specific_registries_require_matching_downloads() {
        let mut mirror_only = valid_catalog();
        mirror_only.publish_names.clear();
        mirror_only
            .homes
            .homes
            .remove(&PackageKey::new("main", "pkgre-indexer"));
        mirror_only.approvals.clear();
        mirror_only
            .categories
            .remove(&"main/pkgre".parse().unwrap());
        mirror_only.registries.registries[0].download = PUBLISH_DOWNLOAD.to_owned();
        let error = validate_catalog(&mirror_only).unwrap_err();
        assert!(format!("{error:#}").contains("for its source class"));

        let mut publish_only = valid_catalog();
        publish_only.mirror_names.clear();
        publish_only
            .homes
            .homes
            .remove(&PackageKey::new("main", "mirror-crate"));
        publish_only
            .categories
            .remove(&"main/general".parse().unwrap());
        publish_only
            .categories
            .get_mut(&"main/pkgre".parse().unwrap())
            .unwrap()
            .retain(|category| category == &"main/pkgre".parse().unwrap());
        publish_only.registries.registries[0].download = MIRROR_DOWNLOAD.to_owned();
        let error = validate_catalog(&publish_only).unwrap_err();
        assert!(format!("{error:#}").contains("for its source class"));
    }

    #[test]
    fn mixed_source_registry_requires_its_exact_router_template() {
        let mut catalog = valid_catalog();
        catalog.registries.registries[0].download = MIRROR_DOWNLOAD.to_owned();
        let error = validate_catalog(&catalog).unwrap_err();
        assert!(format!("{error:#}").contains("requires download"));

        catalog.registries.registries[0].download = router_download_template("other");
        let error = validate_catalog(&catalog).unwrap_err();
        assert!(format!("{error:#}").contains("requires download"));

        catalog.registries.registries[0].download = router_download_template("main");
        validate_catalog(&catalog).unwrap();
    }

    #[test]
    fn future_subregistry_has_its_canonical_path_and_independent_name_namespace() {
        let mut catalog = valid_catalog();
        catalog.registries.registries.push(Registry {
            name: "staging".to_owned(),
            index: canonical_registry_index("staging"),
            download: MIRROR_DOWNLOAD.to_owned(),
            cargo_version: Version::parse(CARGO_VERSION).unwrap(),
        });
        catalog.categories.insert(
            "staging/general".parse().unwrap(),
            vec!["staging/general".parse().unwrap()],
        );
        catalog.homes.homes.insert(
            PackageKey::new("staging", "mirror_crate"),
            PackageHome {
                registry: "staging".to_owned(),
                category: "staging/general".parse().unwrap(),
            },
        );
        catalog
            .mirror_names
            .insert(PackageKey::new("staging", "mirror_crate"));
        validate_catalog(&catalog).unwrap();

        catalog.registries.registries[1].index = "sparse+https://rust.pkg.re/other/".to_owned();
        assert!(validate_catalog(&catalog).is_err());
        catalog.registries.registries[1].index = canonical_registry_index("staging");

        catalog.homes.homes.insert(
            PackageKey::new("staging", "mirror-crate"),
            PackageHome {
                registry: "staging".to_owned(),
                category: "staging/general".parse().unwrap(),
            },
        );
        catalog
            .mirror_names
            .insert(PackageKey::new("staging", "mirror-crate"));
        let error = validate_catalog(&catalog).unwrap_err();
        assert!(format!("{error:#}").contains("collide under Cargo normalization"));
    }

    #[test]
    fn source_declarations_and_package_homes_have_exact_inventory() {
        let mut missing = valid_catalog();
        missing
            .publish_names
            .remove(&PackageKey::new("main", "pkgre-indexer"));
        let error = validate_catalog(&missing).unwrap_err();
        assert!(format!("{error:#}").contains("has no retained mirror or publish"));

        let mut orphan = valid_catalog();
        orphan
            .mirror_names
            .insert(PackageKey::new("main", "orphan"));
        let error = validate_catalog(&orphan).unwrap_err();
        assert!(format!("{error:#}").contains("has no package home"));

        let mut mixed_name = valid_catalog();
        mixed_name
            .mirror_names
            .insert(PackageKey::new("main", "pkgre-indexer"));
        validate_catalog(&mixed_name).unwrap();
    }

    #[test]
    fn tags_and_object_ids_are_unambiguous() {
        validate_git_tag("indexer/v0.1.0").unwrap();
        assert!(validate_git_tag("--upload-pack=x").is_err());
        validate_git_object_id(&"01".repeat(20)).unwrap();
        assert!(validate_git_object_id(&"AB".repeat(20)).is_err());
    }
}
