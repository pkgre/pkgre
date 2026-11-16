//! Translating `Cargo.lock` from the curated registry to crates.io.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use toml_edit::{ArrayOfTables, DocumentMut, Item, TableLike, value};

use super::super::catalog::{CatalogIdentity, CatalogSnapshot};
use super::super::config::CratesIoConfig;
use super::super::lock::CratesIoLock;
use super::cargo::{CRATES_IO_INDEX, CURATED_INDEX};
use super::workspace::{ReleasePlan, Workspace};

/// The curated registry's sources, as a lock file spells them.
const CURATED_LOCK_SOURCES: [&str; 2] = [CURATED_INDEX, "registry+sparse+https://rust.pkg.re/"];

/// The source that every external package of a translated lock names.
fn crates_io_source() -> String {
    format!("registry+{CRATES_IO_INDEX}")
}

/// What one lock package becomes.
#[derive(Clone, Debug)]
struct Translated {
    /// Package name in the translated lock.
    name: String,
    /// What happens to the `source` field.
    source: SourceChange,
    /// Replacement for the `checksum` field, absent to keep it.
    checksum: Option<String>,
}

/// What happens to the `source` field of one lock package.
#[derive(Clone, Debug)]
enum SourceChange {
    /// A workspace member keeps no source.
    Keep,
    /// The package moves to another registry.
    Replace(String),
}

/// One package of a lock, as read.
#[derive(Clone, Debug)]
struct LockedPackage {
    name: String,
    version: Version,
    source: Option<String>,
    checksum: Option<String>,
}

/// Translates one `Cargo.lock` to crates.io, in the package entries and in every
/// dependency list.
///
/// Mirrored identities keep their name, version, and checksum. A first-party
/// identity of an earlier release takes its crates.io name and the checksum of
/// its `crates-io.lock` entry. A released workspace member takes its crates.io
/// name.
///
/// # Errors
///
/// Returns the crate names that the translation renamed, which a comparison
/// with the curated archive maps the curated names through.
///
/// # Errors
///
/// Returns an error for a lock that cannot be read or parsed, holds a package
/// whose source is not the curated registry or a workspace member, holds an
/// identity the catalog does not have, or maps one package name to several
/// crates.io names.
pub(super) fn translate_lock(
    checkout: &Path,
    workspace: &Workspace,
    plan: &ReleasePlan,
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
) -> Result<BTreeMap<String, String>> {
    let path = checkout.join("Cargo.lock");
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let text =
        String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    let mut document: DocumentMut = text
        .parse()
        .with_context(|| format!("parse {}", path.display()))?;
    let packages = read_packages(&document)?;
    let mut translated = BTreeMap::new();
    let mut renames: BTreeMap<String, String> = BTreeMap::new();
    for package in &packages {
        let target = translate_package(workspace, plan, catalog, config, earlier, package)
            .with_context(|| {
                format!(
                    "translate lock package {} {}",
                    package.name, package.version
                )
            })?;
        if target.name != package.name {
            match renames.get(&package.name) {
                Some(previous) => ensure!(
                    previous == &target.name,
                    "lock packages named {:?} become both {previous:?} and {:?} on crates.io",
                    package.name,
                    target.name
                ),
                None => {
                    renames.insert(package.name.clone(), target.name.clone());
                }
            }
        }
        translated.insert((package.name.clone(), package.version.clone()), target);
    }
    // Two versions of one crate share its crates.io name; two different crates
    // may not.
    let mut names: BTreeMap<&str, (&String, &Version)> = BTreeMap::new();
    for ((name, version), target) in &translated {
        if let Some((other_name, other_version)) =
            names.insert(target.name.as_str(), (name, version))
            && other_name != name
        {
            bail!(
                "lock packages {other_name} {other_version} and {name} {version} both become {:?} on crates.io",
                target.name
            );
        }
    }
    apply(&mut document, &translated, &renames)?;
    fs::write(&path, document.to_string())
        .with_context(|| format!("write translated {}", path.display()))?;
    Ok(renames)
}

/// Returns every package of one lock.
fn read_packages(document: &DocumentMut) -> Result<Vec<LockedPackage>> {
    let mut packages = Vec::new();
    for package in lock_packages(document)? {
        let name = package
            .get("name")
            .and_then(Item::as_str)
            .context("lock package has no name")?;
        let version = package
            .get("version")
            .and_then(Item::as_str)
            .with_context(|| format!("lock package {name:?} has no version"))?;
        let version = Version::parse(version)
            .with_context(|| format!("parse the version of lock package {name:?}"))?;
        packages.push(LockedPackage {
            name: name.to_owned(),
            version,
            source: package
                .get("source")
                .and_then(Item::as_str)
                .map(str::to_owned),
            checksum: package
                .get("checksum")
                .and_then(Item::as_str)
                .map(str::to_owned),
        });
    }
    Ok(packages)
}

/// Returns the `[[package]]` array of one lock.
fn lock_packages(document: &DocumentMut) -> Result<&ArrayOfTables> {
    document
        .get("package")
        .and_then(Item::as_array_of_tables)
        .context("lock file has no [[package]] array")
}

/// Translates one lock package.
fn translate_package(
    workspace: &Workspace,
    plan: &ReleasePlan,
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    package: &LockedPackage,
) -> Result<Translated> {
    match &package.source {
        None => translate_member(workspace, plan, package),
        Some(source) if CURATED_LOCK_SOURCES.contains(&source.as_str()) => {
            let identity = catalog
                .identity(&package.name, &package.version)
                .with_context(|| {
                    format!(
                        "registry/main.lock holds no identity for the curated package {} {}",
                        package.name, package.version
                    )
                })?;
            translate_identity(plan, config, earlier, identity, package)
        }
        Some(source) if source == &crates_io_source() => bail!(
            "lock package {} {} comes from crates.io directly, which the curated registry cannot serve",
            package.name,
            package.version
        ),
        Some(source) => bail!(
            "lock package {} {} uses the unsupported source {source:?}",
            package.name,
            package.version
        ),
    }
}

/// Translates a lock package without a source, which must be a workspace member.
fn translate_member(
    workspace: &Workspace,
    plan: &ReleasePlan,
    package: &LockedPackage,
) -> Result<Translated> {
    let member = workspace.member(&package.name).with_context(|| {
        format!(
            "lock package {} {} has no source and is not a workspace member",
            package.name, package.version
        )
    })?;
    ensure!(
        member.version == package.version,
        "lock package {} {} disagrees with the workspace member's version {}",
        package.name,
        package.version,
        member.version
    );
    let name = plan
        .crates_io_name(&package.name)
        .map_or_else(|| package.name.clone(), str::to_owned);
    Ok(Translated {
        name,
        source: SourceChange::Keep,
        checksum: None,
    })
}

/// Translates a lock package of the curated registry.
fn translate_identity(
    plan: &ReleasePlan,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    identity: &CatalogIdentity,
    package: &LockedPackage,
) -> Result<Translated> {
    let source = SourceChange::Replace(crates_io_source());
    let Some(release) = &identity.release else {
        let checksum = package.checksum.as_deref().with_context(|| {
            format!(
                "lock package {} {} has no checksum, but crates.io serves it byte for byte",
                package.name, package.version
            )
        })?;
        ensure!(
            checksum == identity.crate_sha256,
            "lock package {} {} records checksum {checksum:?} but registry/main.lock records {:?}; crates.io serves the mirrored bytes",
            package.name,
            package.version,
            identity.crate_sha256
        );
        return Ok(Translated {
            name: package.name.clone(),
            source,
            checksum: None,
        });
    };
    if plan.is_released(&identity.name) {
        bail!(
            "{} is released from the same tag, and crates.io cannot resolve a dependency between two released crates of one tag",
            identity.name
        );
    }
    if config
        .abandoned_version(&identity.name, &identity.version)
        .is_some()
    {
        bail!(
            "{} {} is abandoned on crates.io",
            identity.name,
            identity.version
        );
    }
    let entry = earlier
        .entry(&identity.name, &identity.version)
        .with_context(|| {
            format!(
                "{} {} comes from tag {:?} of {:?}, which has no entry in crates-io.lock; crates.io does not have it yet",
                identity.name, identity.version, release.tag, release.git
            )
        })?;
    ensure!(
        entry.pkgre_crate_sha256 == identity.crate_sha256,
        "entry {} {} records pkgre archive checksum {:?} but registry/main.lock records {:?}",
        identity.name,
        identity.version,
        entry.pkgre_crate_sha256,
        identity.crate_sha256
    );
    Ok(Translated {
        name: entry.crates_io_name.clone(),
        source,
        checksum: Some(entry.crate_sha256.clone()),
    })
}

/// Applies the translation to one lock document.
fn apply(
    document: &mut DocumentMut,
    translated: &BTreeMap<(String, Version), Translated>,
    renames: &BTreeMap<String, String>,
) -> Result<()> {
    let packages = document
        .get_mut("package")
        .and_then(Item::as_array_of_tables_mut)
        .context("lock file has no [[package]] array")?;
    for package in packages.iter_mut() {
        let name = package
            .get("name")
            .and_then(Item::as_str)
            .context("lock package has no name")?
            .to_owned();
        let version = package
            .get("version")
            .and_then(Item::as_str)
            .context("lock package has no version")?;
        let version = Version::parse(version)
            .with_context(|| format!("parse the version of lock package {name:?}"))?;
        let target = translated
            .get(&(name.clone(), version))
            .with_context(|| format!("lock package {name} has no translation"))?;
        package.insert("name", value(target.name.as_str()));
        if let SourceChange::Replace(source) = &target.source {
            package.insert("source", value(source.as_str()));
        }
        if let Some(checksum) = &target.checksum {
            package.insert("checksum", value(checksum.as_str()));
        }
        rewrite_dependencies(package, translated, renames)
            .with_context(|| format!("rewrite the dependencies of lock package {name}"))?;
    }
    Ok(())
}

/// Rewrites the `dependencies` list of one lock package.
fn rewrite_dependencies(
    package: &mut dyn TableLike,
    translated: &BTreeMap<(String, Version), Translated>,
    renames: &BTreeMap<String, String>,
) -> Result<()> {
    let Some(Item::Value(dependencies)) = package.get_mut("dependencies") else {
        return Ok(());
    };
    let Some(array) = dependencies.as_array_mut() else {
        bail!("lock package dependencies are not an array");
    };
    let mut rewritten = Vec::with_capacity(array.len());
    for item in array.iter() {
        let text = item.as_str().context("lock dependency is not a string")?;
        let (name, version) = match text.split_once(' ') {
            Some((name, version)) => (name, Some(version)),
            None => (text, None),
        };
        let new_name = if let Some(version) = version {
            let version = Version::parse(version)
                .with_context(|| format!("parse the version of dependency {text:?}"))?;
            translated
                .get(&(name.to_owned(), version))
                .with_context(|| format!("lock dependency {text:?} has no package"))?
                .name
                .clone()
        } else {
            renames
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_owned())
        };
        rewritten.push(match version {
            Some(version) => format!("{new_name} {version}"),
            None => new_name,
        });
    }
    let mut array = toml_edit::Array::new();
    for text in rewritten {
        array.push(text);
    }
    package.insert("dependencies", value(array));
    Ok(())
}
