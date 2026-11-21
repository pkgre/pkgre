//! The checkout's `Cargo.lock`: its packages, and the translation to crates.io.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use toml_edit::{DocumentMut, Item, TableLike, value};

use super::cargo::CRATES_IO_INDEX;
use super::expectations::Expectations;

/// One package of a lock file.
#[derive(Clone, Debug)]
pub(super) struct LockedPackage {
    /// Cargo package name.
    pub(super) name: String,
    /// Exact package version.
    pub(super) version: Version,
    /// Package source, absent for a workspace member.
    pub(super) source: Option<String>,
    /// Package checksum, absent for a workspace member.
    pub(super) checksum: Option<String>,
    /// Resolved dependencies, by package name and version.
    pub(super) dependencies: Vec<(String, Version)>,
}

/// The packages of one `Cargo.lock`, with every dependency resolved.
pub(super) struct LockIndex {
    /// Lock format version; an absent field is version 1.
    pub(super) version: i64,
    packages: Vec<LockedPackage>,
}

impl LockIndex {
    /// Reads and resolves one `Cargo.lock`.
    ///
    /// # Errors
    ///
    /// Returns an error for a lock that cannot be read or parsed, or a
    /// dependency entry that names no package of the lock or an ambiguous one.
    pub(super) fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&bytes).with_context(|| format!("parse {}", path.display()))
    }

    /// Parses and resolves one `Cargo.lock`.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed lock, or a dependency entry that names
    /// no package of the lock or an ambiguous one.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("the lock file is not UTF-8")?;
        let document: DocumentMut = text.parse().context("parse the lock file")?;
        let entries = document
            .get("package")
            .and_then(Item::as_array_of_tables)
            .context("the lock file has no [[package]] array")?;
        let mut packages = Vec::new();
        for entry in entries {
            let name = entry
                .get("name")
                .and_then(Item::as_str)
                .context("a lock package has no name")?
                .to_owned();
            let version = entry
                .get("version")
                .and_then(Item::as_str)
                .with_context(|| format!("lock package {name:?} has no version"))?;
            let version = Version::parse(version)
                .with_context(|| format!("parse the version of lock package {name:?}"))?;
            let dependencies = entry
                .get("dependencies")
                .and_then(Item::as_array)
                .map(|array| {
                    array
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .map(str::to_owned)
                                .context("a lock dependency is not a string")
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();
            packages.push((
                LockedPackage {
                    name,
                    version,
                    source: entry
                        .get("source")
                        .and_then(Item::as_str)
                        .map(str::to_owned),
                    checksum: entry
                        .get("checksum")
                        .and_then(Item::as_str)
                        .map(str::to_owned),
                    dependencies: Vec::new(),
                },
                dependencies,
            ));
        }
        let mut index = Self {
            version: document
                .get("version")
                .and_then(Item::as_integer)
                .unwrap_or(1),
            packages: packages
                .iter()
                .map(|(package, _)| package.clone())
                .collect(),
        };
        for (position, (package, dependencies)) in packages.iter().enumerate() {
            let resolved = dependencies
                .iter()
                .map(|dependency| index.resolve_dependency(&package.name, dependency))
                .collect::<Result<Vec<_>>>()?;
            index.packages[position].dependencies = resolved;
        }
        Ok(index)
    }

    /// Resolves one dependency entry of a lock package.
    ///
    /// Cargo writes `name`, `name version`, or, when two packages share a name
    /// and version, `name version (source)`.
    fn resolve_dependency(&self, package: &str, entry: &str) -> Result<(String, Version)> {
        let (name, rest) = match entry.split_once(' ') {
            Some((name, rest)) => (name, Some(rest)),
            None => (entry, None),
        };
        let (version, source) = match rest {
            Some(rest) => match rest.split_once(" (") {
                Some((version, source)) => (
                    Some(version),
                    Some(source.strip_suffix(')').unwrap_or(source)),
                ),
                None => (Some(rest), None),
            },
            None => (None, None),
        };
        let mut candidates = self
            .packages
            .iter()
            .filter(|candidate| candidate.name == name)
            .filter(|candidate| {
                version.is_none_or(|version| candidate.version.to_string() == version)
            })
            .filter(|candidate| {
                source.is_none_or(|source| candidate.source.as_deref() == Some(source))
            });
        let Some(candidate) = candidates.next() else {
            bail!(
                "the dependency {entry:?} of lock package {package:?} names no package of the lock"
            );
        };
        ensure!(
            candidates.next().is_none(),
            "the dependency {entry:?} of lock package {package:?} matches several packages of the lock"
        );
        Ok((candidate.name.clone(), candidate.version.clone()))
    }

    /// Returns every package of the lock, in file order.
    pub(super) fn packages(&self) -> &[LockedPackage] {
        &self.packages
    }

    /// Returns one exact package of the lock.
    pub(super) fn package(&self, name: &str, version: &Version) -> Option<&LockedPackage> {
        self.packages
            .iter()
            .find(|package| package.name == name && package.version == *version)
    }
}

/// Translates one `Cargo.lock` to crates.io, in the package entries and in every
/// dependency list.
///
/// Mirrored identities keep their name, version, and checksum; a first-party
/// identity of an earlier release takes its crates.io name and the checksum of
/// its `crates-io.lock` entry; a released workspace member takes its crates.io
/// name.
///
/// # Errors
///
/// Returns an error for a lock that cannot be read or parsed, holds a package
/// that the catalog does not resolve, or would hold two packages of one name and
/// version after the translation.
pub(super) fn translate_lock(checkout: &Path, expectations: &Expectations) -> Result<()> {
    let path = checkout.join("Cargo.lock");
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let index = LockIndex::parse(&bytes).with_context(|| format!("resolve {}", path.display()))?;
    let text =
        String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    let mut document: DocumentMut = text
        .parse()
        .with_context(|| format!("parse {}", path.display()))?;
    let mut identities = BTreeSet::new();
    for package in index.packages() {
        let expected = expectations
            .package(&package.name, &package.version)
            .with_context(|| {
                format!(
                    "translate lock package {name} {version}",
                    name = package.name,
                    version = package.version
                )
            })?;
        ensure!(
            identities.insert((expected.crates_io_name.clone(), package.version.clone())),
            "the translation would hold two packages named {} {}",
            expected.crates_io_name,
            package.version
        );
    }
    apply(&mut document, &index, expectations)?;
    fs::write(&path, document.to_string())
        .with_context(|| format!("write translated {}", path.display()))?;
    Ok(())
}

/// The new name, source, and checksum of one lock package.
struct Translated {
    name: String,
    source: Option<String>,
    checksum: Option<String>,
}

impl Translated {
    /// Returns the translation of one package of the lock.
    ///
    /// A workspace member of the tag stays a path package, even when the release
    /// publishes it: the rewritten manifest keeps the path, and Cargo packages
    /// the release's crates together.
    fn of(expectations: &Expectations, package: &LockedPackage) -> Result<Self> {
        let expected = expectations.package(&package.name, &package.version)?;
        if expected.member {
            return Ok(Self {
                name: expected.crates_io_name.clone(),
                source: None,
                checksum: None,
            });
        }
        match (&expected.curated_checksum, &expected.derived_checksum) {
            (Some(_), Some(checksum)) => Ok(Self {
                name: expected.crates_io_name.clone(),
                source: Some(crates_io_source()),
                checksum: Some(checksum.clone()),
            }),
            (curated, derived) => bail!(
                "package {} {} has curated checksum {curated:?} but derived checksum {derived:?}",
                package.name,
                package.version
            ),
        }
    }
}

/// The source that every external package of a translated lock names.
fn crates_io_source() -> String {
    format!("registry+{CRATES_IO_INDEX}")
}

/// Applies the translation to one lock document.
fn apply(document: &mut DocumentMut, index: &LockIndex, expectations: &Expectations) -> Result<()> {
    let packages = document
        .get_mut("package")
        .and_then(Item::as_array_of_tables_mut)
        .context("the lock file has no [[package]] array")?;
    for package in packages.iter_mut() {
        let name = package
            .get("name")
            .and_then(Item::as_str)
            .context("a lock package has no name")?
            .to_owned();
        let version = package
            .get("version")
            .and_then(Item::as_str)
            .with_context(|| format!("lock package {name:?} has no version"))?;
        let version = Version::parse(version)
            .with_context(|| format!("parse the version of lock package {name:?}"))?;
        let locked = index
            .package(&name, &version)
            .with_context(|| format!("the lock holds no package {name} {version}"))?;
        let translated = Translated::of(expectations, locked)
            .with_context(|| format!("translate lock package {name} {version}"))?;
        package.insert("name", value(translated.name.as_str()));
        match &translated.source {
            Some(source) => {
                package.insert("source", value(source.as_str()));
            }
            None => {
                package.remove("source");
            }
        }
        if let Some(checksum) = &translated.checksum {
            package.insert("checksum", value(checksum.as_str()));
        }
        rewrite_dependencies(package, locked, expectations)
            .with_context(|| format!("rewrite the dependencies of lock package {name}"))?;
    }
    Ok(())
}

/// Rewrites the `dependencies` list of one lock package.
fn rewrite_dependencies(
    package: &mut dyn TableLike,
    locked: &LockedPackage,
    expectations: &Expectations,
) -> Result<()> {
    let Some(Item::Value(dependencies)) = package.get_mut("dependencies") else {
        return Ok(());
    };
    let Some(array) = dependencies.as_array_mut() else {
        bail!("lock package dependencies are not an array");
    };
    let mut rewritten = Vec::with_capacity(array.len());
    for (position, item) in array.iter().enumerate() {
        let text = item.as_str().context("a lock dependency is not a string")?;
        let (name, version) = locked
            .dependencies
            .get(position)
            .with_context(|| format!("the dependency {text:?} has no resolved identity"))?;
        let expected = expectations.package(name, version)?;
        // A version qualifier stays, since Cargo writes it only when two packages
        // share a name; a source qualifier names the old registry, which every
        // external package leaves for crates.io.
        let qualified = text.split(' ').nth(1).is_some();
        rewritten.push(if qualified {
            format!("{} {version}", expected.crates_io_name)
        } else {
            expected.crates_io_name.clone()
        });
    }
    let mut array = toml_edit::Array::new();
    for text in rewritten {
        array.push(text);
    }
    package.insert("dependencies", value(array));
    Ok(())
}
