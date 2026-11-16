//! The workspace of one release tag: its members, their manifests, and the
//! rewrite that turns them into crates.io packages.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::{Version, VersionReq};
use toml_edit::{DocumentMut, Item, Table, TableLike, Value, value};

use super::super::catalog::{CatalogIdentity, CatalogSnapshot};
use super::super::config::CratesIoConfig;
use super::super::isolation::ChildEnvironment;
use super::super::lock::CratesIoLock;
use super::cargo::{CURATED_INDEX, run_cargo};

/// The curated registry that the tagged manifests resolve from.
pub(super) const CURATED_REGISTRY: &str = "pkgre";
/// The registry a released crate publishes to on crates.io.
pub(super) const CRATES_IO_REGISTRY: &str = "crates-io";
/// The curated registry's sources, as `cargo metadata` reports them.
const CURATED_SOURCES: [&str; 2] = [CURATED_INDEX, "registry+sparse+https://rust.pkg.re/"];
/// The alternative spellings Cargo accepts for the development dependency table.
const DEV_DEPENDENCY_SPELLINGS: [&str; 2] = ["dev-dependencies", "dev_dependencies"];
/// The alternative spellings Cargo accepts for the build dependency table.
const BUILD_DEPENDENCY_SPELLINGS: [&str; 2] = ["build-dependencies", "build_dependencies"];

/// One workspace, as the tagged commit declares it.
pub(super) struct Workspace {
    /// Root of the workspace, the directory that holds the root manifest.
    pub(super) root: PathBuf,
    /// Every workspace member, in metadata order.
    pub(super) members: Vec<Member>,
}

/// One workspace member of the tagged commit.
pub(super) struct Member {
    /// Cargo package name.
    pub(super) name: String,
    /// Exact Cargo version.
    pub(super) version: Version,
    /// Absolute path of the member's manifest.
    pub(super) manifest_path: PathBuf,
    /// Dependencies, as Cargo reports them, with inherited workspace
    /// dependencies resolved.
    pub(super) dependencies: Vec<MemberDependency>,
    /// Library target name, when the member has a library.
    pub(super) library: Option<String>,
    /// Binary target name of `src/main.rs`, when the member has one.
    pub(super) main_binary: Option<String>,
    /// Whether `publish` is exactly `[`pkgre`]`.
    pub(super) released: bool,
}

/// One dependency of one workspace member.
#[derive(Clone, Debug)]
pub(super) struct MemberDependency {
    /// Cargo package name the dependency resolves to.
    pub(super) package: String,
    /// Requirement on the dependency's version.
    pub(super) requirement: String,
    /// Cargo dependency source, absent for a path dependency.
    pub(super) source: Option<String>,
    /// Cargo registry alias the dependency declares, if any.
    pub(super) registry: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
    workspace_root: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
struct MetadataPackage {
    name: String,
    version: Version,
    manifest_path: PathBuf,
    dependencies: Vec<MetadataDependency>,
    targets: Vec<MetadataTarget>,
    publish: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
struct MetadataDependency {
    name: String,
    req: String,
    source: Option<String>,
    registry: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct MetadataTarget {
    name: String,
    kind: Vec<String>,
    src_path: PathBuf,
}

impl Workspace {
    /// Reads the workspace of one checkout with `cargo metadata --no-deps
    /// --locked`.
    ///
    /// # Errors
    ///
    /// Returns an error for a workspace that Cargo cannot read, or a metadata
    /// document the derivation does not understand.
    pub(super) fn load(
        cargo: &Path,
        environment: &ChildEnvironment,
        work: &Path,
        checkout: &Path,
    ) -> Result<Self> {
        let manifest_path = checkout.join("Cargo.toml");
        let mut arguments = [
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--manifest-path",
        ]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
        arguments.push(manifest_path.into_os_string());
        let output = run_cargo(cargo, environment, work, arguments)?;
        let metadata: Metadata =
            serde_json::from_slice(&output).context("parse pinned Cargo metadata output")?;
        let root = metadata.workspace_root.clone();
        let members = metadata
            .packages
            .into_iter()
            .map(|package| Member {
                library: library_target(&package),
                main_binary: main_binary_target(&package),
                dependencies: package
                    .dependencies
                    .into_iter()
                    .map(|dependency| MemberDependency {
                        package: dependency.name,
                        requirement: dependency.req,
                        source: dependency.source,
                        registry: dependency.registry,
                    })
                    .collect(),
                released: package.publish.as_deref() == Some(&[CURATED_REGISTRY.to_owned()]),
                name: package.name,
                version: package.version,
                manifest_path: package.manifest_path,
            })
            .collect();
        Ok(Self { root, members })
    }

    /// Returns one member by its Cargo package name.
    pub(super) fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|member| member.name == name)
    }

    /// Returns every manifest of the workspace: the root manifest and every
    /// member's, in path order.
    pub(super) fn manifest_paths(&self) -> Vec<PathBuf> {
        let mut paths = self
            .members
            .iter()
            .map(|member| member.manifest_path.clone())
            .collect::<BTreeSet<_>>();
        paths.insert(self.root.join("Cargo.toml"));
        paths.into_iter().collect()
    }
}

/// Returns the library target name of one package, when it has a library.
fn library_target(package: &MetadataPackage) -> Option<String> {
    package
        .targets
        .iter()
        .find(|target| {
            target.kind.iter().any(|kind| {
                matches!(
                    kind.as_str(),
                    "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
                )
            })
        })
        .map(|target| target.name.clone())
}

/// Returns the binary target name of `src/main.rs`, when the package has one.
fn main_binary_target(package: &MetadataPackage) -> Option<String> {
    let directory = package.manifest_path.parent()?;
    package
        .targets
        .iter()
        .find(|target| {
            target.kind.iter().any(|kind| kind == "bin")
                && target.src_path == directory.join("src").join("main.rs")
        })
        .map(|target| target.name.clone())
}

/// What one release does to the members of its workspace.
pub(super) struct ReleasePlan {
    /// Every member by name: its crates.io name when the release publishes it.
    members: BTreeMap<String, Option<String>>,
    /// Library target names to pin, by member.
    libraries: BTreeMap<String, String>,
    /// Binary target names of `src/main.rs` to pin, by member.
    binaries: BTreeMap<String, String>,
    /// The members the release publishes.
    released: BTreeSet<String>,
}

impl ReleasePlan {
    /// Plans the rewrite of one release's workspace.
    ///
    /// `published` are the identities that the catalog publishes from the tag,
    /// with their crates.io names.
    ///
    /// # Errors
    ///
    /// Returns an error when the tag's publishable members and the catalog's
    /// identities differ, or when a dependency of the workspace is one that
    /// crates.io cannot resolve.
    pub(super) fn new(
        workspace: &Workspace,
        catalog: &CatalogSnapshot,
        config: &CratesIoConfig,
        earlier: &CratesIoLock,
        published: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let released = workspace
            .members
            .iter()
            .filter(|member| member.released)
            .map(|member| member.name.clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            released == published.keys().cloned().collect::<BTreeSet<_>>(),
            "the tag publishes {released:?} but registry/main.lock holds {:?}; a release tag publishes exactly its publishable members",
            published.keys().collect::<Vec<_>>()
        );
        let mut members = BTreeMap::new();
        let mut libraries = BTreeMap::new();
        let mut binaries = BTreeMap::new();
        for member in &workspace.members {
            let Some(crates_io_name) = published.get(&member.name) else {
                members.insert(member.name.clone(), None);
                continue;
            };
            members.insert(member.name.clone(), Some(crates_io_name.clone()));
            if let Some(library) = &member.library
                && *library == derived_library_name(&member.name)
            {
                // The installed library keeps the curated name, which Cargo
                // would otherwise derive from the crates.io package name.
                libraries.insert(member.name.clone(), library.clone());
            }
            if let Some(binary) = &member.main_binary
                && *binary == member.name
            {
                binaries.insert(member.name.clone(), binary.clone());
            }
        }
        let plan = Self {
            members,
            libraries,
            binaries,
            released,
        };
        plan.validate_dependencies(workspace, catalog, config, earlier)?;
        Ok(plan)
    }

    /// Returns the crates.io name of a released member.
    pub(super) fn crates_io_name(&self, member: &str) -> Option<&str> {
        self.members.get(member).and_then(|name| name.as_deref())
    }

    /// Returns whether the release publishes one member.
    pub(super) fn is_released(&self, member: &str) -> bool {
        self.released.contains(member)
    }

    /// Refuses every dependency that crates.io cannot resolve.
    fn validate_dependencies(
        &self,
        workspace: &Workspace,
        catalog: &CatalogSnapshot,
        config: &CratesIoConfig,
        earlier: &CratesIoLock,
    ) -> Result<()> {
        for member in &workspace.members {
            for dependency in &member.dependencies {
                let context = || format!("crate {} depends on {}", member.name, dependency.package);
                self.check_dependency_source(member, dependency)
                    .with_context(context)?;
                self.classify(
                    catalog,
                    config,
                    earlier,
                    Some(member.name.as_str()),
                    &dependency.package,
                    &dependency.requirement,
                )
                .with_context(context)?;
            }
        }
        Ok(())
    }

    /// Refuses a dependency whose Cargo source is not the curated registry or a
    /// workspace member.
    fn check_dependency_source(
        &self,
        member: &Member,
        dependency: &MemberDependency,
    ) -> Result<()> {
        if self.members.contains_key(&dependency.package) {
            ensure!(
                dependency.source.is_none(),
                "{} is a workspace member but has the dependency source {:?}",
                dependency.package,
                dependency.source
            );
            return Ok(());
        }
        let source = dependency.source.as_deref().with_context(|| {
            format!(
                "{} is not a workspace member and names no dependency source",
                dependency.package
            )
        })?;
        if source == "registry+https://github.com/rust-lang/crates.io-index" {
            bail!(
                "{} takes {} from crates.io directly, which the curated registry cannot serve; every dependency comes from registry {CURATED_REGISTRY:?}",
                member.name,
                dependency.package
            );
        }
        ensure!(
            CURATED_SOURCES.contains(&source),
            "{} takes {} from the unsupported source {source:?}; every dependency comes from registry {CURATED_REGISTRY:?}",
            member.name,
            dependency.package
        );
        ensure!(
            dependency
                .registry
                .as_deref()
                .is_some_and(|index| CURATED_SOURCES.contains(&index)),
            "{} does not declare registry {CURATED_REGISTRY:?} for {}",
            member.name,
            dependency.package
        );
        Ok(())
    }

    /// Classifies one dependency, refusing what crates.io cannot resolve.
    ///
    /// `dependent` is the member that names the dependency, absent for a
    /// `[workspace.dependencies]` entry that no member inherits.
    ///
    /// # Errors
    ///
    /// Returns an error for a dependency between two released crates of one
    /// tag, a released crate's dependency on a member the tag does not publish,
    /// a fork, an abandoned version, a first-party version without an entry in
    /// `crates-io.lock`, or a version the catalog does not hold.
    pub(super) fn classify(
        &self,
        catalog: &CatalogSnapshot,
        config: &CratesIoConfig,
        earlier: &CratesIoLock,
        dependent: Option<&str>,
        package: &str,
        requirement: &str,
    ) -> Result<Classified> {
        if self.members.contains_key(package) {
            return self.classify_member(dependent, package);
        }
        let identity = resolve(catalog, package, requirement)?;
        self.classify_identity(catalog, config, earlier, dependent, identity)
    }

    /// Classifies a dependency on a workspace member.
    fn classify_member(&self, dependent: Option<&str>, package: &str) -> Result<Classified> {
        let dependent_released = dependent.is_some_and(|name| self.is_released(name));
        let dependency_released = self.is_released(package);
        if dependent_released && dependency_released {
            bail!(
                "{package} is released from the same tag, and crates.io cannot resolve a dependency between two released crates of one tag"
            );
        }
        if dependent_released && !dependency_released {
            bail!(
                "{package} is a workspace member that the tag does not publish, and crates.io cannot resolve a path to it"
            );
        }
        Ok(Classified::Member {
            crates_io_name: self.crates_io_name(package).map(str::to_owned),
        })
    }

    /// Classifies one identity of `registry/main.lock`.
    fn classify_identity(
        &self,
        catalog: &CatalogSnapshot,
        config: &CratesIoConfig,
        earlier: &CratesIoLock,
        dependent: Option<&str>,
        identity: &CatalogIdentity,
    ) -> Result<Classified> {
        let Some(release) = &identity.release else {
            return Ok(Classified::Mirrored);
        };
        if catalog.is_mirror(&identity.name) {
            bail!(
                "registry/main mirrors {}, but the dependency is a Git publication of the same name, so the crates.io name belongs to someone else",
                identity.name
            );
        }
        if config.repository(&release.git).is_none() {
            bail!(
                "the dependency is a Git publication from {:?}, which does not self-publish, so crates.io does not have it",
                release.git
            );
        }
        if dependent.is_some_and(|name| self.is_released(name)) && self.is_released(&identity.name)
        {
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
                "{} {} is abandoned on crates.io, so nothing can depend on it",
                identity.name,
                identity.version
            );
        }
        let Some(entry) = earlier.entry(&identity.name, &identity.version) else {
            bail!(
                "{} {} comes from tag {:?} of {:?}, which has no entry in crates-io.lock; crates.io does not have it yet",
                identity.name,
                identity.version,
                release.tag,
                release.git
            );
        };
        ensure!(
            entry.pkgre_crate_sha256 == identity.crate_sha256,
            "entry {} {} records pkgre archive checksum {:?} but registry/main.lock records {:?}",
            identity.name,
            identity.version,
            entry.pkgre_crate_sha256,
            identity.crate_sha256
        );
        Ok(Classified::FirstParty {
            crates_io_name: entry.crates_io_name.clone(),
        })
    }
}

/// What one dependency becomes on crates.io.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Classified {
    /// A mirrored identity: the same name and version on crates.io.
    Mirrored,
    /// A workspace member.
    Member {
        /// Its crates.io name, absent when the release does not publish it.
        crates_io_name: Option<String>,
    },
    /// A first-party identity of an earlier release.
    FirstParty {
        /// Its crates.io name.
        crates_io_name: String,
    },
}

/// Resolves the version of one dependency in the catalog.
fn resolve<'a>(
    catalog: &'a CatalogSnapshot,
    package: &str,
    requirement: &str,
) -> Result<&'a CatalogIdentity> {
    let requirement = VersionReq::parse(requirement)
        .with_context(|| format!("parse the version requirement {requirement:?} of {package}"))?;
    let matching = catalog
        .versions_of(package)
        .filter(|identity| requirement.matches(&identity.version))
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [] => bail!(
            "registry/main.lock holds no version of {package} that {requirement} matches, so crates.io cannot resolve it"
        ),
        [identity] => Ok(identity),
        identities => bail!(
            "dependency {package} matches {} versions of registry/main.lock ({}); the derivation cannot choose one",
            identities.len(),
            identities
                .iter()
                .map(|identity| identity.version.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Returns the library name that Cargo derives from a package name.
fn derived_library_name(package: &str) -> String {
    package.replace('-', "_")
}

/// Rewrites every manifest of one workspace for crates.io.
///
/// # Errors
///
/// Returns an error for a manifest that cannot be read, parsed, or written,
/// holds `[patch]` or `[replace]`, or names a dependency that the derivation
/// cannot place on crates.io.
pub(super) fn rewrite_manifests(
    workspace: &Workspace,
    plan: &ReleasePlan,
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
) -> Result<()> {
    let inherited = inherited_packages(workspace)?;
    for path in workspace.manifest_paths() {
        let bytes = fs::read(&path)
            .with_context(|| format!("read workspace manifest {}", path.display()))?;
        let text = String::from_utf8(bytes)
            .with_context(|| format!("workspace manifest {} is not UTF-8", path.display()))?;
        let mut document: DocumentMut = text
            .parse()
            .with_context(|| format!("parse workspace manifest {}", path.display()))?;
        ensure!(
            document.get("patch").is_none() && document.get("replace").is_none(),
            "workspace manifest {} declares [patch] or [replace], which a crates.io package cannot carry",
            path.display()
        );
        if let Some(member) = workspace
            .members
            .iter()
            .find(|member| member.manifest_path == path)
            && let Some(name) = plan.crates_io_name(&member.name)
        {
            rewrite_released_member(&mut document, member, name, plan)
                .with_context(|| format!("rewrite manifest {}", path.display()))?;
        }
        rewrite_dependency_tables(
            document.as_table_mut(),
            plan,
            catalog,
            config,
            earlier,
            &inherited,
        )
        .with_context(|| format!("rewrite manifest {}", path.display()))?;
        fs::write(&path, document.to_string())
            .with_context(|| format!("rewrite manifest {}", path.display()))?;
    }
    Ok(())
}

/// Rewrites one released member's package, library, and binary fields.
fn rewrite_released_member(
    document: &mut DocumentMut,
    member: &Member,
    crates_io_name: &str,
    plan: &ReleasePlan,
) -> Result<()> {
    let package = document
        .get_mut("package")
        .and_then(Item::as_table_like_mut)
        .context("released member has no [package] table")?;
    package.insert("name", value(crates_io_name));
    let mut publish = toml_edit::Array::new();
    publish.push(CRATES_IO_REGISTRY);
    package.insert("publish", value(publish));
    if let Some(library) = plan.libraries.get(&member.name) {
        let table = document
            .entry("lib")
            .or_insert(Item::Table(Table::new()))
            .as_table_like_mut()
            .context("[lib] is not a table")?;
        table.insert("name", value(library.as_str()));
    }
    if let Some(binary) = plan.binaries.get(&member.name) {
        pin_main_binary(document, binary)?;
    }
    Ok(())
}

/// Pins the installed name of the binary that Cargo derives from `src/main.rs`.
fn pin_main_binary(document: &mut DocumentMut, name: &str) -> Result<()> {
    let entry = document
        .entry("bin")
        .or_insert(Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    let binaries = entry
        .as_array_of_tables_mut()
        .context("[[bin]] is not an array of tables")?;
    for binary in binaries.iter_mut() {
        if binary.get("name").and_then(Item::as_str) == Some(name) {
            if binary.get("path").is_none() {
                binary.insert("path", value("src/main.rs"));
            }
            return Ok(());
        }
    }
    let mut binary = Table::new();
    binary.insert("name", value(name));
    binary.insert("path", value("src/main.rs"));
    binaries.push(binary);
    Ok(())
}

/// Returns the Cargo package name of every `[workspace.dependencies]` entry,
/// which a member inherits with `workspace = true`.
fn inherited_packages(workspace: &Workspace) -> Result<BTreeMap<String, String>> {
    let path = workspace.root.join("Cargo.toml");
    let bytes =
        fs::read(&path).with_context(|| format!("read workspace manifest {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("workspace manifest {} is not UTF-8", path.display()))?;
    let document: DocumentMut = text
        .parse()
        .with_context(|| format!("parse workspace manifest {}", path.display()))?;
    let mut inherited = BTreeMap::new();
    let Some(dependencies) = document
        .get("workspace")
        .and_then(Item::as_table_like)
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(Item::as_table_like)
    else {
        return Ok(inherited);
    };
    for (key, item) in dependencies.iter() {
        let package = item
            .as_table_like()
            .and_then(|entry| entry.get("package"))
            .and_then(Item::as_str)
            .unwrap_or(key);
        inherited.insert(key.to_owned(), package.to_owned());
    }
    Ok(inherited)
}

/// Rewrites every dependency table of one manifest, target-specific tables
/// included.
fn rewrite_dependency_tables(
    table: &mut dyn TableLike,
    plan: &ReleasePlan,
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    inherited: &BTreeMap<String, String>,
) -> Result<()> {
    let keys = table
        .iter()
        .map(|(key, _)| key.to_owned())
        .collect::<Vec<_>>();
    for key in keys {
        if is_dependency_table_name(&key) {
            if let Some(dependencies) = table.get_mut(&key).and_then(Item::as_table_like_mut) {
                rewrite_dependency_table(dependencies, plan, catalog, config, earlier, inherited)?;
            }
            continue;
        }
        if key == "target" {
            if let Some(targets) = table.get_mut(&key).and_then(Item::as_table_like_mut) {
                let names = targets
                    .iter()
                    .map(|(name, _)| name.to_owned())
                    .collect::<Vec<_>>();
                for name in names {
                    if let Some(target) = targets.get_mut(&name).and_then(Item::as_table_like_mut) {
                        rewrite_dependency_tables(
                            target, plan, catalog, config, earlier, inherited,
                        )?;
                    }
                }
            }
            continue;
        }
        if key == "workspace"
            && let Some(workspace) = table.get_mut(&key).and_then(Item::as_table_like_mut)
            && let Some(dependencies) = workspace
                .get_mut("dependencies")
                .and_then(Item::as_table_like_mut)
        {
            rewrite_dependency_table(dependencies, plan, catalog, config, earlier, inherited)?;
        }
    }
    Ok(())
}

/// Returns whether a table name is one of Cargo's dependency tables.
fn is_dependency_table_name(name: &str) -> bool {
    name == "dependencies"
        || DEV_DEPENDENCY_SPELLINGS.contains(&name)
        || BUILD_DEPENDENCY_SPELLINGS.contains(&name)
}

/// Rewrites one dependency table.
fn rewrite_dependency_table(
    table: &mut dyn TableLike,
    plan: &ReleasePlan,
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    earlier: &CratesIoLock,
    inherited: &BTreeMap<String, String>,
) -> Result<()> {
    let keys = table
        .iter()
        .map(|(key, _)| key.to_owned())
        .collect::<Vec<_>>();
    for key in keys {
        let Some(item) = table.get_mut(&key) else {
            continue;
        };
        // A member inherits the requirement and any rename from the workspace
        // table, which this function rewrites on its own.
        if item
            .as_table_like()
            .and_then(|entry| entry.get("workspace"))
            .and_then(Item::as_bool)
            == Some(true)
        {
            continue;
        }
        let package = item
            .as_table_like()
            .and_then(|entry| entry.get("package"))
            .and_then(Item::as_str)
            .map(str::to_owned)
            .or_else(|| inherited.get(&key).cloned())
            .unwrap_or_else(|| key.clone());
        let requirement = dependency_requirement(item).unwrap_or("*").to_owned();
        let classified = plan
            .classify(catalog, config, earlier, None, &package, &requirement)
            .with_context(|| format!("rewrite dependency {key:?}"))?;
        let rename = match classified {
            Classified::Mirrored
            | Classified::Member {
                crates_io_name: None,
            } => None,
            Classified::Member {
                crates_io_name: Some(name),
            }
            | Classified::FirstParty {
                crates_io_name: name,
            } => (name != key).then_some(name),
        };
        if let Some(entry) = item.as_table_like_mut() {
            entry.remove("registry");
            if let Some(rename) = rename {
                entry.insert("package", value(rename));
            }
            continue;
        }
        if let Some(rename) = rename {
            let mut entry = toml_edit::InlineTable::new();
            if requirement != "*" {
                entry.insert("version", requirement.as_str().into());
            }
            entry.insert("package", rename.as_str().into());
            *item = Item::Value(Value::InlineTable(entry));
        }
    }
    Ok(())
}

/// Returns the version requirement a dependency entry declares.
fn dependency_requirement(item: &Item) -> Option<&str> {
    item.as_str().or_else(|| {
        item.as_table_like()
            .and_then(|entry| entry.get("version"))
            .and_then(Item::as_str)
    })
}
