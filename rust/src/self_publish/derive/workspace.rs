//! The workspace of one release tag: its members, their manifests, and the
//! rewrite that turns them into crates.io packages.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::{Version, VersionReq};
use toml_edit::{DocumentMut, Item, Table, TableLike, Value, value};

use super::super::isolation::ChildEnvironment;
use super::cargo::{CURATED_INDEX, run_cargo};
use super::cargo_lock::LockIndex;
use super::expectations::Expectations;

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
    /// Whether `publish` is exactly `[`pkgre`]`, which makes the member part of
    /// its repository's releases.
    pub(super) released: bool,
    /// Library target name, when the member has a library.
    pub(super) library: Option<String>,
    /// Binary target name of `src/main.rs`, when the member has one.
    pub(super) main_binary: Option<String>,
    /// The manifest fields that crates.io's own rules read.
    pub(super) facts: super::MemberFacts,
}

/// One dependency of one workspace member, as Cargo reports it.
#[derive(Clone, Debug)]
pub(super) struct MemberDependency {
    /// Cargo package name the dependency resolves to.
    pub(super) package: String,
    /// Cargo dependency source, absent for a path dependency.
    pub(super) source: Option<String>,
    /// Cargo registry alias the dependency declares, if any.
    pub(super) registry: Option<String>,
    /// The version requirement the manifest declares.
    pub(super) req: String,
    /// Directory of a path dependency, which Cargo reports instead of a source.
    pub(super) path: Option<PathBuf>,
    /// The dependency key, when the manifest renames the package.
    pub(super) rename: Option<String>,
}

impl MemberDependency {
    /// Returns the dependency key that the manifest wrote.
    pub(super) fn key(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.package)
    }
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
    description: Option<String>,
    license: Option<String>,
    license_file: Option<PathBuf>,
    homepage: Option<String>,
    documentation: Option<String>,
    repository: Option<String>,
    keywords: Option<Vec<String>>,
    categories: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
struct MetadataDependency {
    name: String,
    source: Option<String>,
    registry: Option<String>,
    req: String,
    path: Option<PathBuf>,
    rename: Option<String>,
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
                facts: super::MemberFacts {
                    description: package.description,
                    license: package.license,
                    license_file: package.license_file,
                    homepage: package.homepage,
                    documentation: package.documentation,
                    repository: package.repository,
                    keywords: package.keywords.unwrap_or_default(),
                    categories: package.categories.unwrap_or_default(),
                },
                dependencies: package
                    .dependencies
                    .into_iter()
                    .map(|dependency| MemberDependency {
                        package: dependency.name,
                        source: dependency.source,
                        registry: dependency.registry,
                        req: dependency.req,
                        path: dependency.path,
                        rename: dependency.rename,
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

    /// Returns the members that the tag publishes, which are exactly the crates
    /// that its release must hold.
    pub(super) fn publishable_members(&self) -> BTreeSet<&str> {
        self.members
            .iter()
            .filter(|member| member.released)
            .map(|member| member.name.as_str())
            .collect()
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
    /// The crates the release publishes, with their crates.io names.
    published: BTreeMap<String, String>,
    /// Library target names to pin, by member.
    libraries: BTreeMap<String, String>,
    /// Binary target names of `src/main.rs` to pin, by member.
    binaries: BTreeMap<String, String>,
}

impl ReleasePlan {
    /// Plans the rewrite of one release's workspace.
    ///
    /// # Errors
    ///
    /// Returns an error when the dependencies of the workspace include one that
    /// crates.io cannot resolve.
    pub(super) fn new(
        workspace: &Workspace,
        lock: &LockIndex,
        expectations: &Expectations,
        published: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let plan = Self {
            published: published.clone(),
            libraries: library_pins(workspace, published),
            binaries: binary_pins(workspace),
        };
        plan.validate_dependencies(workspace, lock, expectations)?;
        Ok(plan)
    }

    /// Returns the crates.io name of a released member.
    pub(super) fn crates_io_name(&self, member: &str) -> Option<&str> {
        self.published.get(member).map(String::as_str)
    }

    /// Returns whether the release publishes one member.
    pub(super) fn is_released(&self, member: &str) -> bool {
        self.published.contains_key(member)
    }

    /// Validates every dependency of the release's workspace.
    ///
    /// A released crate depends on the curated registry, or on another crate of
    /// the same tag, which it must declare as a path dependency of that crate's
    /// own directory, requiring exactly the tag's version from the curated
    /// registry: crates.io resolves the packaged form of such a dependency from
    /// the sibling's crates.io package, so the release cannot reach anything
    /// else.
    fn validate_dependencies(
        &self,
        workspace: &Workspace,
        lock: &LockIndex,
        expectations: &Expectations,
    ) -> Result<()> {
        for member in &workspace.members {
            for dependency in &member.dependencies {
                check_dependency_source(member, dependency)?;
                if member.released {
                    validate_released_dependency(member, dependency, workspace)?;
                }
            }
            let locked = lock
                .package(&member.name, &member.version)
                .with_context(|| {
                    format!(
                        "the lock holds no package {} {}",
                        member.name, member.version
                    )
                })?;
            for (package, version) in &locked.dependencies {
                if workspace.member(package).is_none() {
                    continue;
                }
                let context = || format!("crate {} depends on {package}", member.name);
                if self.is_released(&member.name) && self.is_released(package) {
                    // `validate_released_dependency` accepted this dependency.
                    continue;
                }
                if self.is_released(&member.name) {
                    return Err(anyhow::anyhow!(
                        "crate {} depends on {package}, which the tag does not publish; crates.io cannot resolve a path to it",
                        member.name
                    ))
                    .with_context(context);
                }
                expectations
                    .package(package, version)
                    .with_context(context)?;
            }
        }
        Ok(())
    }
}

/// Validates one dependency of a released crate on a crate of the same tag.
///
/// The dependency must be the path form that the reconciler accepts, so that
/// the packaged manifest carries no path and Cargo resolves the sibling from its
/// crates.io package.
///
/// # Errors
///
/// Returns an error for a released crate that depends on a member the tag does
/// not publish, on a path outside the workspace, on a sibling through the
/// curated registry instead of a path, on a sibling without the curated
/// registry, on a sibling whose requirement is not exactly the tag's version, or
/// on a path that is not the sibling's own directory.
fn validate_released_dependency(
    member: &Member,
    dependency: &MemberDependency,
    workspace: &Workspace,
) -> Result<()> {
    let key = dependency.key();
    let Some(target) = workspace.member(&dependency.package) else {
        ensure!(
            dependency.source.is_some(),
            "crate {} depends on {key} by path, which is not a member of the tag's workspace; the tag cannot publish it",
            member.name
        );
        return Ok(());
    };
    ensure!(
        target.released,
        "crate {} depends on {key}, which the tag does not publish; crates.io cannot resolve a path to it",
        member.name
    );
    ensure!(
        dependency.source.is_none(),
        "crate {} depends on {key}, a crate of the same tag, through the source {:?}; a crate of the same tag is a path dependency",
        member.name,
        dependency.source
    );
    ensure!(
        dependency
            .registry
            .as_deref()
            .is_some_and(|index| CURATED_SOURCES.contains(&index)),
        "crate {} depends on {key}, a crate of the same tag, which does not declare registry = {CURATED_REGISTRY:?}",
        member.name
    );
    let exact = format!("={}", target.version);
    let expected = VersionReq::parse(&exact).context("build the exact requirement of the tag")?;
    ensure!(
        VersionReq::parse(&dependency.req).is_ok_and(|requirement| requirement == expected),
        "crate {} depends on {key} requiring {:?}; a dependency on a crate of the same tag must require exactly {exact:?}",
        member.name,
        dependency.req
    );
    let directory = dependency.path.as_deref().with_context(|| {
        format!(
            "crate {} depends on {key}, a crate of the same tag, without a directory",
            member.name
        )
    })?;
    let target_directory = target
        .manifest_path
        .parent()
        .with_context(|| format!("the manifest of {} has no parent directory", target.name))?;
    ensure!(
        same_directory(directory, target_directory)?,
        "crate {} depends on {key} at {}, but the crate {} of the tag is at {}",
        member.name,
        directory.display(),
        target.name,
        target_directory.display()
    );
    Ok(())
}

/// Returns whether two directories are the same directory, resolving symbolic
/// links in both.
///
/// # Errors
///
/// Returns an error for a directory that cannot be resolved.
fn same_directory(left: &Path, right: &Path) -> Result<bool> {
    let left = fs::canonicalize(left)
        .with_context(|| format!("resolve path dependency directory {}", left.display()))?;
    let right = fs::canonicalize(right)
        .with_context(|| format!("resolve crate directory {}", right.display()))?;
    Ok(left == right)
}

/// Refuses a dependency whose Cargo source is not the curated registry or a
/// workspace member.
fn check_dependency_source(member: &Member, dependency: &MemberDependency) -> Result<()> {
    let Some(source) = &dependency.source else {
        return Ok(());
    };
    if source == "registry+https://github.com/rust-lang/crates.io-index" {
        bail!(
            "{} takes {} from crates.io directly, which the curated registry cannot serve; every dependency comes from registry {CURATED_REGISTRY:?}",
            member.name,
            dependency.package
        );
    }
    ensure!(
        CURATED_SOURCES.contains(&source.as_str()),
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

/// Returns the library names to pin for one release.
fn library_pins(
    workspace: &Workspace,
    published: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut libraries = BTreeMap::new();
    for member in &workspace.members {
        if !published.contains_key(&member.name) {
            continue;
        }
        if let Some(library) = &member.library
            && *library == derived_library_name(&member.name)
        {
            // The installed library keeps the curated name, which Cargo would
            // otherwise derive from the crates.io package name.
            libraries.insert(member.name.clone(), library.clone());
        }
    }
    libraries
}

/// Returns the binary names to pin for one release.
fn binary_pins(workspace: &Workspace) -> BTreeMap<String, String> {
    let mut binaries = BTreeMap::new();
    for member in &workspace.members {
        if let Some(binary) = &member.main_binary
            && *binary == member.name
        {
            binaries.insert(member.name.clone(), binary.clone());
        }
    }
    binaries
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
    expectations: &Expectations,
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
        let member = workspace
            .members
            .iter()
            .find(|member| member.manifest_path == path);
        if let Some(member) = member
            && let Some(name) = plan.crates_io_name(&member.name)
        {
            rewrite_released_member(&mut document, member, name, plan)
                .with_context(|| format!("rewrite manifest {}", path.display()))?;
        }
        rewrite_dependency_tables(&mut document, member, expectations, &inherited)
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
    document: &mut DocumentMut,
    member: Option<&Member>,
    expectations: &Expectations,
    inherited: &BTreeMap<String, String>,
) -> Result<()> {
    rewrite_tables_in(document.as_table_mut(), member, expectations, inherited)
}

/// Rewrites the dependency tables below one table.
fn rewrite_tables_in(
    table: &mut dyn TableLike,
    member: Option<&Member>,
    expectations: &Expectations,
    inherited: &BTreeMap<String, String>,
) -> Result<()> {
    let keys = table
        .iter()
        .map(|(key, _)| key.to_owned())
        .collect::<Vec<_>>();
    for key in keys {
        if is_dependency_table_name(&key) {
            if let Some(dependencies) = table.get_mut(&key).and_then(Item::as_table_like_mut) {
                rewrite_dependency_table(dependencies, member, expectations, inherited)?;
            }
            continue;
        }
        if key == "target"
            && let Some(targets) = table.get_mut(&key).and_then(Item::as_table_like_mut)
        {
            let names = targets
                .iter()
                .map(|(name, _)| name.to_owned())
                .collect::<Vec<_>>();
            for name in names {
                if let Some(target) = targets.get_mut(&name).and_then(Item::as_table_like_mut) {
                    rewrite_tables_in(target, member, expectations, inherited)?;
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
            rewrite_dependency_table(dependencies, member, expectations, inherited)?;
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
///
/// The crates.io name of every dependency comes from the catalog and the entries
/// of earlier releases, so the rewrite and the comparison read the same facts.
fn rewrite_dependency_table(
    table: &mut dyn TableLike,
    member: Option<&Member>,
    expectations: &Expectations,
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
        let resolved = expectations.contains(&package);
        let rename = if resolved {
            let expected = expectations.crates_io_name(&package)?;
            (expected != key).then(|| expected.to_owned())
        } else if let Some(member) = member {
            bail!(
                "crate {} depends on {key:?}, which the lock does not resolve",
                member.name
            );
        } else {
            None
        };
        // An unused `[workspace.dependencies]` entry keeps its name, but no
        // dependency table names a registry after the rewrite.
        if let Some(entry) = item.as_table_like_mut() {
            entry.remove("registry");
            if let Some(rename) = rename {
                entry.insert("package", value(rename));
            } else if resolved {
                // The dependency keeps its own name on crates.io, and a stale
                // `package` key would name another crate there, also in the
                // `[workspace.dependencies]` table of a virtual root.
                entry.remove("package");
            }
            continue;
        }
        if let Some(rename) = rename {
            let mut entry = toml_edit::InlineTable::new();
            if let Some(version) = dependency_requirement(item) {
                entry.insert("version", version.into());
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
