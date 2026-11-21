//! Checks for an unrewritten crates.io-native release.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::VersionReq;
use toml_edit::DocumentMut;

use super::super::catalog::CatalogSnapshot;
use super::super::config::CratesIoConfig;
use super::super::isolation::ChildEnvironment;
use super::{DerivedDependency, cargo, cargo_lock::LockIndex, workspace::Workspace};

/// Checks the manifests and the entire committed lock without changing either.
/// The resulting dependencies are the exact archives crates.io must serve.
pub(super) fn validate(
    workspace: &Workspace,
    lock: &LockIndex,
    catalog: &CatalogSnapshot,
    config: &CratesIoConfig,
    environment: &ChildEnvironment,
) -> Result<Vec<DerivedDependency>> {
    super::super::git::run(
        Some(&workspace.root),
        ["ls-files", "--error-unmatch", "Cargo.lock"],
        environment,
        false,
    )
    .context("a native release must commit its workspace Cargo.lock")?;
    for path in workspace.manifest_paths() {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("read manifest {}", path.display()))?;
        let document: DocumentMut = text.parse().context("parse native manifest")?;
        ensure!(
            document.get("patch").is_none() && document.get("replace").is_none(),
            "native manifest {} declares [patch] or [replace]",
            path.display()
        );
    }
    validate_dependencies(workspace)?;
    ensure!(
        lock.version >= 3,
        "a native Cargo.lock must have version 3 or later"
    );
    let mut dependencies = Vec::new();
    for package in lock.packages() {
        let Some(source) = &package.source else {
            ensure!(
                workspace
                    .member(&package.name)
                    .is_some_and(|member| member.version == package.version),
                "native lock package {} {} without a source is not a workspace member",
                package.name,
                package.version
            );
            continue;
        };
        ensure!(
            source == &format!("registry+{}", cargo::CRATES_IO_INDEX),
            "native lock package {} {} has unsupported source {source}",
            package.name,
            package.version
        );
        let identity = catalog.identity(&package.name, &package.version)
            .filter(|identity| !identity.removed)
            .filter(|identity| identity.release.as_ref().is_none_or(|release| config.is_native(&release.git)))
            .with_context(|| format!("native lock package {} {} is not an active mirror or native identity of the catalog", package.name, package.version))?;
        ensure!(
            package.checksum.as_deref() == Some(identity.crate_sha256.as_str()),
            "native lock package {} {} has a missing or different checksum from the catalog",
            package.name,
            package.version
        );
        dependencies.push(DerivedDependency {
            crates_io_name: package.name.clone(),
            version: package.version.clone(),
            crate_sha256: identity.crate_sha256.clone(),
        });
    }
    dependencies.sort_by(|left, right| {
        (&left.crates_io_name, &left.version).cmp(&(&right.crates_io_name, &right.version))
    });
    Ok(dependencies)
}

/// Every released dependency is a plain crates.io requirement or an exact path
/// to a released sibling. All dependency kinds participate in the cycle check.
fn validate_dependencies(workspace: &Workspace) -> Result<()> {
    let mut edges = BTreeMap::new();
    for member in workspace.members.iter().filter(|member| member.released) {
        let mut siblings = std::collections::BTreeSet::new();
        for dependency in &member.dependencies {
            ensure!(
                dependency.registry.is_none(),
                "native dependency {} of {} names a registry",
                dependency.key(),
                member.name
            );
            if let Some(source) = &dependency.source {
                ensure!(
                    source == &format!("registry+{}", cargo::CRATES_IO_INDEX),
                    "native dependency {} of {} has unsupported source {source}",
                    dependency.key(),
                    member.name
                );
                continue;
            }
            let target = workspace
                .member(&dependency.package)
                .filter(|target| target.released)
                .with_context(|| {
                    format!(
                        "native path dependency {} of {} is not a released sibling",
                        dependency.key(),
                        member.name
                    )
                })?;
            ensure!(
                target.version == member.version,
                "native siblings must have the same version"
            );
            let exact = format!("={}", target.version);
            ensure!(
                VersionReq::parse(&dependency.req)? == VersionReq::parse(&exact)?,
                "native sibling {} of {} must require exactly {exact}",
                dependency.key(),
                member.name
            );
            let path = dependency
                .path
                .as_deref()
                .context("native sibling has no path")?;
            // Cargo reports a path dependency of the tagged workspace from the
            // root it read the manifest from.
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                workspace.root.join(path)
            };
            let target_path = target
                .manifest_path
                .parent()
                .context("native sibling manifest has no parent")?;
            ensure!(
                fs::canonicalize(&path)? == fs::canonicalize(target_path)?,
                "native sibling {} of {} names another directory",
                dependency.key(),
                member.name
            );
            siblings.insert(target.name.as_str());
        }
        edges.insert(member.name.as_str(), siblings);
    }
    while let Some(name) = edges
        .iter()
        .find(|(_, dependencies)| dependencies.is_empty())
        .map(|(name, _)| *name)
    {
        edges.remove(name);
        for dependencies in edges.values_mut() {
            dependencies.remove(name);
        }
    }
    ensure!(
        edges.is_empty(),
        "native released crates form a dependency cycle: {edges:?}"
    );
    Ok(())
}

/// Copies the clean checkout, including its independent Git database, before
/// verified packaging runs package code. This is a copy, not a sandbox.
pub(super) fn copy_checkout(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination).context("replace an earlier verified checkout copy")?;
    }
    fs::create_dir(destination).context("create verified checkout copy")?;
    for entry in fs::read_dir(source).context("read checkout to copy")? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_checkout(&entry.path(), &target)?;
        } else {
            ensure!(
                kind.is_file(),
                "checkout copy refuses a symlink or special file"
            );
            fs::copy(entry.path(), target).context("copy checkout file")?;
        }
    }
    Ok(())
}
