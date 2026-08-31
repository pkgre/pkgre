//! Transactional application of compact human admission manifests.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::category::CategoryId;
use crate::lock::{self, MirrorAdmission, ReconcileSummary};
use crate::schema::Catalog;

use super::admission::{prepare_admission_lock, write_admission_pair};
use super::declaration::append_mirror_version;
use super::workflow::{LivePlannerResolver, recompute_admission_plan_with};
use super::{UpdateDecision, UtcTimestamp, load_admission_manifest, serialize_admission_manifest};

/// Revalidates and atomically admits every exact request in one compact human manifest.
///
/// Complete network-backed facts are recomputed at apply time before a guarded catalog transaction.
/// The immutable human manifest, generated fact lock, declaration edits, registry locks, and source
/// rows are installed as one complete directory replacement.
///
/// # Errors
///
/// Returns an error for an empty/noncanonical manifest, unsupported Git-tag request, blocked/young/
/// yanked/drifted candidate, route mismatch, invalid optional evidence, existing filename collision,
/// catalog drift, reconciliation failure, or invalid staged catalog. Any failure before installation
/// leaves the live catalog unchanged.
pub fn apply_admission_manifest(root: &Path, manifest_path: &Path) -> Result<ReconcileSummary> {
    let admitted_at = UtcTimestamp::now().context("read update admission time")?;
    apply_admission_manifest_with(
        root,
        manifest_path,
        &LivePlannerResolver,
        &lock::LiveResolver,
        &admitted_at,
    )
}

pub(crate) fn apply_admission_manifest_with<
    P: super::workflow::PlannerResolver,
    L: lock::Resolver,
>(
    root: &Path,
    manifest_path: &Path,
    planner_resolver: &P,
    lock_resolver: &L,
    admitted_at: &UtcTimestamp,
) -> Result<ReconcileSummary> {
    super::manifest::validate_admission_filename(manifest_path, "toml")?;
    let manifest = load_admission_manifest(manifest_path).context("load admission manifest")?;
    ensure!(
        !manifest.entries.is_empty(),
        "admission manifest contains no requests"
    );
    let manifest_bytes = serialize_admission_manifest(&manifest)?;
    let filename = manifest_path
        .file_name()
        .context("admission manifest path has no filename")?;
    let installed_manifest = root.join("admissions").join(filename);
    let installed_lock = installed_manifest.with_extension("lock");
    match (
        fs::symlink_metadata(&installed_manifest),
        fs::symlink_metadata(&installed_lock),
    ) {
        (Ok(manifest_metadata), Ok(lock_metadata)) => {
            ensure!(
                manifest_metadata.file_type().is_file() && lock_metadata.file_type().is_file(),
                "installed admission pair is not made of regular files"
            );
            ensure!(
                fs::read(&installed_manifest).with_context(|| format!(
                    "read installed admission manifest {}",
                    installed_manifest.display()
                ))? == manifest_bytes,
                "installed admission manifest with this filename has different content"
            );
            Catalog::load(root).context("validate already-applied admission manifest")?;
            return Ok(ReconcileSummary::default());
        }
        (Err(manifest_error), Err(lock_error))
            if manifest_error.kind() == std::io::ErrorKind::NotFound
                && lock_error.kind() == std::io::ErrorKind::NotFound => {}
        (manifest_result, lock_result) => {
            let manifest_state = path_state(manifest_result.as_ref());
            let lock_state = path_state(lock_result.as_ref());
            anyhow::bail!(
                "admission filename collision has incomplete or unsafe installed pair: manifest={manifest_state}, lock={lock_state}"
            );
        }
    }

    let plan =
        recompute_admission_plan_with(root, &manifest, planner_resolver, admitted_at.clone())
            .context("recompute exact admission facts")?;
    for candidate in &plan.candidates {
        ensure!(
            candidate.decision != UpdateDecision::Blocked,
            "blocked candidate {} {} cannot be admitted",
            candidate.name,
            candidate.candidate.version
        );
    }
    let (admission_lock, batch_sha256) = prepare_admission_lock(&manifest, &plan, admitted_at)?;

    lock::transact_catalog(root, &plan.catalog_sha256, |staged| {
        let mut admissions = Vec::with_capacity(plan.candidates.len());
        for candidate in &plan.candidates {
            append_mirror_version(staged, candidate).with_context(|| {
                format!(
                    "declare admitted candidate {} {}",
                    candidate.name, candidate.candidate.version
                )
            })?;
            admissions.push(MirrorAdmission {
                registry: candidate.registry.clone(),
                category: candidate
                    .category
                    .parse::<CategoryId>()
                    .context("parse admitted candidate category")?,
                name: candidate.name.clone(),
                version: candidate.candidate.version.clone(),
                crate_sha256: candidate.candidate.crate_sha256.clone(),
                source_row_sha256: candidate.candidate.source_row_sha256.clone(),
                binding_sha256: batch_sha256.clone(),
                admitted_at: candidate.candidate.published_at.clone(),
            });
        }
        write_admission_pair(
            staged,
            Path::new(filename),
            &manifest_bytes,
            &admission_lock,
        )
        .context("retain immutable admission manifest and generated facts")?;
        lock::reconcile_admitted_with(staged, &admissions, lock_resolver)
            .context("reconcile exact admitted mirror identities")
    })
}

fn path_state(result: Result<&fs::Metadata, &std::io::Error>) -> &'static str {
    match result {
        Ok(metadata) if metadata.file_type().is_file() => "regular-file",
        Ok(metadata) if metadata.file_type().is_dir() => "directory",
        Ok(_) => "special",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing",
        Err(_) => "unreadable",
    }
}
