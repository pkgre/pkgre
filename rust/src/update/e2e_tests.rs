//! Deterministic end-to-end coverage for compact admission manifests and generated facts.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use flate2::{Compression, write::GzEncoder};
use semver::Version;
use serde_json::json;

use super::inspect::InspectionResolver;
use super::workflow::PlannerResolver;
use super::{
    AdmissionEvidence, AdmissionManifest, AdmissionRequest, DecisionReason, PackageActivity,
    SourceCorrespondence, SourceEvidence, UpdateDecision, UtcTimestamp,
    apply::apply_admission_manifest_with,
    inspect::inspect_update_candidate_with,
    load_admission_manifest, serialize_admission_manifest, validate_admission_inventory,
    workflow::{ExactRequest, plan_exact_update_with, plan_exact_updates_with, plan_updates_with},
};
use crate::artifact::{ArtifactMap, sha256_bytes};
use crate::import::{CratesIoHistory, SparseIndexRow};
use crate::index::IndexRecord;
use crate::lock::{self, ReconcileSummary, ResolvedPackage, Resolver};
use crate::policy::validate_catalog;
use crate::schema::{Catalog, LockedSource, PackageState, Source};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
#[allow(clippy::too_many_lines)]
fn compact_manifest_lifecycle_is_inert_transactional_bound_and_convergent() {
    let temporary = TemporaryDirectory::new("pkgre-admission-v2-success");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["demo"]);
    assert_eq!(
        lock::reconcile(&catalog_root).unwrap(),
        ReconcileSummary {
            changed: true,
            names_added: 9,
            ..ReconcileSummary::default()
        }
    );

    let marker = temporary.path().join("archive-code-must-not-run");
    let fixture = malicious_build_fixture(&marker);
    let version = Version::parse("1.0.0").unwrap();
    let manifest_path = temporary.path().join("2026-08-24-demo.toml");
    let plan = plan_exact_update_with(
        &catalog_root,
        "demo",
        &version,
        &manifest_path,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    let mut manifest = load_admission_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    let template = fs::read_to_string(&manifest_path).unwrap();
    assert!(template.contains("[[admit]]"));
    assert!(template.contains("category = \"main/general\""));
    assert!(template.contains("version = \"1.0.0\""));
    assert!(!template.contains("sha256"));

    let review = temporary.path().join("review");
    let before_inspection = super::catalog_fingerprint(&catalog_root).unwrap();
    inspect_update_candidate_with(
        &catalog_root,
        &manifest_path,
        "demo",
        &version,
        &review,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert_eq!(
        super::catalog_fingerprint(&catalog_root).unwrap(),
        before_inspection
    );
    assert!(!marker.exists());
    assert_eq!(
        fs::read(review.join("candidate.crate")).unwrap(),
        fixture.package("demo", &version).unwrap().archive
    );
    assert!(!review.join("base.crate").exists());

    manifest.entries[0].evidence = vec![AdmissionEvidence::ManualFullArchive {
        note: "Reviewed every regular archive member and relevant metadata.".to_owned(),
    }];
    fs::write(
        &manifest_path,
        serialize_admission_manifest(&manifest).unwrap(),
    )
    .unwrap();

    let summary = apply_admission_manifest_with(
        &catalog_root,
        &manifest_path,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert_eq!(
        summary,
        ReconcileSummary {
            changed: true,
            packages_added: 1,
            ..ReconcileSummary::default()
        }
    );
    assert_eq!(fixture.lock_calls.get(), 1);
    assert!(
        fixture.source_calls.get() >= 3,
        "plan, inspect, and apply must each recompute evidence"
    );

    assert_admitted_catalog(
        &catalog_root,
        &fixture,
        &[("demo", "1.0.0", "main/general")],
        "2026-08-24-demo",
    );
    let applied_snapshot = snapshot_tree(&catalog_root).unwrap();
    assert_eq!(
        apply_admission_manifest_with(
            &catalog_root,
            &manifest_path,
            &fixture,
            &fixture,
            &UtcTimestamp::now().unwrap(),
        )
        .unwrap(),
        ReconcileSummary::default()
    );
    assert_eq!(snapshot_tree(&catalog_root).unwrap(), applied_snapshot);

    manifest.entries[0].evidence = vec![AdmissionEvidence::ManualFullArchive {
        note: "A different review note must not reuse an installed batch name.".to_owned(),
    }];
    fs::write(
        &manifest_path,
        serialize_admission_manifest(&manifest).unwrap(),
    )
    .unwrap();
    let collision = apply_admission_manifest_with(
        &catalog_root,
        &manifest_path,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert!(format!("{collision:#}").contains("filename has different content"));
    assert_eq!(snapshot_tree(&catalog_root).unwrap(), applied_snapshot);

    assert_render_and_lock_convergence(&catalog_root, &temporary.path().join("site"));
    assert_admission_failures_reach_ordinary_catalog_verification(&catalog_root, "2026-08-24-demo");
    assert!(!marker.exists());
}

#[test]
fn mirror_admission_retains_archives_only_for_retained_delivery() {
    for delivery in [Some("retained"), Some("redirect"), None] {
        let temporary = TemporaryDirectory::new("pkgre-admission-delivery");
        let catalog_root = temporary.path().join("catalog");
        write_catalog(&catalog_root, &["demo"]);
        let registry_path = catalog_root.join("main.toml");
        let mut registry = fs::read_to_string(&registry_path).unwrap().replace(
            &crate::download::router_download_template("main"),
            &crate::download::native_download_template("main"),
        );
        if let Some(delivery) = delivery {
            registry = registry.replace(
                "[registry]\n",
                &format!("[registry]\ndelivery = {delivery:?}\n"),
            );
        }
        fs::write(registry_path, registry).unwrap();
        lock::reconcile(&catalog_root).unwrap();
        let fixture = FixtureResolver::new(vec![FixturePackage::new(
            "demo",
            "1.0.0",
            "src/lib.rs",
            b"pub fn demo() {}\n",
        )]);
        let manifest_path = prepare_manifest(
            temporary.path(),
            &catalog_root,
            &fixture,
            &["demo"],
            "2026-08-24-delivery",
        );

        let summary = apply_admission_manifest_with(
            &catalog_root,
            &manifest_path,
            &fixture,
            &fixture,
            &UtcTimestamp::now().unwrap(),
        )
        .unwrap();
        assert_eq!(
            summary,
            ReconcileSummary {
                changed: true,
                packages_added: 1,
                ..ReconcileSummary::default()
            }
        );
        assert_eq!(fixture.lock_calls.get(), 1);
        let catalog = Catalog::load(&catalog_root).unwrap();
        validate_catalog(&catalog).unwrap();
        ArtifactMap::load(&catalog).unwrap();
        validate_admission_inventory(&catalog).unwrap();
        let downloads = crate::download::DownloadCatalog::load_from_root(&catalog_root).unwrap();
        assert_eq!(downloads.routes.len(), 1);
        let retained = delivery == Some("retained");
        assert_eq!(downloads.routes[0].delivery.is_retained(), retained);
        let archives = catalog_root.join("objects/crates");
        assert_eq!(
            fs::read_dir(&archives).unwrap().count(),
            usize::from(retained)
        );
        if retained {
            let package = fixture.package("demo", &Version::new(1, 0, 0)).unwrap();
            assert_eq!(
                fs::read(archives.join(format!("{}.crate", sha256_bytes(&package.archive))))
                    .unwrap(),
                package.archive
            );
        }
        let site = temporary.path().join("site");
        assert_render_and_lock_convergence(&catalog_root, &site);
        crate::render::verify_monotonic(&site, &site).unwrap();
    }
}

#[test]
fn one_generated_batch_binds_multiple_locks_to_its_complete_hash() {
    let temporary = TemporaryDirectory::new("pkgre-admission-v2-batch");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "beta"]);
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("beta", "1.0.0", "src/lib.rs", b"pub fn beta() {}\n"),
    ]);
    let manifest_path = prepare_manifest(
        temporary.path(),
        &catalog_root,
        &fixture,
        &["alpha", "beta"],
        "2026-08-24-routine",
    );

    let summary = apply_admission_manifest_with(
        &catalog_root,
        &manifest_path,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert_eq!(summary.packages_added, 2);
    assert_admitted_catalog(
        &catalog_root,
        &fixture,
        &[
            ("alpha", "1.0.0", "main/general"),
            ("beta", "1.0.0", "main/general"),
        ],
        "2026-08-24-routine",
    );

    let lock_bytes = fs::read(catalog_root.join("admissions/2026-08-24-routine.lock")).unwrap();
    let batch_hash = sha256_bytes(&lock_bytes);
    let catalog = Catalog::load(&catalog_root).unwrap();
    let bindings = catalog
        .approvals
        .iter()
        .filter(|approval| approval.name == "alpha" || approval.name == "beta")
        .map(|approval| approval.admission_sha256.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(
        bindings,
        vec![Some(batch_hash.as_str()), Some(batch_hash.as_str())]
    );
    assert_eq!(
        fs::read_dir(catalog_root.join("admissions"))
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn later_resolution_failure_rolls_back_complete_multi_candidate_apply() {
    let temporary = TemporaryDirectory::new("pkgre-admission-v2-rollback");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "beta"]);
    lock::reconcile(&catalog_root).unwrap();
    let packages = vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("beta", "1.0.0", "src/lib.rs", b"pub fn beta() {}\n"),
    ];
    let planner = FixtureResolver::new(packages.clone());
    let lock_resolver =
        FixtureResolver::new(packages).with_lock_failure("beta", &Version::parse("1.0.0").unwrap());
    let manifest_path = prepare_manifest(
        temporary.path(),
        &catalog_root,
        &planner,
        &["alpha", "beta"],
        "2026-08-24-failing",
    );
    let before = snapshot_tree(&catalog_root).unwrap();

    let error = apply_admission_manifest_with(
        &catalog_root,
        &manifest_path,
        &planner,
        &lock_resolver,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();

    assert!(format!("{error:#}").contains("injected lock resolution failure for beta 1.0.0"));
    assert_eq!(lock_resolver.lock_calls.get(), 2);
    assert_eq!(snapshot_tree(&catalog_root).unwrap(), before);
}

#[test]
fn apply_rejects_upstream_yank_and_route_drift_without_mutating_catalog() {
    let temporary = TemporaryDirectory::new("pkgre-admission-v2-drift");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["demo"]);
    lock::reconcile(&catalog_root).unwrap();
    let package = FixturePackage::new("demo", "1.0.0", "src/lib.rs", b"pub fn demo() {}\n");
    let planned = FixtureResolver::new(vec![package.clone()]);
    let manifest_path = prepare_manifest(
        temporary.path(),
        &catalog_root,
        &planned,
        &["demo"],
        "2026-08-24-drift",
    );
    let before = snapshot_tree(&catalog_root).unwrap();

    let yanked = FixtureResolver::new(vec![package.with_yanked(true)]);
    let error = apply_admission_manifest_with(
        &catalog_root,
        &manifest_path,
        &yanked,
        &planned,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("yanked"));
    assert_eq!(snapshot_tree(&catalog_root).unwrap(), before);

    let mut manifest = load_admission_manifest(&manifest_path).unwrap();
    manifest.entries[0].category = "main/matrix".parse().unwrap();
    fs::write(
        &manifest_path,
        serialize_admission_manifest(&manifest).unwrap(),
    )
    .unwrap();
    let error = apply_admission_manifest_with(
        &catalog_root,
        &manifest_path,
        &planned,
        &planned,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("route differs from permanent home"));
    assert_eq!(snapshot_tree(&catalog_root).unwrap(), before);
}

#[test]
#[allow(clippy::too_many_lines)]
fn exact_request_older_than_every_locked_release_reviews_the_whole_archive() {
    let temporary = TemporaryDirectory::new("pkgre-admission-v2-predating");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["demo"]);
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("demo", "1.0.0", "src/lib.rs", b"pub fn demo() {}\n")
            .with_published_at("2021-01-01T00:00:00Z"),
        FixturePackage::new("demo", "0.9.0", "src/lib.rs", b"pub fn demo_v0() {}\n")
            .with_published_at("2020-01-01T00:00:00Z"),
    ]);
    let first = prepare_manifest(
        temporary.path(),
        &catalog_root,
        &fixture,
        &["demo"],
        "2026-08-24-demo",
    );
    apply_admission_manifest_with(
        &catalog_root,
        &first,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();

    let older = Version::parse("0.9.0").unwrap();
    let manifest_path = temporary.path().join("2026-08-25-demo-0-9-0.toml");
    let plan = plan_exact_update_with(
        &catalog_root,
        "demo",
        &older,
        &manifest_path,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    let candidate = &plan.candidates[0];
    assert_eq!(candidate.activity, PackageActivity::Active);
    assert_eq!(candidate.candidate.version, older);
    assert!(candidate.base.is_none());
    assert!(candidate.base_archive.is_none());
    assert!(candidate.archive_delta.is_none());
    assert!(candidate.dormant_gap.is_none());
    assert!(
        candidate
            .reasons
            .contains(&DecisionReason::PredatesLockedReleases)
    );
    assert!(
        candidate
            .reasons
            .contains(&DecisionReason::ExplicitCandidate)
    );
    assert_eq!(candidate.decision, UpdateDecision::ReviewRequired);

    let review = temporary.path().join("review-demo-0.9.0");
    inspect_update_candidate_with(
        &catalog_root,
        &manifest_path,
        "demo",
        &older,
        &review,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert!(review.join("candidate.crate").is_file());
    assert!(!review.join("base.crate").exists());

    let summary = apply_admission_manifest_with(
        &catalog_root,
        &manifest_path,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert!(summary.changed);
    assert_eq!(summary.names_added, 0);
    assert_eq!(summary.packages_added, 1);

    let catalog = Catalog::load(&catalog_root).unwrap();
    validate_catalog(&catalog).unwrap();
    validate_admission_inventory(&catalog).unwrap();
    let locked = catalog
        .approvals
        .iter()
        .find(|approval| approval.name == "demo" && approval.version == older)
        .unwrap();
    assert_eq!(locked.state, PackageState::Active);
    assert!(locked.admission_sha256.is_some());
    let declaration = fs::read_to_string(catalog_root.join("main.toml")).unwrap();
    assert!(
        declaration.contains("demo = [\"0.9.0\",\"1.0.0\"]"),
        "declaration: {declaration}"
    );

    crate::check::check(&catalog_root).unwrap();
    let fingerprint = super::catalog_fingerprint(&catalog_root).unwrap();
    assert_eq!(
        lock::reconcile(&catalog_root).unwrap(),
        ReconcileSummary::default()
    );
    assert_eq!(
        super::catalog_fingerprint(&catalog_root).unwrap(),
        fingerprint
    );
}

#[test]
fn exact_request_not_newer_than_its_lane_is_refused_by_planning_and_application_alike() {
    let temporary = TemporaryDirectory::new("pkgre-admission-v2-lane");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["demo"]);
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("demo", "1.2.0", "src/lib.rs", b"pub fn demo() {}\n")
            .with_published_at("2021-01-01T00:00:00Z"),
        FixturePackage::new("demo", "1.1.0", "src/lib.rs", b"pub fn demo_old() {}\n")
            .with_published_at("2023-01-01T00:00:00Z"),
    ]);
    let first = temporary.path().join("2026-08-24-demo.toml");
    plan_exact_update_with(
        &catalog_root,
        "demo",
        &Version::parse("1.2.0").unwrap(),
        &first,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    apply_admission_manifest_with(
        &catalog_root,
        &first,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();

    let superseded = Version::parse("1.1.0").unwrap();
    let expected = "requested identity 1.1.0 is not newer than active lane maximum 1.2.0";
    let manifest_path = temporary.path().join("2026-08-25-demo-1-1-0.toml");
    let offline = FixtureResolver::new(Vec::new());
    let error = plan_exact_update_with(
        &catalog_root,
        "demo",
        &superseded,
        &manifest_path,
        &offline,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(format!("{error:#}"), expected);
    assert!(!manifest_path.exists());

    let error = plan_exact_update_with(
        &catalog_root,
        "demo",
        &superseded,
        &manifest_path,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(format!("{error:#}"), expected);

    let manifest = AdmissionManifest {
        schema: super::ADMISSION_MANIFEST_SCHEMA,
        entries: vec![AdmissionRequest {
            category: "main/general".parse().unwrap(),
            name: "demo".to_owned(),
            version: Some(superseded),
            tag: None,
            evidence: Vec::new(),
        }],
    };
    let request_path = temporary.path().join("2026-08-25-demo-superseded.toml");
    fs::write(
        &request_path,
        serialize_admission_manifest(&manifest).unwrap(),
    )
    .unwrap();
    let error = apply_admission_manifest_with(
        &catalog_root,
        &request_path,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").ends_with(expected),
        "unexpected error: {error:#}"
    );
}

/// Admits the held versions, then checks that planning and application refuse a lane request alike.
fn assert_plan_and_apply_refuse_a_lane_request_alike(
    label: &str,
    packages: Vec<FixturePackage>,
    held: &[&str],
    request: &str,
) {
    let temporary = TemporaryDirectory::new(label);
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["demo"]);
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(packages);
    for (index, version) in held.iter().enumerate() {
        let path = temporary.path().join(format!("2026-08-2{index}-demo.toml"));
        plan_exact_update_with(
            &catalog_root,
            "demo",
            &Version::parse(version).unwrap(),
            &path,
            &fixture,
            UtcTimestamp::now().unwrap(),
        )
        .unwrap();
        apply_admission_manifest_with(
            &catalog_root,
            &path,
            &fixture,
            &fixture,
            &UtcTimestamp::now().unwrap(),
        )
        .unwrap();
    }

    let requested = Version::parse(request).unwrap();
    let expected = "requested compatibility lane has no prior locked base";
    let manifest_path = temporary.path().join("2026-08-29-demo-lane.toml");
    let error = plan_exact_update_with(
        &catalog_root,
        "demo",
        &requested,
        &manifest_path,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(format!("{error:#}"), expected);
    assert!(!manifest_path.exists());

    let manifest = AdmissionManifest {
        schema: super::ADMISSION_MANIFEST_SCHEMA,
        entries: vec![AdmissionRequest {
            category: "main/general".parse().unwrap(),
            name: "demo".to_owned(),
            version: Some(requested),
            tag: None,
            evidence: Vec::new(),
        }],
    };
    let request_path = temporary.path().join("2026-08-29-demo-lane-request.toml");
    fs::write(
        &request_path,
        serialize_admission_manifest(&manifest).unwrap(),
    )
    .unwrap();
    let error = apply_admission_manifest_with(
        &catalog_root,
        &request_path,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").ends_with(expected),
        "unexpected error: {error:#}"
    );
}

#[test]
fn exact_request_newer_than_its_lane_but_published_before_every_lock_is_refused_alike() {
    assert_plan_and_apply_refuse_a_lane_request_alike(
        "pkgre-admission-v2-lane-out-of-order",
        vec![
            FixturePackage::new("demo", "1.5.1", "src/lib.rs", b"pub fn demo() {}\n")
                .with_published_at("2022-01-01T00:00:00Z"),
            FixturePackage::new("demo", "1.6.0", "src/lib.rs", b"pub fn demo_v16() {}\n")
                .with_published_at("2021-01-01T00:00:00Z"),
        ],
        &["1.5.1"],
        "1.6.0",
    );
}

#[test]
fn exact_request_newer_than_its_lane_with_only_a_cross_lane_lock_is_refused_alike() {
    assert_plan_and_apply_refuse_a_lane_request_alike(
        "pkgre-admission-v2-lane-cross",
        vec![
            FixturePackage::new("demo", "0.9.0", "src/lib.rs", b"pub fn demo_v09() {}\n")
                .with_published_at("2019-01-01T00:00:00Z"),
            FixturePackage::new("demo", "1.5.1", "src/lib.rs", b"pub fn demo() {}\n")
                .with_published_at("2022-01-01T00:00:00Z"),
            FixturePackage::new("demo", "1.6.0", "src/lib.rs", b"pub fn demo_v16() {}\n")
                .with_published_at("2021-01-01T00:00:00Z"),
        ],
        &["0.9.0", "1.5.1"],
        "1.6.0",
    );
}

fn malicious_build_fixture(marker: &Path) -> FixtureResolver {
    let payload = format!(
        "fn main() {{ std::fs::write({:?}, b\"executed\").unwrap(); }}\n",
        marker.display().to_string()
    );
    FixtureResolver::new(vec![FixturePackage::new(
        "demo",
        "1.0.0",
        "build.rs",
        payload.as_bytes(),
    )])
}

fn prepare_manifest(
    temporary: &Path,
    catalog_root: &Path,
    resolver: &FixtureResolver,
    names: &[&str],
    stem: &str,
) -> PathBuf {
    let requests = names
        .iter()
        .map(|name| exact(name, "1.0.0"))
        .collect::<Vec<_>>();
    let path = temporary.join(format!("{stem}.toml"));
    plan_exact_updates_with(
        catalog_root,
        &requests,
        &path,
        resolver,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    path
}

fn assert_admitted_catalog(
    root: &Path,
    fixture: &FixtureResolver,
    identities: &[(&str, &str, &str)],
    batch_stem: &str,
) {
    let catalog = Catalog::load(root).unwrap();
    validate_catalog(&catalog).unwrap();
    ArtifactMap::load(&catalog).unwrap();
    validate_admission_inventory(&catalog).unwrap();
    let lock_path = root.join("admissions").join(format!("{batch_stem}.lock"));
    let batch_hash = sha256_bytes(&fs::read(&lock_path).unwrap());
    for (name, version, category) in identities {
        let version = Version::parse(version).unwrap();
        let locked = catalog
            .approvals
            .iter()
            .find(|approval| approval.name == *name && approval.version == version)
            .unwrap();
        let package = fixture.package(name, &version).unwrap();
        assert_eq!(locked.registry, "main");
        assert_eq!(locked.category.to_string(), *category);
        assert_eq!(locked.archive_sha256, sha256_bytes(&package.archive));
        assert_eq!(
            locked.admission_sha256.as_deref(),
            Some(batch_hash.as_str())
        );
        assert_eq!(
            locked.index_record_sha256,
            sha256_bytes(&package.source_row())
        );
        assert!(matches!(locked.source, Source::CratesIo));
        assert_eq!(
            fs::read(
                root.join("objects/rows")
                    .join(format!("{}.json", locked.index_record_sha256))
            )
            .unwrap(),
            package.source_row()
        );
        assert!(
            fs::read_to_string(root.join("main.toml"))
                .unwrap()
                .lines()
                .find(|line| line.starts_with(&format!("{name} = [")))
                .is_some_and(|line| line.contains(&format!("\"{version}\""))),
            "{name} declaration lacks {version}"
        );
    }
    assert_eq!(
        fs::read_dir(root.join("objects/crates")).unwrap().count(),
        0,
        "mirror archives must not be retained in the catalog"
    );
    assert!(
        root.join("admissions")
            .join(format!("{batch_stem}.toml"))
            .is_file()
    );
    assert!(lock_path.is_file());
}

fn assert_admission_failures_reach_ordinary_catalog_verification(root: &Path, stem: &str) {
    let admissions = root.join("admissions");
    let manifest = admissions.join(format!("{stem}.toml"));
    let lock = admissions.join(format!("{stem}.lock"));
    let manifest_bytes = fs::read(&manifest).unwrap();
    let lock_bytes = fs::read(&lock).unwrap();

    fs::OpenOptions::new()
        .append(true)
        .open(&manifest)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    assert!(Catalog::load(root).is_err());
    fs::write(&manifest, &manifest_bytes).unwrap();

    fs::OpenOptions::new()
        .append(true)
        .open(&lock)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    assert!(Catalog::load(root).is_err());
    fs::write(&lock, &lock_bytes).unwrap();

    fs::remove_file(&manifest).unwrap();
    assert!(Catalog::load(root).is_err());
    fs::write(&manifest, &manifest_bytes).unwrap();

    fs::remove_file(&lock).unwrap();
    assert!(Catalog::load(root).is_err());
    fs::write(&lock, &lock_bytes).unwrap();

    let orphan = admissions.join("unexpected.toml");
    fs::write(&orphan, &manifest_bytes).unwrap();
    assert!(Catalog::load(root).is_err());
    fs::remove_file(orphan).unwrap();
    Catalog::load(root).unwrap();
}

fn assert_render_and_lock_convergence(root: &Path, site: &Path) {
    let catalog = Catalog::load(root).unwrap();
    let artifacts = ArtifactMap::load(&catalog).unwrap();
    crate::render::render(&catalog, &artifacts, site).unwrap();
    crate::render::verify(&catalog, &artifacts, site).unwrap();

    let fingerprint = super::catalog_fingerprint(root).unwrap();
    assert_eq!(lock::reconcile(root).unwrap(), ReconcileSummary::default());
    assert_eq!(super::catalog_fingerprint(root).unwrap(), fingerprint);
}

#[derive(Clone)]
struct FixturePackage {
    name: String,
    version: Version,
    archive: Vec<u8>,
    published_at: String,
    yanked: bool,
    dependencies: Vec<String>,
}

impl FixturePackage {
    fn new(name: &str, version: &str, file: &str, contents: &[u8]) -> Self {
        let version = Version::parse(version).unwrap();
        let archive = crate_archive(name, &version, file, contents);
        Self {
            name: name.to_owned(),
            version,
            archive,
            published_at: "2020-01-01T00:00:00Z".to_owned(),
            yanked: false,
            dependencies: Vec::new(),
        }
    }

    fn with_dependency(mut self, package: &str) -> Self {
        self.dependencies.push(package.to_owned());
        self
    }

    fn with_yanked(mut self, yanked: bool) -> Self {
        self.yanked = yanked;
        self
    }

    fn with_published_at(mut self, published_at: &str) -> Self {
        self.published_at = published_at.to_owned();
        self
    }

    fn source_row(&self) -> Vec<u8> {
        let mut source_row = serde_json::to_vec(&json!({
            "name": self.name,
            "vers": self.version.to_string(),
            "deps": self.dependencies.iter().map(|package| json!({
                "name": package,
                "req": "^1",
                "features": [],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
            })).collect::<Vec<_>>(),
            "cksum": sha256_bytes(&self.archive),
            "features": {},
            "yanked": self.yanked,
            "pubtime": self.published_at,
        }))
        .unwrap();
        source_row.push(b'\n');
        source_row
    }
}

struct FixtureResolver {
    packages: BTreeMap<(String, Version), FixturePackage>,
    history_calls: Cell<usize>,
    archive_calls: Cell<usize>,
    source_calls: Cell<usize>,
    lock_calls: Cell<usize>,
    fail_history_for: Vec<String>,
    fail_archive_for: Vec<(String, Version)>,
    fail_lock_for: Option<(String, Version)>,
}

impl FixtureResolver {
    fn new(packages: Vec<FixturePackage>) -> Self {
        Self {
            packages: packages
                .into_iter()
                .map(|package| ((package.name.clone(), package.version.clone()), package))
                .collect(),
            history_calls: Cell::new(0),
            archive_calls: Cell::new(0),
            source_calls: Cell::new(0),
            lock_calls: Cell::new(0),
            fail_history_for: Vec::new(),
            fail_archive_for: Vec::new(),
            fail_lock_for: None,
        }
    }

    fn with_history_failure(mut self, name: &str) -> Self {
        self.fail_history_for.push(name.to_owned());
        self
    }

    fn with_archive_failure(mut self, name: &str, version: &Version) -> Self {
        self.fail_archive_for
            .push((name.to_owned(), version.clone()));
        self
    }

    fn with_lock_failure(mut self, name: &str, version: &Version) -> Self {
        self.fail_lock_for = Some((name.to_owned(), version.clone()));
        self
    }

    fn package(&self, name: &str, version: &Version) -> Result<&FixturePackage> {
        self.packages
            .get(&(name.to_owned(), version.clone()))
            .with_context(|| format!("fixture has no package {name} {version}"))
    }
}

impl PlannerResolver for FixtureResolver {
    fn history(&self, name: &str) -> Result<CratesIoHistory> {
        self.history_calls.set(self.history_calls.get() + 1);
        if self.fail_history_for.iter().any(|failed| failed == name) {
            bail!("injected history failure for {name}");
        }
        let mut packages = self
            .packages
            .values()
            .filter(|package| package.name == name)
            .collect::<Vec<_>>();
        ensure!(!packages.is_empty(), "fixture has no history for {name}");
        packages.sort_by(|left, right| left.version.cmp(&right.version));
        let rows = packages
            .iter()
            .map(|package| {
                let bytes = package.source_row();
                let record = IndexRecord::parse(&bytes)?;
                record.validate_structure()?;
                Ok(SparseIndexRow { bytes, record })
            })
            .collect::<Result<Vec<_>>>()?;
        let bytes = rows
            .iter()
            .flat_map(|row| row.bytes.clone())
            .collect::<Vec<u8>>();
        Ok(CratesIoHistory {
            sha256: sha256_bytes(&bytes),
            bytes,
            rows,
        })
    }

    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>> {
        self.archive_calls.set(self.archive_calls.get() + 1);
        if self
            .fail_archive_for
            .iter()
            .any(|identity| identity == &(name.to_owned(), version.clone()))
        {
            bail!("injected archive failure for {name} {version}");
        }
        let package = self.package(name, version)?;
        ensure!(sha256_bytes(&package.archive) == checksum);
        Ok(package.archive.clone())
    }

    fn api(&self, _: &str) -> Result<Vec<u8>> {
        bail!("fixture intentionally has no crates.io API evidence")
    }

    fn source(
        &self,
        _: &super::ArchiveAnalysis,
        _: &super::ArchiveLineEndings,
        _: Option<&[u8]>,
        _: Option<&super::ApiVersionEvidence>,
    ) -> Result<SourceCorrespondence> {
        self.source_calls.set(self.source_calls.get() + 1);
        Ok(SourceCorrespondence {
            evidence: SourceEvidence::Unavailable {
                reason: "fixture-no-public-source".to_owned(),
            },
            comparison: None,
        })
    }
}

impl InspectionResolver for FixtureResolver {
    fn archive(&self, name: &str, version: &Version, checksum: &str) -> Result<Vec<u8>> {
        PlannerResolver::archive(self, name, version, checksum)
    }
}

impl Resolver for FixtureResolver {
    fn resolve_mirror(&self, name: &str, version: &Version) -> Result<ResolvedPackage> {
        self.lock_calls.set(self.lock_calls.get() + 1);
        if self
            .fail_lock_for
            .as_ref()
            .is_some_and(|identity| identity == &(name.to_owned(), version.clone()))
        {
            bail!("injected lock resolution failure for {name} {version}");
        }
        let package = self.package(name, version)?;
        Ok(ResolvedPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            archive_bytes: package.archive.clone(),
            source_row_bytes: package.source_row(),
            published_at: None,
            source: LockedSource::CratesIo {},
        })
    }

    fn resolve_git_tag_group(
        &self,
        _: &str,
        _: &str,
        _: &[&str],
        _: &[crate::package::PublishedPackage<'_>],
        _: &Version,
    ) -> Result<Vec<ResolvedPackage>> {
        bail!("fixture does not resolve Git tags")
    }
}

fn write_catalog(root: &Path, general_names: &[&str]) {
    write_catalog_with(root, general_names, None);
}

/// Writes the fixture catalog, declaring `extra`'s names in that second category as well.
fn write_catalog_with(root: &Path, general_names: &[&str], extra: Option<(&str, &[&str])>) {
    fs::create_dir_all(root).unwrap();
    let mut general_declarations = String::new();
    for name in general_names {
        writeln!(general_declarations, "{name} = []").unwrap();
    }
    let mut categories = mirror_category(
        "general",
        &["main/general"],
        &general_declarations,
        "reserved-general",
    );
    for (local, dependencies) in [
        ("acp", &["main/acp", "main/general"] as &[_]),
        ("filesystem", &["main/filesystem", "main/general"] as &[_]),
        ("matrix", &["main/matrix", "main/general"] as &[_]),
        ("mcp", &["main/mcp", "main/sse", "main/general"] as &[_]),
        ("sse", &["main/sse", "main/general"] as &[_]),
        ("terminal", &["main/terminal", "main/general"] as &[_]),
        ("yaml", &["main/yaml", "main/general"] as &[_]),
    ] {
        let mut declarations = String::new();
        if let Some((category, names)) = extra {
            if category == local {
                for name in names {
                    writeln!(declarations, "{name} = []").unwrap();
                }
            }
        }
        categories.push_str(&mirror_category(
            local,
            dependencies,
            &declarations,
            &format!("reserved-{local}"),
        ));
    }
    categories.push_str(concat!(
        "[categories.pkgre]\n",
        "may-depend-on = [\"main/pkgre\", \"main/general\"]\n\n",
        "[categories.pkgre.publish.pkgre-category-anchor]\n",
        "git = \"https://github.com/pkgre/pkgre\"\n",
        "tags = []\n",
    ));
    write_registry(
        root,
        "main",
        &crate::download::router_download_template("main"),
        &categories,
    );
}

fn mirror_category(
    local: &str,
    dependencies: &[&str],
    declarations: &str,
    fallback_name: &str,
) -> String {
    let dependencies = dependencies
        .iter()
        .map(|category| format!("\"{category}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let declarations = if declarations.trim().is_empty() {
        format!("{fallback_name} = []\n")
    } else {
        declarations.to_owned()
    };
    format!(
        "[categories.{local}]\nmay-depend-on = [{dependencies}]\n\n[categories.{local}.mirror]\n{declarations}\n"
    )
}

fn write_registry(root: &Path, name: &str, download: &str, categories: &str) {
    let index = crate::policy::canonical_registry_index(name);
    fs::write(
        root.join(format!("{name}.toml")),
        format!(
            "schema = 5\n\n[registry]\nname = {name:?}\nindex = {index:?}\ndownload = {download:?}\naudience = \"public\"\ncargo-version = \"1.95.0\"\n\n{categories}"
        ),
    )
    .unwrap();
}

fn crate_archive(name: &str, version: &Version, relative_path: &str, contents: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 512;
    let path = format!("{name}-{version}/{relative_path}");
    let mut header = [0_u8; BLOCK];
    set_string(&mut header[..100], &path);
    set_octal(&mut header[100..108], 0o644);
    set_octal(&mut header[108..116], 0);
    set_octal(&mut header[116..124], 0);
    set_octal(&mut header[124..136], contents.len() as u64);
    set_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
    set_octal(&mut header[148..156], checksum);
    let mut tar = header.to_vec();
    tar.extend_from_slice(contents);
    tar.resize(tar.len() + (BLOCK - contents.len() % BLOCK) % BLOCK, 0);
    tar.resize(tar.len() + BLOCK * 2, 0);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

fn set_string(field: &mut [u8], value: &str) {
    assert!(value.len() < field.len());
    field[..value.len()].copy_from_slice(value.as_bytes());
}

fn set_octal(field: &mut [u8], value: u64) {
    let digits = format!("{:0width$o}", value, width = field.len() - 2);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[field.len() - 2] = 0;
    field[field.len() - 1] = b' ';
}

#[derive(Debug, Eq, PartialEq)]
enum SnapshotEntry {
    Directory,
    File(Vec<u8>),
}

fn snapshot_tree(root: &Path) -> Result<BTreeMap<PathBuf, SnapshotEntry>> {
    let mut snapshot = BTreeMap::new();
    snapshot_directory(root, root, &mut snapshot)?;
    Ok(snapshot)
}

fn snapshot_directory(
    root: &Path,
    directory: &Path,
    snapshot: &mut BTreeMap<PathBuf, SnapshotEntry>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read snapshot directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .context("snapshot entry escaped root")?
            .to_path_buf();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect snapshot entry {}", path.display()))?;
        if metadata.file_type().is_dir() {
            ensure!(
                snapshot
                    .insert(relative, SnapshotEntry::Directory)
                    .is_none()
            );
            snapshot_directory(root, &path, snapshot)?;
        } else {
            ensure!(
                metadata.file_type().is_file(),
                "snapshot entry is not a regular file: {}",
                path.display()
            );
            ensure!(
                snapshot
                    .insert(relative, SnapshotEntry::File(fs::read(&path)?))
                    .is_none()
            );
        }
    }
    Ok(())
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn exact(name: &str, version: &str) -> ExactRequest {
    ExactRequest {
        name: name.to_owned(),
        version: Version::parse(version).unwrap(),
    }
}

/// The canonical template of the batch in the merge test, in manifest key order.
const EXACT_BATCH_TEMPLATE: &str = "\
schema = 2

[[admit]]
category = \"main/general\"
name = \"alpha\"
version = \"1.0.0\"

[[admit]]
category = \"main/general\"
name = \"beta\"
version = \"1.0.0\"

[[admit]]
category = \"main/general\"
name = \"uint\"
version = \"0.10.2\"

[[admit]]
category = \"main/general\"
name = \"uint\"
version = \"0.9.5\"

[[admit]]
category = \"main/terminal\"
name = \"tty\"
version = \"1.0.0\"
";

#[test]
fn exact_batch_template_equals_the_canonical_merge_of_single_templates() {
    let temporary = TemporaryDirectory::new("pkgre-exact-batch-merge");
    let catalog_root = temporary.path().join("catalog");
    write_catalog_with(
        &catalog_root,
        &["alpha", "beta", "uint"],
        Some(("terminal", &["tty"])),
    );
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("beta", "1.0.0", "src/lib.rs", b"pub fn beta() {}\n"),
        FixturePackage::new("tty", "1.0.0", "src/lib.rs", b"pub fn tty() {}\n"),
        FixturePackage::new("uint", "0.9.5", "src/lib.rs", b"pub fn old() {}\n"),
        FixturePackage::new("uint", "0.10.2", "src/lib.rs", b"pub fn new() {}\n"),
    ]);
    let requests = [
        exact("uint", "0.9.5"),
        exact("tty", "1.0.0"),
        exact("uint", "0.10.2"),
        exact("alpha", "1.0.0"),
        exact("beta", "1.0.0"),
    ];
    let evaluated_at = UtcTimestamp::now().unwrap();
    let batch = temporary.path().join("2026-08-24-batch.toml");
    let plan = plan_exact_updates_with(
        &catalog_root,
        &requests,
        &batch,
        &fixture,
        evaluated_at.clone(),
    )
    .unwrap();
    assert_eq!(plan.candidates.len(), 5);
    assert_eq!(
        fixture.history_calls.get(),
        4,
        "uint's two identities share one history fetch"
    );

    let template = fs::read(&batch).unwrap();
    assert_eq!(
        String::from_utf8(template.clone()).unwrap(),
        EXACT_BATCH_TEMPLATE
    );
    let text = String::from_utf8(template.clone()).unwrap();
    assert!(text.find("\"0.10.2\"").unwrap() < text.find("\"0.9.5\"").unwrap());

    let mut entries = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        let single = temporary.path().join(format!("single-{index}.toml"));
        plan_exact_update_with(
            &catalog_root,
            &request.name,
            &request.version,
            &single,
            &fixture,
            evaluated_at.clone(),
        )
        .unwrap();
        entries.extend(load_admission_manifest(&single).unwrap().entries);
    }
    entries.sort_by_key(|entry| {
        (
            entry.category.to_string(),
            entry.name.to_ascii_lowercase(),
            entry.name.clone(),
            entry.version.as_ref().unwrap().to_string(),
        )
    });
    let merged = serialize_admission_manifest(&AdmissionManifest {
        schema: super::ADMISSION_MANIFEST_SCHEMA,
        entries,
    })
    .unwrap();
    assert_eq!(template, merged);

    let summary = apply_admission_manifest_with(
        &catalog_root,
        &batch,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    assert_eq!(summary.packages_added, 5, "one admission per identity");
    assert_admitted_catalog(
        &catalog_root,
        &fixture,
        &[
            ("alpha", "1.0.0", "main/general"),
            ("beta", "1.0.0", "main/general"),
            ("uint", "0.9.5", "main/general"),
            ("uint", "0.10.2", "main/general"),
            ("tty", "1.0.0", "main/terminal"),
        ],
        "2026-08-24-batch",
    );
}

#[test]
fn exact_batch_reports_every_catalog_stage_failure_before_any_fetch() {
    let temporary = TemporaryDirectory::new("pkgre-exact-batch-offline");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "demo"]);
    lock::reconcile(&catalog_root).unwrap();
    let seed = FixtureResolver::new(vec![FixturePackage::new(
        "demo",
        "1.2.0",
        "src/lib.rs",
        b"pub fn demo() {}\n",
    )]);
    let seeded = temporary.path().join("2026-08-23-demo.toml");
    plan_exact_update_with(
        &catalog_root,
        "demo",
        &Version::parse("1.2.0").unwrap(),
        &seeded,
        &seed,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    apply_admission_manifest_with(
        &catalog_root,
        &seeded,
        &seed,
        &seed,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();

    let offline = FixtureResolver::new(Vec::new());
    let output = temporary.path().join("2026-08-24-batch.toml");
    let error = plan_exact_updates_with(
        &catalog_root,
        &[
            exact("nowhere", "1.0.0"),
            exact("alpha", "1.0.0"),
            exact("demo", "1.1.0"),
            exact("alpha", "1.0.0"),
            exact("alpha", "1.0.0+build"),
        ],
        &output,
        &offline,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "4 of 5 exact requests failed: nowhere 1.0.0: requested update package \"nowhere\" is not a permanently reserved crates.io mirror name; demo 1.1.0: requested identity 1.1.0 is not newer than active lane maximum 1.2.0; alpha 1.0.0: exact requests repeat Cargo identity alpha 1.0.0; alpha 1.0.0+build: exact requests repeat Cargo identity alpha 1.0.0+build"
    );
    assert_eq!(offline.history_calls.get(), 0);
    assert!(!output.exists());
}

#[test]
fn exact_batch_reports_every_selection_failure_and_fetches_no_archive() {
    let temporary = TemporaryDirectory::new("pkgre-exact-batch-refused");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "beta", "delta", "gamma"]);
    lock::reconcile(&catalog_root).unwrap();
    let seed = FixtureResolver::new(vec![FixturePackage::new(
        "alpha",
        "1.0.0",
        "src/lib.rs",
        b"pub fn alpha() {}\n",
    )]);
    let seeded = temporary.path().join("2026-08-23-alpha.toml");
    plan_exact_update_with(
        &catalog_root,
        "alpha",
        &Version::parse("1.0.0").unwrap(),
        &seeded,
        &seed,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    apply_admission_manifest_with(
        &catalog_root,
        &seeded,
        &seed,
        &seed,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();

    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("beta", "1.0.0", "src/lib.rs", b"pub fn beta() {}\n").with_yanked(true),
        FixturePackage::new("delta", "1.0.0", "src/lib.rs", b"pub fn delta() {}\n"),
        FixturePackage::new("gamma", "1.0.0", "src/lib.rs", b"pub fn gamma() {}\n"),
    ]);
    let output = temporary.path().join("2026-08-24-batch.toml");
    let error = plan_exact_updates_with(
        &catalog_root,
        &[
            exact("gamma", "2.0.0"),
            exact("alpha", "1.0.0"),
            exact("delta", "1.0.0"),
            exact("beta", "1.0.0"),
        ],
        &output,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "3 of 4 exact requests failed: gamma 2.0.0: requested identity 2.0.0 is absent from upstream history; alpha 1.0.0: requested identity 1.0.0 is already locked; beta 1.0.0: requested identity 1.0.0 is yanked upstream"
    );
    assert_eq!(fixture.archive_calls.get(), 0);
    assert!(!output.exists());
}

#[test]
fn exact_batch_omits_blocked_candidates_from_its_template() {
    let temporary = TemporaryDirectory::new("pkgre-exact-batch-blocked");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "beta"]);
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("beta", "1.0.0", "src/lib.rs", b"pub fn beta() {}\n")
            .with_dependency("unhomed"),
    ]);
    let output = temporary.path().join("2026-08-24-batch.toml");
    let plan = plan_exact_updates_with(
        &catalog_root,
        &[exact("beta", "1.0.0"), exact("alpha", "1.0.0")],
        &output,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    let decisions = plan
        .candidates
        .iter()
        .map(|candidate| (candidate.name.as_str(), candidate.decision))
        .collect::<Vec<_>>();
    assert_eq!(
        decisions,
        [
            ("alpha", UpdateDecision::ReviewRequired),
            ("beta", UpdateDecision::Blocked)
        ]
    );
    let manifest = load_admission_manifest(&output).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].name, "alpha");
}

#[test]
fn exact_batch_reports_every_evidence_failure_in_argument_order() {
    let temporary = TemporaryDirectory::new("pkgre-exact-batch-evidence");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "beta", "delta"]);
    lock::reconcile(&catalog_root).unwrap();
    let failed = Version::parse("1.0.0").unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("beta", "1.0.0", "src/lib.rs", b"pub fn beta() {}\n"),
        FixturePackage::new("delta", "1.0.0", "src/lib.rs", b"pub fn delta() {}\n"),
    ])
    .with_archive_failure("beta", &failed)
    .with_archive_failure("delta", &failed);
    let output = temporary.path().join("2026-08-24-batch.toml");
    let error = plan_exact_updates_with(
        &catalog_root,
        &[
            exact("delta", "1.0.0"),
            exact("alpha", "1.0.0"),
            exact("beta", "1.0.0"),
        ],
        &output,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "2 of 3 exact requests failed: delta 1.0.0: fetch candidate archive delta 1.0.0: injected archive failure for delta 1.0.0; beta 1.0.0: fetch candidate archive beta 1.0.0: injected archive failure for beta 1.0.0"
    );
    assert!(!output.exists());
}

#[test]
fn exact_batch_reports_a_history_failure_for_every_identity_of_that_name() {
    let temporary = TemporaryDirectory::new("pkgre-exact-batch-history");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "uint"]);
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("uint", "0.9.5", "src/lib.rs", b"pub fn old() {}\n"),
        FixturePackage::new("uint", "0.10.2", "src/lib.rs", b"pub fn new() {}\n"),
    ])
    .with_history_failure("uint");
    let output = temporary.path().join("2026-08-24-batch.toml");
    let error = plan_exact_updates_with(
        &catalog_root,
        &[
            exact("uint", "0.9.5"),
            exact("alpha", "1.0.0"),
            exact("uint", "0.10.2"),
        ],
        &output,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "2 of 3 exact requests failed: uint 0.9.5: fetch complete crates.io history for main/uint: injected history failure for uint; uint 0.10.2: fetch complete crates.io history for main/uint: injected history failure for uint"
    );
    assert!(!output.exists());

    let single = temporary.path().join("2026-08-24-single.toml");
    let error = plan_exact_update_with(
        &catalog_root,
        "uint",
        &Version::parse("0.9.5").unwrap(),
        &single,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.chain().map(ToString::to_string).collect::<Vec<_>>(),
        [
            "fetch complete crates.io history for main/uint",
            "injected history failure for uint",
        ],
        "one identity keeps the error chain of the failure, not a flattened copy"
    );
    assert!(!single.exists());
}

#[test]
fn exact_planning_refuses_an_existing_template_path_before_any_fetch() {
    let temporary = TemporaryDirectory::new("pkgre-exact-batch-existing");
    let catalog_root = temporary.path().join("catalog");
    write_catalog(&catalog_root, &["alpha", "beta"]);
    lock::reconcile(&catalog_root).unwrap();
    let fixture = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("beta", "1.0.0", "src/lib.rs", b"pub fn beta() {}\n"),
    ]);
    let version = Version::parse("1.0.0").unwrap();
    let requests = [exact("beta", "1.0.0"), exact("alpha", "1.0.0")];
    for kind in ["file", "directory", "symlink"] {
        let output = temporary.path().join(format!("2026-08-24-{kind}.toml"));
        match kind {
            "directory" => fs::create_dir(&output).unwrap(),
            "symlink" => std::os::unix::fs::symlink("absent-target", &output).unwrap(),
            _ => fs::write(&output, b"existing\n").unwrap(),
        }
        let expected = format!("refusing to overwrite existing path {}", output.display());
        let batch_error = plan_exact_updates_with(
            &catalog_root,
            &requests,
            &output,
            &fixture,
            UtcTimestamp::now().unwrap(),
        )
        .unwrap_err();
        assert_eq!(format!("{batch_error:#}"), expected);
        let single_error = plan_exact_update_with(
            &catalog_root,
            "alpha",
            &version,
            &output,
            &fixture,
            UtcTimestamp::now().unwrap(),
        )
        .unwrap_err();
        assert_eq!(format!("{single_error:#}"), expected);
        assert_eq!(
            fixture.history_calls.get(),
            0,
            "the output path is refused before any fetch"
        );
    }

    let seeded = temporary.path().join("2026-08-23-alpha.toml");
    plan_exact_update_with(
        &catalog_root,
        "alpha",
        &version,
        &seeded,
        &fixture,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    apply_admission_manifest_with(
        &catalog_root,
        &seeded,
        &fixture,
        &fixture,
        &UtcTimestamp::now().unwrap(),
    )
    .unwrap();
    let runtime = FixtureResolver::new(vec![
        FixturePackage::new("alpha", "1.0.0", "src/lib.rs", b"pub fn alpha() {}\n"),
        FixturePackage::new("alpha", "1.1.0", "src/lib.rs", b"pub fn later() {}\n"),
    ]);
    let routine = temporary.path().join("2026-08-24-routine.toml");
    fs::write(&routine, b"existing\n").unwrap();
    let error = plan_updates_with(
        &catalog_root,
        &routine,
        &runtime,
        UtcTimestamp::now().unwrap(),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("create admission manifest"),
        "update-plan keeps its refusal at creation: {error:#}"
    );
    assert!(
        runtime.history_calls.get() > 0,
        "update-plan fetches its evidence before refusing the existing path"
    );
}
