//! Unit tests of the selection of the Git-tag identities a catalog change adds.

use std::path::PathBuf;

use super::*;
use crate::update::UtcTimestamp;

const CARGO_VERSION: &str = "1.95.0";

/// Builds one locked approval of a first-party Git tag.
fn git_tag(registry: &str, name: &str, version: &str, state: PackageState) -> Approval {
    Approval {
        registry: registry.to_owned(),
        category: format!("{registry}/pkgre").parse().unwrap(),
        name: name.to_owned(),
        version: Version::parse(version).unwrap(),
        archive_sha256: format!("{:064x}", version.len()),
        index_record_sha256: "02".repeat(32),
        index_row_sha256: "03".repeat(32),
        admission_sha256: None,
        admitted_at: UtcTimestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        state,
        source: Source::GitTag {
            repository: format!("https://example.invalid/{name}"),
            tag: format!("{name}/v{version}"),
            tag_oid: "11".repeat(20),
            commit: "22".repeat(20),
            package: name.to_owned(),
            subdir: PathBuf::from("."),
            cargo_version: Version::parse(CARGO_VERSION).unwrap(),
        },
        declared_in: PathBuf::from(format!("{registry}.lock")),
    }
}

/// Builds one locked approval of a crates.io mirror.
fn mirror(registry: &str, name: &str, version: &str) -> Approval {
    Approval {
        source: Source::CratesIo,
        ..git_tag(registry, name, version, PackageState::Active)
    }
}

/// Returns the identities of a selection, as `registry/name/version`.
fn selected(selection: &[&Approval]) -> Vec<String> {
    selection.iter().map(|value| identity_name(value)).collect()
}

#[test]
fn selects_the_added_git_tag_identities_in_registry_name_and_version_order() {
    let accepted = vec![
        git_tag("main", "pkgre-indexer", "0.1.0", PackageState::Active),
        mirror("main", "warp", "0.3.62"),
        git_tag("staging", "pkgre-indexer", "0.1.0", PackageState::Active),
    ];
    let candidate = vec![
        git_tag("staging", "pkgre-indexer", "0.2.0", PackageState::Active),
        git_tag("main", "pkgre-indexer", "0.1.0", PackageState::Active),
        mirror("main", "warp", "0.3.62"),
        mirror("main", "futures-util", "0.3.31"),
        git_tag("main", "pkgre-indexer", "0.10.0", PackageState::Active),
        git_tag("main", "pkgre-indexer", "0.2.0", PackageState::Active),
    ];

    let selection = added_git_tag_identities(&accepted, &candidate).unwrap();

    assert_eq!(
        selected(&selection),
        [
            "main/pkgre-indexer/0.2.0",
            "main/pkgre-indexer/0.10.0",
            "staging/pkgre-indexer/0.2.0"
        ],
        "a mirror and an identity the accepted catalog locks are not selected, \
         and the rest are ordered by registry, name, then version"
    );
}

#[test]
fn selects_nothing_when_the_candidate_adds_no_git_tag_identity() {
    let accepted = vec![git_tag(
        "main",
        "pkgre-indexer",
        "0.1.0",
        PackageState::Active,
    )];
    let mut candidate = accepted.clone();
    candidate.push(mirror("main", "warp", "0.3.62"));

    let selection = added_git_tag_identities(&accepted, &candidate).unwrap();

    assert!(selection.is_empty(), "{:?}", selected(&selection));
}

#[test]
fn refuses_a_removed_git_tag_identity_the_accepted_catalog_does_not_lock() {
    let accepted = vec![git_tag(
        "main",
        "pkgre-indexer",
        "0.1.0",
        PackageState::Active,
    )];
    let candidate = vec![
        git_tag("main", "pkgre-indexer", "0.1.0", PackageState::Active),
        git_tag("main", "pkgre-indexer", "0.2.0", PackageState::Removed),
    ];

    let error = added_git_tag_identities(&accepted, &candidate).unwrap_err();
    let message = format!("{error:#}");

    assert!(
        message.contains("main/pkgre-indexer/0.2.0 is a removed Git-tag identity")
            && message.contains("so this lock was not produced by `lock`"),
        "{message}"
    );
}

#[test]
fn a_reproduction_of_several_identities_stops_at_the_first_failure_and_names_it() {
    let approvals = [
        git_tag("main", "pkgre-indexer", "0.1.0", PackageState::Active),
        git_tag("main", "pkgre-indexer", "0.2.0", PackageState::Active),
        git_tag("main", "pkgre-indexer", "0.3.0", PackageState::Active),
    ];
    let references = approvals.iter().collect::<Vec<_>>();
    let mut reproduced = Vec::new();
    let error = reproduce_selected(&references, |approval| {
        reproduced.push(identity_name(approval));
        if approval.version == Version::parse("0.2.0").unwrap() {
            anyhow::bail!("the tag names another commit");
        }
        Ok(())
    })
    .unwrap_err();
    let message = format!("{error:#}");

    assert_eq!(
        reproduced,
        ["main/pkgre-indexer/0.1.0", "main/pkgre-indexer/0.2.0"],
        "a failure stops the run instead of reproducing the identities after it"
    );
    assert!(
        message.contains("reproduce added main/pkgre-indexer/0.2.0")
            && message.contains("the tag names another commit"),
        "{message}"
    );

    let reproduced = reproduce_selected(&references, |_| Ok(())).unwrap();
    assert_eq!(reproduced, 3, "a run reports every identity it reproduced");
}
