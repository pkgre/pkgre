//! Offline evidence for deterministic schema-4 to schema-5 catalog migration.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use pkgre_rust::migrate::{migrate_retained_delivery, migrate_v4_to_v5};
use pkgre_rust::policy::validate_catalog;
use pkgre_rust::projection::ProjectionLimits;
use pkgre_rust::schema::Catalog;
use pkgre_rust::serve::{DeliveryMode, build_snapshot};

const FIXTURE_SHA256: &str = "9c70bcffb58b92003f9c950656953b51844aeaa1d86183b86415f09da334f2fa";
const FIXTURE: &[u8] = include_bytes!("fixtures/rust-current-catalog-f9b5ffa.tar.gz");
// Canonical UTC git-tag committer times; the CLI accepts RFC 3339 but the library
// migration entry point requires canonical YYYY-MM-DDTHH:MM:SSZ input.
const GIT_TAG_TIME_0_1_1: &str = "2026-08-22T17:57:02Z";
const GIT_TAG_TIME_0_2_0: &str = "2026-08-22T22:38:36Z";
const GIT_TAG_TIME_0_3_0: &str = "2026-08-24T02:26:23Z";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn frozen_v4_catalog_migrates_deterministically_to_valid_v5() {
    assert_eq!(
        pkgre_rust::artifact::sha256_bytes(FIXTURE),
        FIXTURE_SHA256,
        "frozen schema-4 catalog fixture must remain unchanged"
    );

    let temporary = TemporaryDirectory::new("pkgre-rust-migrate");
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    let extraction = temporary.path().join("extracted");
    extract_fixture(FIXTURE, &extraction);
    let input = extraction.join("registry");

    let git_times = git_tag_times();

    let summary = migrate_v4_to_v5(&input, &first, &git_times).unwrap();
    assert_eq!(summary.routes, 747);
    assert_eq!(
        summary
            .registries
            .iter()
            .map(|registry| (registry.name.as_str(), registry.packages))
            .collect::<Vec<_>>(),
        vec![("main", 747)]
    );
    migrate_v4_to_v5(&input, &second, &git_times).unwrap();

    assert!(
        trees_equal(&first, &second),
        "migration must be deterministic across runs"
    );

    let catalog = Catalog::load(&first).unwrap();
    let registry = &catalog.registries.registries[0];
    assert_eq!(registry.name, "main");
    assert_eq!(registry.audience, pkgre_rust::schema::Audience::Public);
    assert_eq!(catalog.approvals.len(), 747);
    let git_tag = catalog
        .approvals
        .iter()
        .find(|approval| {
            matches!(
                &approval.source,
                pkgre_rust::schema::Source::GitTag { tag, .. } if tag == "indexer/v0.2.0"
            )
        })
        .unwrap();
    assert_eq!(
        git_tag.admitted_at.to_string(),
        "2026-08-22T22:38:36Z",
        "offset RFC 3339 git-tag timestamps must canonicalize to UTC"
    );

    let downloads = fs::read(first.join("downloads.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&downloads).unwrap();
    assert_eq!(value["schema"], 2);
    let routes = value["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 747);
    let retained = routes
        .iter()
        .filter(|route| route["delivery"]["delivery"] == "retained")
        .count();
    let redirected = routes
        .iter()
        .filter(|route| route["delivery"]["delivery"] == "redirect")
        .count();
    assert_eq!((retained, redirected), (3, 744));
    let first_retained = routes
        .iter()
        .find(|route| route["delivery"]["delivery"] == "retained")
        .unwrap();
    assert_eq!(first_retained["name"], "pkgre-indexer");
    assert!(
        first_retained["delivery"]["path"]
            .as_str()
            .unwrap()
            .starts_with("main/objects/crates/"),
        "retained delivery must point into the registry object store"
    );
}

fn git_tag_times() -> Vec<(String, String)> {
    vec![
        (
            "main/pkgre-indexer@indexer/v0.1.1".to_owned(),
            GIT_TAG_TIME_0_1_1.to_owned(),
        ),
        (
            "main/pkgre-indexer@indexer/v0.2.0".to_owned(),
            GIT_TAG_TIME_0_2_0.to_owned(),
        ),
        (
            "main/pkgre-indexer@indexer/v0.3.0".to_owned(),
            GIT_TAG_TIME_0_3_0.to_owned(),
        ),
    ]
}

#[test]
fn retained_delivery_migration_is_in_place_idempotent_and_strictly_gated() {
    let temporary = TemporaryDirectory::new("pkgre-rust-retained-delivery");
    let extraction = temporary.path().join("extracted");
    extract_fixture(FIXTURE, &extraction);
    let registry = temporary.path().join("registry");
    migrate_v4_to_v5(&extraction.join("registry"), &registry, &git_tag_times()).unwrap();

    // A marker comment proves the in-place edit preserves comments and formatting.
    let main_path = registry.join("main.toml");
    let marked = format!(
        "# retained-delivery migration marker\n{}",
        fs::read_to_string(&main_path).unwrap()
    );
    fs::write(&main_path, &marked).unwrap();

    let summary = migrate_retained_delivery(&registry).unwrap();
    assert_eq!(summary.registries, 1);
    assert!(summary.changed);
    assert_eq!((summary.retained_routes, summary.total_routes), (747, 747));

    let migrated = fs::read_to_string(&main_path).unwrap();
    assert!(migrated.contains("delivery = \"retained\""));
    assert_eq!(
        migrated.replacen("delivery = \"retained\"\n", "", 1),
        marked
    );

    let downloads = fs::read(registry.join("downloads.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&downloads).unwrap();
    let routes = value["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 747);
    assert!(
        routes
            .iter()
            .all(|route| route["delivery"]["delivery"] == "retained"),
        "every route must become retained after the migration"
    );
    assert!(
        routes.iter().all(|route| route["delivery"]["path"]
            .as_str()
            .unwrap()
            .starts_with("main/objects/crates/")),
        "retained deliveries must point into the registry object store"
    );

    // Strict gates pass before the retained bodies are imported: catalog loading
    // does not verify objects, while serving fails closed instead.
    let catalog = Catalog::load(&registry).unwrap();
    assert_eq!(catalog.approvals.len(), 747);
    validate_catalog(&catalog).unwrap();

    let second = migrate_retained_delivery(&registry).unwrap();
    assert_eq!(second.registries, 1);
    assert!(!second.changed);
    assert_eq!((second.retained_routes, second.total_routes), (747, 747));
    assert_eq!(fs::read_to_string(&main_path).unwrap(), migrated);
    assert_eq!(
        fs::read(registry.join("downloads.json")).unwrap(),
        downloads
    );

    let error = build_snapshot(
        &registry,
        DeliveryMode::Redirect,
        None,
        ProjectionLimits::default(),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("differs from generated locks"),
        "serving must fail closed on unimported retained bodies: {error:#}"
    );
}

#[test]
fn missing_git_tag_time_error_shows_the_accepted_form() {
    let temporary = TemporaryDirectory::new("pkgre-rust-migrate-tag-time");
    let extraction = temporary.path().join("extracted");
    extract_fixture(FIXTURE, &extraction);
    let input = extraction.join("registry");
    let output = temporary.path().join("migrated");

    let mut git_times = git_tag_times();
    git_times.pop();
    let error = migrate_v4_to_v5(&input, &output, &git_times).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("missing --git-tag-time mapping for main/pkgre-indexer"),
        "{message}"
    );
    assert!(
        message.contains("--git-tag-time=main/pkgre-indexer@indexer/v0.3.0=<canonical-timestamp>"),
        "the error must name the accepted argument form: {message}"
    );
}

#[test]
fn failed_migration_leaves_no_destination() {
    let temporary = TemporaryDirectory::new("pkgre-rust-migrate-failure");
    let extraction = temporary.path().join("extracted");
    extract_fixture(FIXTURE, &extraction);
    let input = extraction.join("registry");
    let output = temporary.path().join("migrated");

    // The missing last Git-tag mapping fails the migration after its staged copy has
    // already been rewritten, which is exactly the case that used to leave a partial tree.
    let mut git_times = git_tag_times();
    git_times.pop();
    migrate_v4_to_v5(&input, &output, &git_times).unwrap_err();
    assert!(
        !output.exists(),
        "a failed migration must leave no destination at {}",
        output.display()
    );
    assert_eq!(
        entry_names(temporary.path()),
        vec!["extracted".to_owned()],
        "a failed migration must leave no staging directory beside the destination"
    );
}

#[test]
fn migration_refuses_a_registry_or_category_file_that_is_not_schema_four() {
    let temporary = TemporaryDirectory::new("pkgre-rust-migrate-schema");
    let extraction = temporary.path().join("extracted");
    extract_fixture(FIXTURE, &extraction);
    let input = extraction.join("registry");
    let git_times = git_tag_times();
    let registry = input.join("main.toml");
    let category = input.join("categories/main/general.toml");
    let registry_bytes = fs::read(&registry).unwrap();
    let category_bytes = fs::read(&category).unwrap();

    fs::write(&category, replace_schema(&category_bytes, 3)).unwrap();
    let output = temporary.path().join("from-old-category");
    let error = migrate_v4_to_v5(&input, &output, &git_times).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("category file")
            && message.contains("general.toml")
            && message.contains("must use schema 4, found 3"),
        "{message}"
    );
    assert!(
        !output.exists(),
        "a refused input must leave no destination"
    );

    fs::write(&category, &category_bytes).unwrap();
    fs::write(&registry, replace_schema(&registry_bytes, 5)).unwrap();
    let output = temporary.path().join("from-new-registry");
    let error = migrate_v4_to_v5(&input, &output, &git_times).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("human registry")
            && message.contains("main.toml")
            && message.contains("must use schema 4, found 5"),
        "{message}"
    );
    assert!(
        !output.exists(),
        "a refused input must leave no destination"
    );

    fs::write(&registry, &registry_bytes).unwrap();
    let output = temporary.path().join("restored");
    migrate_v4_to_v5(&input, &output, &git_times).unwrap();
    assert!(output.join("main.toml").is_file());
}

#[test]
fn migrate_cli_shows_the_accepted_git_tag_time_form() {
    let temporary = TemporaryDirectory::new("pkgre-rust-migrate-cli");
    let input = temporary.path().join("input");
    let output = temporary.path().join("output");
    fs::create_dir(&input).unwrap();
    let accepted = "--git-tag-time=<registry>/<name>@<tag>=<timestamp>";

    let usage = run_cli(&["migrate-v4-to-v5"]);
    assert!(
        usage.contains(accepted),
        "the usage text must show the accepted form: {usage}"
    );
    assert!(
        !usage.contains("--git-tag-time <registry>"),
        "the usage text must not show the separate form: {usage}"
    );

    let separate = run_cli(&[
        "migrate-v4-to-v5",
        path_text(&input),
        path_text(&output),
        "--git-tag-time",
        "main/example@v1.0.0=2026-08-22T17:57:02Z",
    ]);
    assert!(
        separate.contains("unknown argument"),
        "the separate form must be rejected: {separate}"
    );
    assert!(
        separate.contains(accepted),
        "the rejection must repeat the accepted form: {separate}"
    );

    let malformed = run_cli(&[
        "migrate-v4-to-v5",
        path_text(&input),
        path_text(&output),
        "--git-tag-time=main/example",
    ]);
    assert!(
        malformed.contains("<registry>/<name>@<tag>=<canonical-timestamp>"),
        "the value error must show the accepted form: {malformed}"
    );
    assert!(
        !output.exists(),
        "a rejected argument must leave no destination"
    );
}

/// Runs `pkgre-rust` with `arguments` and returns its combined output.
fn run_cli(arguments: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_pkgre-rust"))
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "the command must fail: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn path_text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Returns one directory's entry names in sorted order.
fn entry_names(directory: &Path) -> Vec<String> {
    let mut names = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// Replaces the leading `schema = 4` declaration of one fixture file.
fn replace_schema(bytes: &[u8], schema: u32) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let replaced = text.replacen("schema = 4", &format!("schema = {schema}"), 1);
    assert_ne!(text, replaced, "the fixture must declare schema 4");
    replaced.into_bytes()
}

fn extract_fixture(fixture: &[u8], destination: &Path) {
    let temporary = TemporaryDirectory::new("pkgre-rust-migrate-extract");
    let archive = temporary.path().join("catalog.tar.gz");
    fs::write(&archive, fixture).unwrap();
    fs::create_dir(destination).unwrap();
    let status = Command::new("tar")
        .arg("--extract")
        .arg("--gzip")
        .arg("--file")
        .arg(&archive)
        .arg("--directory")
        .arg(destination)
        .status()
        .unwrap();
    assert!(status.success());
}

fn trees_equal(left: &Path, right: &Path) -> bool {
    fn walk(left: &Path, right: &Path) -> Option<bool> {
        let left_entries = fs::read_dir(left).ok()?;
        let mut left_names = left_entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        left_names.sort();
        let right_entries = fs::read_dir(right).ok()?;
        let mut right_names = right_entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        right_names.sort();
        if left_names != right_names {
            return Some(false);
        }
        for name in left_names {
            let left_child = left.join(&name);
            let right_child = right.join(&name);
            if left_child.is_dir() {
                walk(&left_child, &right_child)?;
            } else if fs::read(&left_child).ok()? != fs::read(&right_child).ok()? {
                return Some(false);
            }
        }
        Some(true)
    }
    walk(left, right).unwrap_or(false)
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Self {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{sequence}", std::process::id()));
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
        let _ = fs::remove_dir_all(&self.path);
    }
}
