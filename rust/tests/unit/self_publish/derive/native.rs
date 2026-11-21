//! Native contract and retained-byte checks on local fixtures.

use super::*;

fn variant() -> Variant {
    Variant {
        native: true,
        sibling: Sibling::Inherited,
        ..Variant::default()
    }
}

#[test]
fn a_native_derivation_requires_the_retained_bytes() {
    let temporary = fixtures::Temp::new("native-retained");
    let (source, release, mut catalog) = fixture(temporary.path(), variant());
    let state = RepositoryState::load(&catalog.root).unwrap();
    catalog.curated.get_mut("example-lib").unwrap().push(0);
    let error = derive_from_catalog(&release, &state, &catalog.curated, &source.root).unwrap_err();
    assert!(
        format!("{error:#}").contains("differs byte for byte"),
        "{error:#}"
    );
}

#[test]
fn native_lock_rule_checks_removed_checksums_and_non_native_identities() {
    let temporary = fixtures::Temp::new("native-lock-rule");
    let (source, release, catalog) = fixture(temporary.path(), variant());
    for change in ["removed", "checksum", "non-native"] {
        let mut state = RepositoryState::load(&catalog.root).unwrap();
        if change == "non-native" {
            state
                .catalog
                .identities
                .iter_mut()
                .find(|identity| identity.name == "earlier-lib")
                .unwrap()
                .release
                .as_mut()
                .unwrap()
                .git = fixtures::FORK.to_owned();
        } else {
            let identity = state
                .catalog
                .identities
                .iter_mut()
                .find(|identity| identity.name == "mirrored-dev")
                .unwrap();
            if change == "removed" {
                identity.removed = true;
            } else {
                identity.crate_sha256 = "a".repeat(64);
            }
        }
        let error =
            derive_from_catalog(&release, &state, &catalog.curated, &source.root).unwrap_err();
        assert!(
            format!("{error:#}").contains("native lock package"),
            "{error:#}"
        );
    }
}

/// Validate a changed fixture directly, so an invalid manifest need not first
/// be packaged into a catalog archive merely to exercise its refusal.
fn check_changed(change: impl FnOnce(&Path)) -> String {
    let temporary = fixtures::Temp::new("native-contract");
    let (source, release, catalog) = fixture(temporary.path(), variant());
    let state = RepositoryState::load(&catalog.root).unwrap();
    change(&release.root);
    let cargo = crate::package::pinned_cargo(&fixtures::CARGO_VERSION.parse().unwrap()).unwrap();
    let home = temporary.path().join("validation-home");
    super::super::cargo::prepare_cargo_home(
        &home,
        super::super::cargo::RegistrySources::Local(source.root),
    )
    .unwrap();
    let environment = ChildEnvironment::capture(&home, &cargo).unwrap();
    let result = (|| -> Result<()> {
        let workspace = super::super::workspace::Workspace::load(
            &cargo,
            &environment,
            temporary.path(),
            &release.root,
            true,
        )?;
        let lock = LockIndex::load(&release.root.join("Cargo.lock"))?;
        super::super::native::validate(
            &workspace,
            &lock,
            &state.catalog,
            &state.self_publish.unwrap().config,
            &environment,
        )?;
        Ok(())
    })();
    format!("{:#}", result.unwrap_err())
}

fn replace(root: &Path, file: &str, old: &str, new: &str) {
    let path = root.join(file);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains(old));
    fs::write(path, text.replace(old, new)).unwrap();
}

#[test]
fn native_contract_refuses_publish_lists_caret_siblings_and_cycles() {
    let cases = [
        (
            "lib/Cargo.toml",
            "name = \"example-lib\"",
            "name = \"example-lib\"\npublish = [\"crates-io\"]",
            "publish list",
        ),
        (
            "Cargo.toml",
            "version = \"=1.0.0\"",
            "version = \"1.0.0\"",
            "must require exactly",
        ),
        (
            "lib/Cargo.toml",
            "[dev-dependencies]",
            "[dev-dependencies]\nexample-bin = { path = \"../bin\", version = \"=1.0.0\" }",
            "dependency cycle",
        ),
        (
            "Cargo.lock",
            "version = 4",
            "version = 2",
            "version 3 or later",
        ),
        ("Cargo.lock", "version = 4\n", "", "version 3 or later"),
        (
            "Cargo.toml",
            "[workspace]",
            "[patch.crates-io]\n\n[workspace]",
            "[patch] or [replace]",
        ),
    ];
    for (path, old, new, expected) in cases {
        let error = check_changed(|root| replace(root, path, old, new));
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn native_contract_refuses_a_lock_not_committed_with_the_tag() {
    let error = check_changed(|root| {
        fixtures::git(root, &["rm", "--cached", "Cargo.lock"]);
    });
    assert!(error.contains("must commit"), "{error}");
}

#[test]
fn native_verified_build_uses_an_independent_clean_copy() {
    let temporary = fixtures::Temp::new("native-copy");
    let (source, release, catalog) = fixture(temporary.path(), variant());
    let state = RepositoryState::load(&catalog.root).unwrap();
    let facts = state
        .catalog
        .identity("example-lib", &fixtures::VERSION.parse().unwrap())
        .unwrap()
        .release
        .as_ref()
        .unwrap();
    let released = RELEASED
        .iter()
        .map(|name| ReleasedCrate {
            name: (*name).to_owned(),
            version: release.version(name),
            archive: catalog.curated[*name].clone(),
            crate_sha256: sha256_bytes(&catalog.curated[*name]),
        })
        .collect::<Vec<_>>();
    let config = &state.self_publish.as_ref().unwrap().config;
    let derived = derive_release_in(
        facts,
        &released,
        &state.catalog,
        config,
        &state.self_publish.as_ref().unwrap().lock,
        Sources::local(&release.root, Some(&source.root), temporary.path()),
    )
    .unwrap();
    let members = derived
        .packages
        .iter()
        .map(|package| (package.entry.name.clone(), package.entry.version.clone()))
        .collect::<Vec<_>>();
    let archives = derived.workspace.verified_archives(&members).unwrap();
    assert_eq!(archives, catalog.curated);
    let copy = derived.workspace.root().join("verified-checkout");
    assert!(copy.join(".git/objects").is_dir());
    assert_ne!(copy, derived.workspace.manifest().parent().unwrap());
    fs::write(copy.join("bin/src/main.rs"), "not Rust").unwrap();
    let upload = derived.workspace.upload_environment().unwrap();
    assert_eq!(
        derived
            .workspace
            .publish_archives(&upload, &members)
            .unwrap(),
        archives
    );
}
