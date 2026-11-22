//! Native contract and retained-byte checks on local fixtures.

use std::ffi::{OsStr, OsString};

use super::*;
use crate::self_publish::test_hooks;

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
        let lock = LockIndex::load(&workspace.root.join("Cargo.lock"))?;
        super::super::native::validate(
            &workspace,
            &lock,
            &state.catalog,
            &state.self_publish.unwrap().config,
            fixtures::REPOSITORY,
            &fixtures::tag(),
            &environment,
        )?;
        Ok(())
    })();
    format!("{:#}", result.unwrap_err())
}

/// Appends one entry to a fixture file.
fn append(root: &Path, file: &str, text: &str) {
    let path = root.join(file);
    let mut contents = fs::read_to_string(&path).unwrap();
    contents.push_str(text);
    fs::write(path, contents).unwrap();
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

/// Requires that each recorded packaging command carries `flag` exactly when
/// `expected` says so.
fn require_flag(recorded: &[&[OsString]], flag: &str, expected: bool) {
    assert!(!recorded.is_empty(), "no packaging command was recorded");
    for arguments in recorded {
        let carries = arguments
            .iter()
            .any(|argument| argument == OsStr::new(flag));
        assert_eq!(
            carries,
            expected,
            "{flag} in {:?}",
            arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
    }
}

/// Splits the recorded packaging commands into the derivation's group
/// packaging, which does not verify, and step 5's verified packaging.
fn by_build(recorded: Vec<Vec<OsString>>) -> (Vec<Vec<OsString>>, Vec<Vec<OsString>>) {
    recorded.into_iter().partition(|arguments| {
        arguments
            .iter()
            .any(|argument| argument == OsStr::new("--no-verify"))
    })
}

#[test]
fn the_tag_packaging_allows_a_dirty_checkout_only_for_a_rewritten_workspace() {
    for (label, variant, allow_dirty) in [
        ("native", variant(), false),
        ("rewritten", Variant::default(), true),
    ] {
        let temporary = fixtures::Temp::new(&format!("{label}-packaging-arguments"));
        let (source, release, catalog) = fixture(temporary.path(), variant);
        let state = RepositoryState::load(&catalog.root).unwrap();
        test_hooks::clear();
        let (derivation, _working) =
            derive_workspace(&release, &state, &catalog.curated, &source.root);
        let (group, verified) = by_build(test_hooks::take_arguments());
        assert_eq!(group.len(), 2, "{label}: the derivation packages twice");
        assert!(verified.is_empty(), "{label}: step 5 has not run yet");
        let commands = group.iter().map(Vec::as_slice).collect::<Vec<_>>();
        require_flag(&commands, "--allow-dirty", allow_dirty);
        let members = derived_members(&derivation);
        derivation
            .workspace
            .verified_archives(&members)
            .expect("verify the packaged release");
        let (group, verified) = by_build(test_hooks::take_arguments());
        assert!(group.is_empty(), "{label}: only step 5 packaged");
        assert_eq!(verified.len(), 1, "{label}: step 5 packages once");
        let commands = verified.iter().map(Vec::as_slice).collect::<Vec<_>>();
        require_flag(&commands, "--allow-dirty", allow_dirty);
    }
}

#[test]
fn native_contract_refuses_other_dependency_sources() {
    let cases: [(&str, &str, &str, &str); 5] = [
        (
            "lib/Cargo.toml",
            "mirrored-dep.workspace = true",
            "mirrored-dep.workspace = true\ngit-dep = { git = \"https://example.invalid/repository\" }",
            "unsupported source",
        ),
        (
            "lib/Cargo.toml",
            "mirrored-dep.workspace = true",
            "mirrored-dep = { version = \"0.3\", registry = \"pkgre\" }",
            "names a registry",
        ),
        (
            "lib/Cargo.toml",
            "mirrored-dep.workspace = true",
            "mirrored-dep = { version = \"0.3\", registry-index = \"https://example.invalid/index\" }",
            "names a registry",
        ),
        (
            "bin/Cargo.toml",
            "example-lib.workspace = true",
            "example-lib = { path = \"../lib\" }",
            "must require exactly",
        ),
        (
            "bin/Cargo.toml",
            "example-lib.workspace = true",
            "example-serve = { path = \"../serve\", version = \"=0.2.0\" }",
            "is not a released sibling",
        ),
    ];
    for (file, old, new, expected) in cases {
        let error = check_changed(|root| replace(root, file, old, new));
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn native_contract_refuses_a_sibling_in_another_directory() {
    let error = check_changed(|root| {
        fs::create_dir_all(root.join("other/src")).unwrap();
        fs::write(
            root.join("other/Cargo.toml"),
            "[package]\nname = \"example-lib\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("other/src/lib.rs"), "").unwrap();
        replace(
            root,
            "Cargo.toml",
            "members = [\"lib\", \"bin\", \"serve\"]",
            "members = [\"lib\", \"bin\", \"serve\"]\nexclude = [\"other\"]",
        );
        replace(
            root,
            "bin/Cargo.toml",
            "example-lib.workspace = true",
            "lib-alias = { package = \"example-lib\", path = \"../other\", version = \"=1.0.0\" }",
        );
    });
    assert!(error.contains("names another directory"), "{error}");
}

#[test]
fn native_lock_rule_refuses_other_sources_and_unknown_packages() {
    type Change = fn(&Path);
    let cases: [(&str, Change); 5] = [
        ("unsupported source", |root| {
            append(
                root,
                "Cargo.lock",
                "\n[[package]]\nname = \"ghost-git\"\nversion = \"1.0.0\"\nsource = \"git+https://example.invalid/repository#0000000000000000000000000000000000000000\"\n",
            );
        }),
        ("unsupported source", |root| {
            append(
                root,
                "Cargo.lock",
                "\n[[package]]\nname = \"ghost-registry\"\nversion = \"1.0.0\"\nsource = \"registry+https://example.invalid/index\"\n",
            );
        }),
        ("missing or different checksum", |root| {
            replace(root, "Cargo.lock", "\nchecksum = ", "\nchecksum-missing = ");
        }),
        ("is not an active mirror or native identity", |root| {
            append(
                root,
                "Cargo.lock",
                "\n[[package]]\nname = \"ghost-absent\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            );
        }),
        ("without a source is not a workspace member", |root| {
            append(
                root,
                "Cargo.lock",
                "\n[[package]]\nname = \"ghost-path\"\nversion = \"0.1.0\"\n",
            );
        }),
    ];
    for (expected, change) in cases {
        let error = check_changed(change);
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn native_lock_rule_refuses_an_identity_of_the_tag_itself() {
    let temporary = fixtures::Temp::new("native-own-tag");
    let (source, release, catalog) = fixture(temporary.path(), variant());
    let state = RepositoryState::load(&catalog.root).unwrap();
    let checksum = sha256_bytes(&catalog.curated["example-lib"]);
    replace(
        &release.root,
        "Cargo.lock",
        "name = \"example-lib\"\nversion = \"1.0.0\"\n",
        &format!(
            "name = \"example-lib\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = {checksum:?}\n"
        ),
    );
    let cargo = crate::package::pinned_cargo(&fixtures::CARGO_VERSION.parse().unwrap()).unwrap();
    let home = temporary.path().join("own-tag-home");
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
        let lock = LockIndex::load(&workspace.root.join("Cargo.lock"))?;
        super::super::native::validate(
            &workspace,
            &lock,
            &state.catalog,
            &state.self_publish.unwrap().config,
            fixtures::REPOSITORY,
            &fixtures::tag(),
            &environment,
        )?;
        Ok(())
    })();
    let error = format!("{:#}", result.unwrap_err());
    assert!(
        error.contains("is not an active mirror or native identity"),
        "{error}"
    );
}

#[test]
fn a_native_tag_reads_the_lock_of_the_workspace_root_below_the_checkout() {
    let temporary = fixtures::Temp::new("native-nested-lock");
    let checkout = temporary.path().join("checkout");
    let workspace = checkout.join("nested");
    fs::create_dir_all(&workspace).unwrap();
    // The decoy at the checkout root is a version-1 lock, which a native tag
    // refuses; the lock at the workspace root is the one that counts.
    fs::write(
        checkout.join("Cargo.lock"),
        "[[package]]\nname = \"decoy\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        workspace.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let native = LockIndex::load(&super::super::release_lock_path(
        true, &checkout, &workspace,
    ))
    .unwrap();
    assert_eq!(native.version, 4);
    let rewritten = LockIndex::load(&super::super::release_lock_path(
        false, &checkout, &workspace,
    ))
    .unwrap();
    assert_eq!(rewritten.version, 1);
}

/// Changes the fixture binary's source in `checkout`, as a process that a
/// package of the run started could.
fn change_source(checkout: &Path) {
    fs::write(
        checkout.join("bin/src/main.rs"),
        "fn main() { println!(\"changed during the run\"); }\n",
    )
    .expect("change the binary's source");
}

/// Returns the recorded error of a derivation that a hook changed at `point`.
fn changed_during(point: test_hooks::Point, temporary: &fixtures::Temp) -> String {
    let (source, release, catalog) = fixture(temporary.path(), variant());
    let state = RepositoryState::load(&catalog.root).unwrap();
    test_hooks::clear();
    test_hooks::on(point, change_source);
    let error = try_derive_workspace(&release, &state, &catalog.curated, &source.root)
        .err()
        .expect("a checkout changed during the derivation is refused");
    format!("{error:#}")
}

#[test]
fn the_native_derivation_refuses_a_checkout_changed_after_the_native_contract() {
    let temporary = fixtures::Temp::new("native-changed-after-contract");
    let error = changed_during(test_hooks::Point::AfterNativeContract, &temporary);
    assert!(error.contains("release tag checkout is dirty"), "{error}");
}

#[test]
fn the_native_derivation_refuses_a_checkout_changed_while_it_packaged() {
    let temporary = fixtures::Temp::new("native-changed-while-packaging");
    let error = changed_during(test_hooks::Point::AfterPackaging, &temporary);
    assert!(error.contains("release tag checkout is dirty"), "{error}");
}

#[test]
fn the_verified_packaging_refuses_a_checkout_changed_before_its_copy() {
    let temporary = fixtures::Temp::new("native-changed-before-copy");
    let (source, release, catalog) = fixture(temporary.path(), variant());
    let state = RepositoryState::load(&catalog.root).unwrap();
    test_hooks::clear();
    let (derivation, _working) = derive_workspace(&release, &state, &catalog.curated, &source.root);
    let members = derived_members(&derivation);
    test_hooks::on(test_hooks::Point::BeforeVerifiedCopy, change_source);
    let error = derivation
        .workspace
        .verified_archives(&members)
        .expect_err("a changed checkout is not copied for step 5");
    let error = format!("{error:#}");
    assert!(error.contains("release tag checkout is dirty"), "{error}");
    assert!(
        !derivation
            .workspace
            .root()
            .join("verified-checkout")
            .exists(),
        "the copy is made only from a clean checkout"
    );
}

#[test]
fn the_verified_packaging_refuses_a_changed_copy() {
    let temporary = fixtures::Temp::new("native-changed-copy");
    let (source, release, catalog) = fixture(temporary.path(), variant());
    let state = RepositoryState::load(&catalog.root).unwrap();
    test_hooks::clear();
    let (derivation, _working) = derive_workspace(&release, &state, &catalog.curated, &source.root);
    let members = derived_members(&derivation);
    test_hooks::on(test_hooks::Point::VerifiedCopy, change_source);
    let error = derivation
        .workspace
        .verified_archives(&members)
        .expect_err("a changed copy is not packaged");
    assert!(
        format!("{error:#}").contains("release tag checkout is dirty"),
        "{error:#}"
    );
}

#[test]
fn a_workspace_root_outside_the_checkout_is_refused() {
    let temporary = fixtures::Temp::new("native-workspace-root");
    let checkout = temporary.path().join("checkout");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(checkout.join("src")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        checkout.join("Cargo.toml"),
        "[package]\nname = \"example\"\nversion = \"1.0.0\"\nedition = \"2021\"\nworkspace = \"../outside\"\n",
    )
    .unwrap();
    fs::write(checkout.join("src/lib.rs"), "").unwrap();
    fs::write(
        outside.join("Cargo.toml"),
        "[workspace]\nmembers = [\"../checkout\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    fs::write(
        outside.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let cargo = crate::package::pinned_cargo(&fixtures::CARGO_VERSION.parse().unwrap()).unwrap();
    let home = temporary.path().join("workspace-root-home");
    super::super::cargo::prepare_cargo_home(&home, super::super::cargo::RegistrySources::CratesIo)
        .unwrap();
    let environment = ChildEnvironment::capture(&home, &cargo).unwrap();
    let work = temporary.path().join("work");
    fs::create_dir(&work).unwrap();
    let error =
        super::super::workspace::Workspace::load(&cargo, &environment, &work, &checkout, true)
            .err()
            .expect("the derivation refuses a workspace root outside the checkout");
    assert!(
        format!("{error:#}").contains("outside the release checkout"),
        "{error:#}"
    );
}
