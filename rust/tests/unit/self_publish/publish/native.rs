//! The unchanged native archive through the complete routine, with fake services.

use super::*;

fn setup(parent: &Path) -> Setup {
    Setup::with_variant(
        parent,
        &[],
        Variant {
            native: true,
            sibling: Sibling::Inherited,
            ..Variant::default()
        },
    )
}

#[test]
fn native_missing_published_and_yanked_states_keep_one_archive() {
    let temporary = fixtures::Temp::new("native-states");
    let setup = setup(temporary.path());
    for name in [LIB, BIN] {
        let entry = setup.fixture.entry(name);
        assert_eq!(entry.name, entry.crates_io_name);
        assert_eq!(entry.crate_sha256, entry.pkgre_crate_sha256);
        assert_eq!(
            setup.fixture.derived[name],
            setup.fixture.candidate.curated[name]
        );
    }
    assert_eq!(setup.dry_run().unwrap().would_upload, 2);
    assert_eq!(setup.tokens.reads(), 0);
    assert_eq!(setup.execute(true).unwrap().uploaded, 2);
    assert_eq!(setup.uploader.uploads(), [LIB, BIN]);
    // A native tag is not rewritten, so the upload must not allow a dirty
    // checkout.
    assert_eq!(setup.uploader.allow_dirty(), [false, false]);
    let published = setup.execute(true).unwrap();
    assert_eq!(published.published, 2);
    assert_eq!(setup.tokens.reads(), 1);
    setup.crates_io.yank(LIB, &setup.fixture.version(LIB));
    assert_eq!(setup.dry_run().unwrap().yanked, 1);
}

#[test]
fn native_partial_upload_resumes_in_dependency_order() {
    let temporary = fixtures::Temp::new("native-resume");
    let setup = setup(temporary.path());
    setup.uploader.fail_after(1);
    assert!(refusal(setup.execute(true)).contains("fake uploader fails"));
    assert_eq!(setup.uploader.uploads(), [LIB]);
    setup.uploader.reset();
    setup.uploader.fail_after(usize::MAX);
    let result = setup.execute(true).unwrap();
    assert_eq!(result.published, 1);
    assert_eq!(result.uploaded, 1);
    assert_eq!(setup.uploader.uploads(), [BIN]);
}

#[test]
fn native_different_checksum_stops_before_the_token() {
    let temporary = fixtures::Temp::new("native-different");
    let setup = setup(temporary.path());
    setup
        .crates_io
        .add_version(LIB, setup.fixture.version(LIB), "f".repeat(64));
    let error = refusal(setup.execute(true));
    assert!(error.contains(&"f".repeat(64)), "{error}");
    assert!(
        error.contains(&setup.fixture.entry(LIB).crate_sha256),
        "{error}"
    );
    assert_eq!(setup.tokens.reads(), 0);
    assert!(setup.uploader.uploads().is_empty());
}

#[test]
fn native_abandoned_version_is_not_uploaded() {
    let temporary = fixtures::Temp::new("native-abandoned");
    let setup = Setup::with_variant(
        temporary.path(),
        &[(BIN, fixtures::VERSION, "not released")],
        Variant {
            native: true,
            ..Variant::default()
        },
    );
    let result = setup.execute(true).unwrap();
    assert_eq!(result.abandoned, 1);
    assert_eq!(setup.uploader.uploads(), [LIB]);
}

#[test]
fn native_dirty_checkout_after_verification_is_refused_by_cargo() {
    let temporary = fixtures::Temp::new("native-dirty");
    let setup = setup(temporary.path());
    let error = refusal(run(
        &setup.fixture.candidate.root,
        &fixtures::tag(),
        true,
        None,
        &setup.services(changed_after_verification),
    ));
    assert!(error.contains("step 6"), "{error}");
    assert!(error.contains("not yet committed"), "{error}");
    assert_eq!(setup.tokens.reads(), 0);
    assert!(setup.uploader.uploads().is_empty());
}

#[test]
fn native_an_upload_that_changes_a_dependent_stops_before_the_dependent() {
    let temporary = fixtures::Temp::new("native-changed-dependent");
    let setup = setup(temporary.path());
    let library = setup.fixture.entry(LIB);
    let binary = setup.fixture.entry(BIN);
    setup
        .uploader
        .change_dependent_after(&library.crates_io_name);
    let error = refusal(setup.execute(true));
    assert!(
        error.contains(&format!(
            "check the package that cargo publish would upload for crate {} {}",
            binary.name, binary.version
        )),
        "{error}"
    );
    assert_eq!(
        setup.uploader.uploads().as_slice(),
        std::slice::from_ref(&library.crates_io_name),
        "the dependent is not uploaded"
    );
    assert_eq!(setup.tokens.reads(), 1, "one read, before the uploads");
}

#[test]
fn native_verified_checksum_must_match_the_record() {
    let temporary = fixtures::Temp::new("native-verification");
    let setup = setup(temporary.path());
    let error = refusal(run(
        &setup.fixture.candidate.root,
        &fixtures::tag(),
        true,
        None,
        &setup.services(unrecorded_verification),
    ));
    assert!(error.contains("step 5"), "{error}");
    assert_eq!(setup.tokens.reads(), 0);
}
