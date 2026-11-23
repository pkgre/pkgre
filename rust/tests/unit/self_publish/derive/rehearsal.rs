//! The rehearsal of a crates.io-native release through the production paths.
//!
//! The test needs `PKGRE_REHEARSAL_CATALOG`, a read-only checkout of the catalog
//! repository, and reads it without writing into it. By default it builds a
//! neutral repository of its own; `PKGRE_NATIVE_REHEARSAL_REPOSITORY`,
//! `PKGRE_NATIVE_REHEARSAL_GIT` and `PKGRE_NATIVE_REHEARSAL_TAG` rehearse a
//! prepared copy of a real repository instead, and
//! `PKGRE_NATIVE_REHEARSAL_SKIP_VERIFY=1` skips step 5's build, since the code
//! of a third-party repository must not run outside a sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use semver::Version;

use super::fixtures;
use super::{ReleasedCrate, Sources, derive_release_in, verified_packages};
use crate::artifact::sha256_bytes;
use crate::package::{FileTagRequest, GitTagMaterialization, NativeCatalog, PublishedPackage};
use crate::schema::{Approval, Catalog, PackageState, Source};
use crate::self_publish::catalog::{CatalogIdentity, CatalogSnapshot, GitRelease};
use crate::self_publish::config::CratesIoConfig;
use crate::self_publish::isolation::ChildEnvironment;
use crate::self_publish::lock::{CRATES_IO_LOCK_SCHEMA, CratesIoLock};
use crate::self_publish::state::LOCK_FILE;

/// The version of the default rehearsal tag.
const VERSION: &str = "0.1.0";

/// The declared repository of the default rehearsal.
const REPOSITORY: &str = "https://github.com/example/workspace";

/// The tag of the default rehearsal.
const TAG: &str = "v0.1.0";

/// One tag that the rehearsal packages.
struct Rehearsal {
    /// The local checkout holding the tag.
    repository: PathBuf,
    /// The credential-free HTTPS URL the declarations name.
    git: String,
    /// The tag.
    tag: String,
    /// The tag's prefix, up to and including the version marker.
    prefix: String,
}

/// Returns the variable's value, when it is set and not empty.
fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Splits a tag into its prefix and its version.
fn split_tag(tag: &str) -> Result<(String, Version)> {
    let (head, last) = tag.rsplit_once('/').unwrap_or(("", tag));
    let version = Version::parse(last.strip_prefix('v').unwrap_or(last))
        .with_context(|| format!("parse the version of tag {tag:?}"))?;
    let prefix = if head.is_empty() {
        "v".to_owned()
    } else if last.starts_with('v') {
        format!("{head}/v")
    } else {
        format!("{head}/")
    };
    Ok((prefix, version))
}

/// Writes one file of the neutral repository.
fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create a rehearsal directory");
    }
    fs::write(path, text).expect("write a rehearsal file");
}

/// Prepares the pinned Cargo and an isolated Cargo home that uses crates.io.
fn crates_io_environment(root: &Path, label: &str) -> Result<(PathBuf, ChildEnvironment, PathBuf)> {
    let cargo = crate::package::pinned_cargo(
        &crate::policy::CARGO_VERSION
            .parse()
            .expect("parse the pinned version"),
    )?;
    let home = root.join(format!("cargo-home-{label}"));
    super::super::cargo::prepare_cargo_home(&home, super::super::cargo::RegistrySources::CratesIo)?;
    let environment = ChildEnvironment::capture(&home, &cargo)?;
    let work = root.join(format!("work-{label}"));
    fs::create_dir_all(&work).context("create the rehearsal's working directory")?;
    Ok((cargo, environment, work))
}

/// Runs one command and requires success.
fn run(command: &mut std::process::Command, description: &str) {
    let output = command.output().expect("run a rehearsal command");
    assert!(
        output.status.success(),
        "{description} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Returns a mirror that the catalog retains, with no dependencies of its own,
/// so that the tag's committed lock holds besides the tag's own crates.
fn choose_mirror(catalog_root: &Path, catalog: &Catalog) -> Result<(String, Version)> {
    for approval in &catalog.approvals {
        if approval.state != PackageState::Active
            || approval.registry != "main"
            || !matches!(approval.source, Source::CratesIo)
            || approval.name.starts_with("rehearsal-")
        {
            continue;
        }
        let row = catalog_root
            .join("objects/rows")
            .join(format!("{}.json", approval.index_record_sha256));
        let Ok(bytes) = fs::read(&row) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if value
            .get("deps")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            return Ok((approval.name.clone(), approval.version.clone()));
        }
    }
    bail!("the catalog retains no crates.io mirror without dependencies to rehearse with")
}

/// Builds the neutral repository, or checks out a prepared one, and returns the
/// tag that the rehearsal packages.
#[allow(clippy::too_many_lines)]
fn prepare(temporary: &Path, catalog_root: &Path, catalog: &Catalog) -> Result<Rehearsal> {
    if let Some(repository) = optional("PKGRE_NATIVE_REHEARSAL_REPOSITORY") {
        let git = optional("PKGRE_NATIVE_REHEARSAL_GIT").context(
            "set PKGRE_NATIVE_REHEARSAL_GIT to the declared URL of the prepared repository",
        )?;
        let tag = optional("PKGRE_NATIVE_REHEARSAL_TAG")
            .context("set PKGRE_NATIVE_REHEARSAL_TAG to the prepared repository's release tag")?;
        let (prefix, _) = split_tag(&tag)?;
        // The prepared clone is read-only to this test; the tag is read from a
        // checkout of its own, at exactly the commit the tag names.
        let checkout = temporary.join("tag-checkout");
        fixtures::git(
            temporary,
            &[
                "clone",
                "--quiet",
                repository.as_str(),
                checkout.to_str().expect("a UTF-8 checkout path"),
            ],
        );
        fixtures::git(&checkout, &["checkout", "--quiet", "--detach", &tag]);
        return Ok(Rehearsal {
            repository: checkout,
            git,
            tag,
            prefix,
        });
    }
    let repository = temporary.join("repository");
    fixtures::git(
        temporary,
        &[
            "init",
            "--quiet",
            repository.to_str().expect("a UTF-8 repository path"),
        ],
    );
    let (mirror, mirror_version) = choose_mirror(catalog_root, catalog)?;
    write(
        &repository,
        "Cargo.toml",
        "[workspace]\nmembers = [\"lib\", \"bin\", \"data\"]\nresolver = \"2\"\n",
    );
    write(
        &repository,
        "lib/Cargo.toml",
        &format!(
            "[package]\nname = \"rehearsal-lib\"\nversion = {VERSION:?}\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"the library of a packaging rehearsal\"\n\n[dependencies]\n{mirror} = \"={mirror_version}\"\n"
        ),
    );
    write(
        &repository,
        "lib/src/lib.rs",
        "pub fn answer() -> u32 { 42 }\n",
    );
    write(
        &repository,
        "bin/Cargo.toml",
        &format!(
            "[package]\nname = \"rehearsal-bin\"\nversion = {VERSION:?}\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"the binary of a packaging rehearsal\"\n\n[dependencies]\nrehearsal-lib = {{ path = \"../lib\", version = \"={VERSION}\" }}\n"
        ),
    );
    write(
        &repository,
        "bin/src/main.rs",
        "fn main() { println!(\"{}\", rehearsal_lib::answer()); }\n",
    );
    write(
        &repository,
        "data/Cargo.toml",
        &format!(
            "[package]\nname = \"rehearsal-data\"\nversion = {VERSION:?}\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"a member that is not released\"\npublish = false\n"
        ),
    );
    write(
        &repository,
        "data/src/lib.rs",
        "pub const DATA: [u8; 1] = [0];\n",
    );
    let (cargo, environment, work) = crates_io_environment(temporary, "tag")?;
    let mut command = std::process::Command::new(&cargo);
    environment.apply(&mut command);
    command.current_dir(&work).args([
        "generate-lockfile",
        "--manifest-path",
        repository
            .join("Cargo.toml")
            .to_str()
            .expect("a UTF-8 manifest path"),
    ]);
    run(&mut command, "cargo generate-lockfile");
    fixtures::git(&repository, &["add", "."]);
    fixtures::git(
        &repository,
        &[
            "commit",
            "--quiet",
            "-m",
            "the tag of a packaging rehearsal",
        ],
    );
    fixtures::git(&repository, &["tag", "-a", TAG, "-m", "rehearsal v0.1.0"]);
    println!(
        "rehearsal: tag {TAG} of {REPOSITORY}, external dependency {mirror} {mirror_version} from the catalog"
    );
    Ok(Rehearsal {
        repository,
        git: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
        prefix: "v".to_owned(),
    })
}

/// Declares the rehearsal's repository crates.io-native.
fn rehearsal_config(git: &str, prefix: &str) -> CratesIoConfig {
    CratesIoConfig::parse(
        format!(
            "schema = 1\n\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = {git:?}\ntag-prefix = {prefix:?}\nmanifests = \"crates-io\"\n"
        )
        .as_bytes(),
        Path::new("crates-io.toml"),
    )
    .expect("parse the rehearsal's self-publishing config")
}

/// Returns the released crates of the tag, those whose `publish` is absent or
/// `true`, read from its workspace.
fn released_members(repository: &Path, root: &Path) -> Result<BTreeSet<String>> {
    let (cargo, environment, work) = crates_io_environment(root, "members")?;
    let workspace =
        super::super::workspace::Workspace::load(&cargo, &environment, &work, repository, true)?;
    Ok(workspace
        .publishable_members()
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Returns the entry that `lock` would record for one materialization.
fn approval(
    materialization: &GitTagMaterialization,
    rehearsal: &Rehearsal,
    cargo_version: &Version,
) -> Approval {
    Approval {
        registry: "main".to_owned(),
        category: "main/general".parse().expect("a category"),
        name: materialization.name.clone(),
        version: materialization.version.clone(),
        archive_sha256: materialization.archive_sha256.clone(),
        index_record_sha256: materialization.source_row_sha256.clone(),
        index_row_sha256: materialization.source_row_sha256.clone(),
        admission_sha256: None,
        admitted_at: crate::update::time::UtcTimestamp::parse("2026-01-01T00:00:00Z")
            .expect("a timestamp"),
        state: PackageState::Active,
        source: Source::GitTag {
            repository: rehearsal.git.clone(),
            tag: rehearsal.tag.clone(),
            tag_oid: materialization.tag_oid.clone(),
            commit: materialization.commit.clone(),
            package: materialization.name.clone(),
            subdir: materialization.path.clone(),
            cargo_version: cargo_version.clone(),
        },
        declared_in: PathBuf::from("main.lock"),
    }
}

/// Loads the entries of the catalog repository, if it records any.
fn earlier_entries(catalog_root: &Path) -> Result<CratesIoLock> {
    let path = catalog_root.join("self-publish").join(LOCK_FILE);
    match fs::read(&path) {
        Ok(bytes) => CratesIoLock::parse_canonical(&bytes, &path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CratesIoLock {
            schema: CRATES_IO_LOCK_SCHEMA,
            packages: Vec::new(),
        }),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Writes a candidate catalog's `objects` beside the real rows, with the rows
/// and archives of the tag's new identities, as the release pull request that
/// adds them would. The real catalog is only read.
fn candidate_objects(
    catalog_root: &Path,
    root: &Path,
    materializations: &BTreeMap<String, GitTagMaterialization>,
) -> Result<PathBuf> {
    let candidate = root.join("candidate-catalog");
    let rows = candidate.join("objects/rows");
    let crates = candidate.join("objects/crates");
    fs::create_dir_all(&rows).context("create the candidate rows")?;
    fs::create_dir_all(&crates).context("create the candidate archives")?;
    for entry in fs::read_dir(catalog_root.join("objects/rows"))
        .with_context(|| format!("read {}", catalog_root.join("objects/rows").display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::copy(entry.path(), rows.join(entry.file_name()))?;
        }
    }
    for materialization in materializations.values() {
        fs::write(
            rows.join(format!("{}.json", materialization.source_row_sha256)),
            &materialization.source_row_bytes,
        )
        .context("write the candidate's source row")?;
        fs::write(
            crates.join(format!("{}.crate", materialization.archive_sha256)),
            &materialization.archive_bytes,
        )
        .context("write the candidate's archive")?;
    }
    Ok(candidate)
}

#[test]
#[ignore = "needs the network and PKGRE_REHEARSAL_CATALOG"]
fn live_native_rehearsal_runs_lock_the_reproduction_and_the_routine() {
    crate::self_publish::sandbox::run_test_body(
        "self_publish::derive::tests::rehearsal::live_native_rehearsal_runs_lock_the_reproduction_and_the_routine_body",
        &[
            "PKGRE_REHEARSAL_CATALOG",
            "PKGRE_NATIVE_REHEARSAL_SKIP_VERIFY",
        ],
    )
    .expect("the rehearsal runs inside a run sandbox");
}

#[test]
#[allow(clippy::too_many_lines)]
fn live_native_rehearsal_runs_lock_the_reproduction_and_the_routine_body() {
    if std::env::var_os(crate::self_publish::sandbox::TEST_BODY_VARIABLE).is_none() {
        return;
    }
    let given = PathBuf::from(
        std::env::var_os("PKGRE_REHEARSAL_CATALOG")
            .expect("set PKGRE_REHEARSAL_CATALOG to a checkout of the catalog repository"),
    );
    // The variable names the repository that holds `registry/`, and a caller
    // may name the catalog's own directory too.
    let (repository_root, catalog_root) = if given.join("main.toml").is_file() {
        (
            given
                .parent()
                .expect("the catalog directory has a parent repository")
                .to_path_buf(),
            given,
        )
    } else {
        (given.clone(), given.join("registry"))
    };
    let skip_verify = std::env::var("PKGRE_NATIVE_REHEARSAL_SKIP_VERIFY").is_ok_and(|v| v == "1");
    let temporary = fixtures::Temp::new("native-rehearsal");
    let catalog = Catalog::load(&catalog_root).expect("load the catalog");
    let rehearsal = prepare(temporary.path(), &catalog_root, &catalog).expect("prepare the tag");
    let config = rehearsal_config(&rehearsal.git, &rehearsal.prefix);
    let cargo_version = Version::parse(crate::policy::CARGO_VERSION).expect("a Cargo version");
    let repositories = crate::self_publish::NativeRepositories::from_config(config.clone());
    let native = repositories
        .catalog(
            &catalog_root,
            &catalog.approvals,
            "main",
            &rehearsal.git,
            &rehearsal.tag,
        )
        .expect("the declaration makes the rehearsal's repository crates.io-native");
    let released = released_members(&rehearsal.repository, temporary.path())
        .expect("read the tag's released crates");
    let names = released.iter().cloned().collect::<Vec<_>>();
    let packages = names.iter().map(String::as_str).collect::<Vec<_>>();
    let published = packages
        .iter()
        .map(|name| PublishedPackage {
            name,
            locked_sha256: None,
        })
        .collect::<Vec<_>>();
    let registry_index = crate::policy::canonical_registry_index("main");
    let fetch_repository = rehearsal
        .repository
        .to_str()
        .expect("a UTF-8 repository path");
    // 1. `lock` packages the whole tag in one run, offline, from the catalog.
    let locked = crate::package::resolve_git_tag_group_from_file(&FileTagRequest {
        root: temporary.path(),
        repository: &rehearsal.git,
        tag: &rehearsal.tag,
        packages: &packages,
        published: Some(&published),
        cargo_version: &cargo_version,
        fetch_repository,
        registry_index: &registry_index,
        allow_retired_registries: false,
        native: Some(native),
    })
    .expect("package the tag as lock does");
    let locked = locked
        .into_iter()
        .map(|materialization| (materialization.name.clone(), materialization))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        locked.keys().cloned().collect::<Vec<_>>(),
        names,
        "lock packages exactly the tag's released crates"
    );
    // 2. `reproduce-git-tags` reproduces every identity of the tag as one group.
    let approvals = locked
        .values()
        .map(|materialization| approval(materialization, &rehearsal, &cargo_version))
        .collect::<Vec<_>>();
    let reproduced_approvals = approvals.iter().collect::<Vec<_>>();
    let mut candidate = catalog.approvals.clone();
    candidate.extend(approvals.iter().cloned());
    let candidate_native = repositories
        .catalog(
            &catalog_root,
            &candidate,
            "main",
            &rehearsal.git,
            &rehearsal.tag,
        )
        .expect("the candidate declares the tag crates.io-native");
    let candidate_root =
        candidate_objects(&catalog_root, temporary.path(), &locked).expect("write the candidate");
    let reproduced = crate::package::reproduce_approved_git_group_from_file_in(
        temporary.path(),
        &candidate,
        &reproduced_approvals,
        Some(NativeCatalog {
            root: &candidate_root,
            identities: candidate_native.identities.clone(),
            locked: candidate_native.locked.clone(),
        }),
        fetch_repository,
        &registry_index,
    )
    .expect("reproduce the tag as reproduce-git-tags does");
    for materialization in &reproduced {
        let original = &locked[&materialization.name];
        assert_eq!(
            materialization.archive_bytes, original.archive_bytes,
            "the reproduction of {} {} differs from lock's archive",
            materialization.name, materialization.version
        );
        assert_eq!(
            materialization.source_row_sha256, original.source_row_sha256,
            "the reproduction of {} {} differs from lock's source row",
            materialization.name, materialization.version
        );
    }
    // 3. The derivation, against live crates.io.
    let mut snapshot = CatalogSnapshot::load(&repository_root).expect("load the catalog snapshot");
    let first = locked
        .values()
        .next()
        .expect("the tag releases at least one crate");
    let facts = GitRelease {
        git: rehearsal.git.clone(),
        tag: rehearsal.tag.clone(),
        tag_oid: first.tag_oid.clone(),
        commit: first.commit.clone(),
        cargo_version: cargo_version.clone(),
    };
    for materialization in locked.values() {
        snapshot.identities.push(CatalogIdentity {
            name: materialization.name.clone(),
            version: materialization.version.clone(),
            crate_sha256: materialization.archive_sha256.clone(),
            removed: false,
            release: Some(facts.clone()),
            dependencies: Vec::new(),
        });
        snapshot.publish_names.push(materialization.name.clone());
        snapshot
            .publish_declarations
            .push((materialization.name.clone(), rehearsal.git.clone()));
    }
    let earlier = earlier_entries(&repository_root).expect("read the catalog's entries");
    let released_crates = locked
        .values()
        .map(|materialization| ReleasedCrate {
            name: materialization.name.clone(),
            version: materialization.version.clone(),
            crate_sha256: materialization.archive_sha256.clone(),
            archive: materialization.archive_bytes.clone(),
        })
        .collect::<Vec<_>>();
    let derived = derive_release_in(
        &facts,
        &released_crates,
        &snapshot,
        &config,
        &earlier,
        Sources::local(&rehearsal.repository, None, temporary.path()),
    )
    .expect("derive the tag against live crates.io");
    assert_eq!(derived.packages.len(), released.len());
    for package in &derived.packages {
        let original = &locked[&package.entry.name];
        assert_eq!(
            package.archive, original.archive_bytes,
            "the derivation's group archive of {} {} differs from lock's archive",
            package.entry.name, package.entry.version
        );
        assert_eq!(
            package.entry.crates_io_name, package.entry.name,
            "a native crate's crates.io name is its package name"
        );
        assert_eq!(
            package.entry.crate_sha256, package.entry.pkgre_crate_sha256,
            "a native crate has one archive for both registries"
        );
        assert_eq!(package.entry.crate_sha256, original.archive_sha256);
    }
    // 4. Step 5, unless a prepared repository's code must not be built here.
    let members = derived
        .packages
        .iter()
        .map(|package| {
            (
                package.entry.crates_io_name.clone(),
                package.entry.version.clone(),
            )
        })
        .collect::<Vec<_>>();
    let verified = if skip_verify {
        println!("rehearsal: step 5 skipped, PKGRE_NATIVE_REHEARSAL_SKIP_VERIFY=1");
        None
    } else {
        Some(
            derived
                .workspace
                .verified_archives(&verified_packages(&members), super::Runner::Sandbox)
                .expect("verify the packages against live crates.io"),
        )
    };
    // 5. Step 6, in the upload's own Cargo home.
    let upload_environment = derived
        .workspace
        .upload_environment()
        .expect("prepare the upload's Cargo home");
    let uploaded = derived
        .workspace
        .publish_archives(&upload_environment, &members)
        .expect("package the tag as cargo publish would");
    for package in &derived.packages {
        let name = &package.entry.crates_io_name;
        let step5 = verified.as_ref().map_or("skipped", |archives| {
            assert_eq!(
                sha256_bytes(&archives[name]),
                package.entry.crate_sha256,
                "the verified package of {} {} differs from the recorded one",
                package.entry.name,
                package.entry.version
            );
            "identical"
        });
        assert_eq!(
            sha256_bytes(&uploaded[name]),
            package.entry.crate_sha256,
            "the package that cargo publish would upload for {} {} differs from the recorded one",
            package.entry.name,
            package.entry.version
        );
        println!(
            "rehearsal: {} {} crates-io-name={name} crate-sha256={} pkgre-crate-sha256={} lock=identical reproduction=identical derivation=identical step5={step5} step6=identical",
            package.entry.name,
            package.entry.version,
            package.entry.crate_sha256,
            package.entry.pkgre_crate_sha256,
        );
    }
}
