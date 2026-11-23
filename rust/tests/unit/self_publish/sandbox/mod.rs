//! Unit tests of the run and build sandboxes.
//!
//! The tests that need `bubblewrap` and unprivileged user namespaces are
//! `#[ignore]`d and run with
//! `cargo test -p pkgre-rust --lib -- --ignored self_publish::sandbox::tests::`.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read as _;
use std::net::ToSocketAddrs as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use semver::Version;

use super::super::isolation::CERTIFICATE_VARIABLES;
use super::*;
use crate::self_publish::derive::{copy_workspace, read_archives};

/// One temporary directory, removed when the test ends.
struct Temporary(PathBuf);

impl Temporary {
    /// Makes one fresh directory below the host's temporary directory.
    fn new(prefix: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "pkgre-sandbox-{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("make a temporary directory");
        Self(path)
    }

    /// Returns the directory.
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = remove_tree(&self.0);
    }
}

/// Writes one executable file with the given text.
fn write_executable(path: &Path, text: &str) {
    fs::write(path, text).expect("write an executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("make it executable");
}

/// Returns the arguments of one run sandbox with fixed inputs.
fn run_arguments() -> Vec<OsString> {
    let binds = RunBinds {
        store: Some(PathBuf::from("/nix/store")),
        system: vec![PathBuf::from("/usr"), PathBuf::from("/bin")],
        etc: vec![
            (
                PathBuf::from("/etc/resolv.conf"),
                PathBuf::from("/etc/resolv.conf"),
            ),
            (
                PathBuf::from("/run/real/hosts"),
                PathBuf::from("/etc/hosts"),
            ),
        ],
        certificates: vec![PathBuf::from("/etc/ssl/certs/ca-certificates.crt")],
        repository: PathBuf::from("/work/catalog"),
        outside: vec![
            PathBuf::from("/work/toolchain"),
            PathBuf::from("/work/bwrap"),
        ],
    };
    let environment = vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("TMPDIR"), OsString::from("/run/root")),
    ];
    let command = vec![
        OsString::from("self-publish"),
        OsString::from("/work/catalog"),
        OsString::from("rust/v1.0.0"),
        OsString::from("--upload"),
    ];
    RunSandbox {
        root: Path::new("/run/root"),
        binds: &binds,
        environment: &environment,
        status_fd: 7,
        command: &command,
    }
    .arguments()
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_run_sandbox_arguments_are_fixed() {
    let expected = [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--die-with-parent",
        "--dir",
        "/tmp",
        "--ro-bind",
        "/nix/store",
        "/nix/store",
        "--ro-bind-try",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind",
        "/etc/resolv.conf",
        "/etc/resolv.conf",
        "--ro-bind",
        "/run/real/hosts",
        "/etc/hosts",
        "--ro-bind-try",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-certificates.crt",
        "--ro-bind",
        "/work/catalog",
        "/work/catalog",
        "--ro-bind",
        "/work/toolchain",
        "/work/toolchain",
        "--ro-bind",
        "/work/bwrap",
        "/work/bwrap",
        "--bind",
        "/run/root",
        "/run/root",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--remount-ro",
        "/",
        "--chdir",
        "/run/root",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "TMPDIR",
        "/run/root",
        "--json-status-fd",
        "7",
        "--",
        "self-publish",
        "/work/catalog",
        "rust/v1.0.0",
        "--upload",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    assert_eq!(run_arguments(), expected);
    let arguments = run_arguments();
    assert!(
        !arguments.iter().any(|argument| argument == "--as-pid-1"),
        "the run sandbox leaves its init alive until --die-with-parent ends it"
    );
    assert!(
        !arguments.iter().any(|argument| argument == "--new-session"),
        "the routine shares the terminal's process group, so that its SIGINT reaches both"
    );
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let home = fs::canonicalize(&home).unwrap_or(home);
        let home = home.to_string_lossy();
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.to_string_lossy().contains(home.as_ref())),
            "no argument names the home or one of its ancestors"
        );
    }
}

#[test]
fn the_build_sandbox_arguments_are_fixed() {
    let system = [PathBuf::from("/usr")];
    let outside = [PathBuf::from("/work/toolchain")];
    let command = [
        OsString::from("/work/toolchain/bin/cargo"),
        OsString::from("package"),
        OsString::from("--offline"),
    ];
    let sandbox = BuildSandbox {
        store: Some(Path::new("/nix/store")),
        system: &system,
        outside: &outside,
        path: OsStr::new("/usr/bin:/bin"),
        root: Path::new("/build/root"),
        command: &command,
    };
    let expected = [
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--assert-userns-disabled",
        "--new-session",
        "--die-with-parent",
        "--as-pid-1",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        "/nix/store",
        "/nix/store",
        "--ro-bind-try",
        "/usr",
        "/usr",
        "--bind",
        "/build/root",
        "/build/root",
        "--ro-bind",
        "/work/toolchain",
        "/work/toolchain",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--remount-ro",
        "/",
        "--chdir",
        "/build/root/work",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "TMPDIR",
        "/build/root/tmp",
        "--setenv",
        "CARGO_HOME",
        "/build/root/cargo-home",
        "--setenv",
        "RUSTC",
        "/work/toolchain/bin/rustc",
        "--setenv",
        "CARGO_TERM_COLOR",
        "never",
        "--setenv",
        "CARGO_NET_GIT_FETCH_WITH_CLI",
        "false",
        "--setenv",
        "CARGO_NET_OFFLINE",
        "true",
        "--",
        "/work/toolchain/bin/cargo",
        "package",
        "--offline",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    let arguments = sandbox.arguments();
    assert_eq!(arguments, expected);
    assert!(
        !arguments
            .iter()
            .any(|argument| argument == OsStr::new("/etc")),
        "the build sandbox shows no /etc"
    );
    for name in CERTIFICATE_VARIABLES {
        assert!(
            !arguments
                .iter()
                .any(|argument| argument == OsStr::new(name)),
            "the build sandbox inherits no certificate variable, but it names {name}"
        );
    }
}

#[test]
fn the_minimal_etc_follows_a_chain_of_links_and_skips_a_missing_file() {
    let temporary = Temporary::new("etc");
    let root = temporary.path();
    fs::create_dir_all(root.join("etc/ssl/certs")).expect("make the etc directory");
    fs::create_dir_all(root.join("real")).expect("make the link target's directory");
    fs::write(root.join("etc/resolv.conf"), "nameserver 127.0.0.1\n").expect("write resolv.conf");
    fs::write(root.join("real/hosts"), "127.0.0.1 localhost\n").expect("write the hosts file");
    // A chain: `/etc/host.conf` links to `/etc/hosts`, which links out of /etc.
    std::os::unix::fs::symlink(root.join("real/hosts"), root.join("etc/hosts"))
        .expect("link the hosts file");
    std::os::unix::fs::symlink(root.join("etc/hosts"), root.join("etc/host.conf"))
        .expect("link host.conf to hosts");
    // A directory where a file belongs is not shown, and a missing file is not.
    fs::create_dir(root.join("etc/passwd")).expect("make a directory named passwd");
    let hosts = fs::canonicalize(root.join("real/hosts")).expect("resolve the hosts file");
    let resolv = fs::canonicalize(root.join("etc/resolv.conf")).expect("resolve resolv.conf");
    let expected = vec![
        (resolv, PathBuf::from("/etc/resolv.conf")),
        (hosts.clone(), PathBuf::from("/etc/hosts")),
        (hosts, PathBuf::from("/etc/host.conf")),
    ];
    assert_eq!(etc_files(root), expected);
}

#[test]
fn the_path_drops_missing_entries_and_keeps_canonical_ones() {
    let temporary = Temporary::new("path");
    let root = temporary.path();
    fs::create_dir(root.join("bin")).expect("make the bin directory");
    fs::create_dir(root.join("second")).expect("make a second directory");
    std::os::unix::fs::symlink(root.join("bin"), root.join("linked")).expect("link the directory");
    let value = std::env::join_paths([
        root.join("linked"),
        root.join("missing"),
        root.join("second"),
    ])
    .expect("join the path");
    let canonical = canonical_path(&value);
    let entries = std::env::split_paths(&canonical).collect::<Vec<_>>();
    assert_eq!(
        entries,
        vec![
            fs::canonicalize(root.join("bin")).expect("resolve the linked directory"),
            fs::canonicalize(root.join("second")).expect("resolve the second directory"),
        ]
    );
}

#[test]
fn the_process_check_decides_from_the_children_and_the_process_table() {
    let init = ProcessEntry {
        pid: 1,
        state: 'S',
        parent: 0,
        command: "bwrap".to_owned(),
    };
    let routine = ProcessEntry {
        pid: 42,
        state: 'S',
        parent: 1,
        command: "self-publish /work/catalog rust/v1.0.0".to_owned(),
    };
    let alone = [init, routine];
    decide(42, Children::None, &alone).expect("the init and the routine alone pass");
    let error = format!(
        "{:#}",
        decide(42, Children::Running, &alone).expect_err("a running child fails the check")
    );
    assert!(error.contains("a child that has not exited"), "{error}");
    let error = format!(
        "{:#}",
        decide(42, Children::Exited(43), &alone).expect_err("an unreaped child fails the check")
    );
    assert!(error.contains("the exited child PID 43"), "{error}");
    let stranger = ProcessEntry {
        pid: 9,
        state: 'R',
        parent: 1,
        command: "sleep 60".to_owned(),
    };
    let error = format!(
        "{:#}",
        decide(
            42,
            Children::None,
            &[alone[0].clone(), alone[1].clone(), stranger]
        )
        .expect_err("an extra process fails the check")
    );
    assert!(
        error.contains("PID 9 (state R, parent 1, command \"sleep 60\")"),
        "{error}"
    );
}

#[test]
fn the_copy_keeps_directories_modes_and_the_empty_ones() {
    let temporary = Temporary::new("copy");
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    fs::create_dir_all(source.join("empty")).expect("make an empty directory");
    fs::create_dir_all(source.join("nested/deeper")).expect("make a nested directory");
    fs::write(source.join("README.md"), "a release\n").expect("write a file");
    write_executable(&source.join("tool"), "#!/bin/sh\nexit 0\n");
    copy_workspace(&source, &destination).expect("copy the workspace");
    assert!(destination.join("empty").is_dir());
    assert!(destination.join("nested/deeper").is_dir());
    assert_eq!(
        fs::read(destination.join("README.md")).expect("read the copy"),
        b"a release\n"
    );
    assert_eq!(
        fs::metadata(destination.join("tool"))
            .expect("inspect the copy")
            .permissions()
            .mode()
            & 0o111,
        0o111,
        "the executable bit stays"
    );
    let target = temporary.path().join("another");
    fs::create_dir(&target).expect("make another directory");
    fs::write(target.join("file"), "one\n").expect("write a file");
    std::os::unix::fs::symlink(target.join("file"), source.join("link")).expect("link a file");
    let error = format!(
        "{:#}",
        copy_workspace(&source, &destination).expect_err("a symbolic link is refused")
    );
    assert!(error.contains("the workspace copy refuses"), "{error}");
    fs::remove_file(source.join("link")).expect("remove the link");
    let fifo = source.join("fifo");
    let status = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed: {status}");
    let error = format!(
        "{:#}",
        copy_workspace(&source, &destination).expect_err("a named pipe is refused")
    );
    assert!(error.contains("the workspace copy refuses"), "{error}");
}

/// Returns the members that one archive test packages.
fn archive_members() -> Vec<(String, Version)> {
    vec![(
        "example-lib".to_owned(),
        Version::parse("1.0.0").expect("parse a version"),
    )]
}

#[test]
fn the_archive_reader_refuses_a_symbolic_link_at_each_level() {
    let temporary = Temporary::new("archive");
    let real = temporary.path().join("real");
    fs::create_dir_all(&real).expect("make the real directory");
    let archive = real.join("example-lib-1.0.0.crate");
    fs::write(&archive, "an archive").expect("write an archive");
    // A link at the archive.
    let target = temporary.path().join("target-one");
    fs::create_dir_all(target.join("package")).expect("make target/package");
    std::os::unix::fs::symlink(&archive, target.join("package/example-lib-1.0.0.crate"))
        .expect("link the archive");
    let error = format!(
        "{:#}",
        read_archives(&target, &archive_members()).expect_err("a linked archive is refused")
    );
    assert!(error.contains("symbolic link"), "{error}");
    // A link at target/package.
    let target = temporary.path().join("target-two");
    fs::create_dir(&target).expect("make target");
    std::os::unix::fs::symlink(&real, target.join("package")).expect("link target/package");
    let error = format!(
        "{:#}",
        read_archives(&target, &archive_members())
            .expect_err("a linked package directory is refused")
    );
    assert!(error.contains("symbolic link"), "{error}");
    // A link at target.
    let link = temporary.path().join("target-three");
    std::os::unix::fs::symlink(&real, &link).expect("link target");
    let error = format!(
        "{:#}",
        read_archives(&link, &archive_members()).expect_err("a linked target is refused")
    );
    assert!(error.contains("symbolic link"), "{error}");
}

#[test]
fn the_removal_opens_a_directory_of_mode_zero_inside_another() {
    let temporary = Temporary::new("remove");
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("inner")).expect("make the inner directory");
    fs::write(root.join("inner/file"), "left behind\n").expect("write a file");
    fs::set_permissions(root.join("inner"), fs::Permissions::from_mode(0o000))
        .expect("close the inner directory");
    remove_tree(&root).expect("remove the tree");
    assert!(!root.exists(), "the tree is gone");
    let missing = temporary.path().join("missing");
    remove_tree(&missing).expect("removing what is not there is not an error");
}

/// The variable that makes one of the helper tests run.
const HELPER_VARIABLE: &str = "PKGRE_SANDBOX_TEST_HELPER";
/// The variable that names the pipe whose ends a helper looks for.
const PIPE_VARIABLE: &str = "PKGRE_SANDBOX_TEST_PIPE";

/// Runs one `git` command in a fixture repository.
fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.name=Sandbox Test",
            "-c",
            "user.email=sandbox@example",
        ])
        .args(arguments)
        .status()
        .expect("run git");
    assert!(status.success(), "git {arguments:?} failed: {status}");
}

/// Makes one committed Git checkout below `root`.
fn checkout(root: &Path) {
    fs::create_dir_all(root).expect("make the checkout");
    git(root, &["init", "--quiet"]);
    fs::write(root.join("file"), "a release\n").expect("write a file");
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "release"]);
}

/// Runs `check_bwrap` on a fake script that a concurrent fork may still hold
/// open for writing in a build sandbox, and retries that one failure.
fn checked_bwrap(path: &Path) -> anyhow::Result<PathBuf> {
    for _ in 0..20 {
        match super::check_bwrap(path) {
            Err(error) if format!("{error:#}").contains("Text file busy") => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            result => return result,
        }
    }
    super::check_bwrap(path)
}

#[test]
fn the_launcher_refuses_a_bubblewrap_that_it_cannot_trust() {
    let temporary = Temporary::new("bwrap");
    let root = temporary.path();
    let good = root.join("bwrap-0.13.1");
    write_executable(&good, "#!/bin/sh\necho 'bubblewrap 0.13.1'\n");
    assert_eq!(
        checked_bwrap(&good).expect("a current bubblewrap is accepted"),
        fs::canonicalize(&good).expect("resolve the fake bubblewrap")
    );
    let old = root.join("bwrap-0.11.2");
    write_executable(&old, "#!/bin/sh\necho 'bubblewrap 0.11.2'\n");
    let error = format!(
        "{:#}",
        checked_bwrap(&old).expect_err("an old bubblewrap is refused")
    );
    assert!(error.contains("older than the first release"), "{error}");
    let setuid = root.join("bwrap-setuid");
    write_executable(&setuid, "#!/bin/sh\necho 'bubblewrap 0.13.1'\n");
    match fs::set_permissions(&setuid, fs::Permissions::from_mode(0o4755)) {
        Ok(()) => {
            let error = format!(
                "{:#}",
                checked_bwrap(&setuid).expect_err("a setuid bubblewrap is refused")
            );
            assert!(error.contains("setuid"), "{error}");
        }
        // A build sandbox without the capability cannot set the bit; the check
        // reads the mode, which no test path can otherwise produce.
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("this host cannot set the setuid bit: {error}");
        }
        Err(error) => panic!("make the fake bubblewrap setuid: {error}"),
    }
    let silent = root.join("bwrap-silent");
    write_executable(&silent, "#!/bin/sh\nexit 0\n");
    let error = format!(
        "{:#}",
        checked_bwrap(&silent).expect_err("a bubblewrap without a version is refused")
    );
    assert!(error.contains("does not report a version"), "{error}");
    let error = format!(
        "{:#}",
        checked_bwrap(Path::new("bwrap")).expect_err("a relative path is refused")
    );
    assert!(error.contains("absolute"), "{error}");
    let error = format!(
        "{:#}",
        checked_bwrap(&root.join("missing")).expect_err("a missing bubblewrap is refused")
    );
    assert!(error.contains("find bubblewrap"), "{error}");
}

#[test]
fn the_launcher_refuses_a_cargo_that_is_not_the_pinned_one() {
    let temporary = Temporary::new("cargo");
    let root = temporary.path();
    let cargo = root.join("cargo");
    write_executable(&cargo, "#!/bin/sh\nexit 0\n");
    assert_eq!(
        check_cargo(Some(cargo.as_os_str())).expect("a regular file is accepted"),
        fs::canonicalize(&cargo).expect("resolve the fake Cargo")
    );
    let error = format!(
        "{:#}",
        check_cargo(None).expect_err("an unset PKGRE_CARGO is refused")
    );
    assert!(error.contains(CARGO_VARIABLE), "{error}");
    let error = format!(
        "{:#}",
        check_cargo(Some(OsStr::new("cargo"))).expect_err("a relative Cargo is refused")
    );
    assert!(error.contains("absolute"), "{error}");
    let error = format!(
        "{:#}",
        check_cargo(Some(root.as_os_str())).expect_err("a directory is refused")
    );
    assert!(error.contains("not a regular file"), "{error}");
}

#[test]
fn the_launcher_refuses_a_bind_that_reaches_the_home_or_another_bind() {
    let home = Path::new("/home/example");
    let error = format!(
        "{:#}",
        check_binds(home, &[PathBuf::from("/home")])
            .expect_err("an ancestor of the home is refused")
    );
    assert!(
        error.contains("home directory or one of its ancestors"),
        "{error}"
    );
    check_binds(home, &[PathBuf::from("/home/example/catalog")])
        .expect("a directory inside the home is bound");
    let error = format!(
        "{:#}",
        check_binds(
            home,
            &[PathBuf::from("/work"), PathBuf::from("/work/inner")]
        )
        .expect_err("a bind inside another is refused")
    );
    assert!(error.contains("inside"), "{error}");
    check_binds(
        home,
        &[PathBuf::from("/nix/store"), PathBuf::from("/nix/store/abc")],
    )
    .expect("a path below the store is visible already");
    check_binds(home, &[PathBuf::from("/usr"), PathBuf::from("/usr/lib")])
        .expect("a path below a system directory is visible already");
}

#[test]
fn the_launcher_refuses_a_repository_that_a_sandbox_cannot_show_alone() {
    let temporary = Temporary::new("repository");
    let root = temporary.path();
    let catalog = root.join("catalog");
    checkout(&catalog);
    assert_eq!(
        check_repository(&catalog).expect("a plain checkout is accepted"),
        fs::canonicalize(&catalog).expect("resolve the checkout")
    );
    let worktree = root.join("linked");
    git(
        &catalog,
        &[
            "worktree",
            "add",
            "--quiet",
            worktree.to_str().expect("a UTF-8 path"),
        ],
    );
    let error = format!(
        "{:#}",
        check_repository(&worktree).expect_err("a linked worktree is refused")
    );
    assert!(error.contains("linked worktree"), "{error}");
    let alternates = root.join("borrowed");
    checkout(&alternates);
    fs::create_dir_all(alternates.join(".git/objects/info")).expect("make objects/info");
    fs::write(
        alternates.join(".git/objects/info/alternates"),
        "/somewhere/else\n",
    )
    .expect("write the alternates file");
    let error = format!(
        "{:#}",
        check_repository(&alternates).expect_err("a checkout with alternates is refused")
    );
    assert!(error.contains("borrows Git objects"), "{error}");
    let plain = root.join("plain");
    fs::create_dir(&plain).expect("make a directory without Git");
    let error = format!(
        "{:#}",
        check_repository(&plain).expect_err("a directory without Git is refused")
    );
    assert!(error.contains("holds no Git repository"), "{error}");
}

#[test]
fn the_launcher_refuses_a_standard_input_below_a_bind() {
    let temporary = Temporary::new("input");
    let catalog = temporary.path().join("catalog");
    fs::create_dir(&catalog).expect("make the catalog directory");
    let pipe = catalog.join("stdin");
    let status = Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed: {status}");
    let sources = [catalog.clone()];
    let error = format!(
        "{:#}",
        check_input_path(Some(&pipe), &sources).expect_err("a pipe below the checkout is refused")
    );
    assert!(error.contains("lies below"), "{error}");
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).expect("make a directory outside the bind");
    check_input_path(Some(&outside), &sources).expect("a path outside every bind is accepted");
    check_input_path(None, &sources).expect("no standard input path needs no check");
}

#[test]
fn a_run_sandbox_that_was_never_made_names_the_usual_causes() {
    use std::os::unix::process::ExitStatusExt as _;
    let status = std::process::ExitStatus::from_raw(1 << 8);
    let error = format!(
        "{:#}",
        interpret_status(&[], status).expect_err("no status document fails the run")
    );
    assert!(error.contains("was never made"), "{error}");
    assert!(
        error.contains("kernel.apparmor_restrict_unprivileged_userns"),
        "{error}"
    );
    let document = serde_json::json!({"child-pid": 1234});
    let error = format!(
        "{:#}",
        interpret_status(&[document], status).expect_err("no exit code fails the run")
    );
    assert!(error.contains("without an exit status"), "{error}");
    let document = serde_json::json!({"child-pid": 1234, "exit-code": 3});
    assert_eq!(
        interpret_status(&[document], status).expect("an exit code is the routine's status"),
        3
    );
}

/// Runs a helper test in a process of its own, with its standard input and
/// output captured.
fn run_helper(action: &str, wrap: Option<&str>) -> std::process::Output {
    let executable = std::env::current_exe().expect("the test binary");
    let helper = "self_publish::sandbox::tests::start_helper";
    let mut command = if let Some(script) = wrap {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            script,
            "sh",
            executable.to_str().expect("a UTF-8 executable path"),
            "--exact",
            helper,
            "--nocapture",
        ]);
        command.env(HELPER_VARIABLE, action);
        command
    } else {
        let mut command = Command::new(executable);
        command.args(["--exact", helper, "--nocapture"]);
        command.env(HELPER_VARIABLE, action);
        command
    };
    command.output().expect("run the helper")
}

#[test]
fn the_start_marks_descriptors_close_on_exec_and_resets_the_signal_handlers() {
    let output = run_helper("start", Some("trap '' INT QUIT; exec \"$@\""));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("SIGINT-IGNORED") && stdout.contains("SIGQUIT-IGNORED"),
        "the shell must start the helper with both signals ignored: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("PIPE-CLOSED"),
        "the child must not inherit the pipe: {stdout}{stderr}"
    );
    assert!(
        !stdout.contains("PIPE-OPEN"),
        "a descriptor above 2 reached the child: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("SIGNALS-DEFAULT"),
        "the child's SIGINT and SIGQUIT must be at their defaults: {stdout}{stderr}"
    );
    assert!(
        !stdout.contains("SIGINT-ALIVE"),
        "the child's SIGINT must be at its default: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("CHILD-SIGNALLED"),
        "the child ends when it raises SIGINT: {stdout}{stderr}"
    );
    assert!(
        output.status.success(),
        "the helper itself passes: {stdout}{stderr}"
    );
}

#[test]
fn start_helper() {
    let Some(action) = std::env::var_os(HELPER_VARIABLE) else {
        return;
    };
    match action.to_str() {
        Some("start") => start_helper_body(),
        Some("child") => start_child_helper_body(),
        Some("relative") => relative_repository_helper_body(),
        _ => panic!("unknown helper action {action:?}"),
    }
}

/// The body of the process that starts the launcher's child.
fn start_helper_body() {
    use std::os::unix::process::ExitStatusExt as _;
    // The shell ignored both signals, so raising them must return.
    nix::sys::signal::raise(nix::sys::signal::Signal::SIGINT).expect("raise SIGINT");
    println!("SIGINT-IGNORED");
    nix::sys::signal::raise(nix::sys::signal::Signal::SIGQUIT).expect("raise SIGQUIT");
    println!("SIGQUIT-IGNORED");
    // Neither end of this pipe is close-on-exec, as a descriptor of the caller
    // is not, so marking them must keep them from the child.
    let (_reader, writer) = nix::unistd::pipe().expect("make a pipe");
    let link = fs::read_link(format!("/proc/self/fd/{}", writer.as_raw_fd()))
        .expect("read the pipe's link")
        .to_string_lossy()
        .into_owned();
    mark_descriptors().expect("mark the descriptors close-on-exec");
    install_signal_handlers().expect("install the launcher's signal handlers");
    let mut command = Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args([
            "--exact",
            "self_publish::sandbox::tests::start_helper",
            "--nocapture",
        ])
        .env(HELPER_VARIABLE, "child")
        .env(PIPE_VARIABLE, link);
    let child = spawn_command(command).expect("start the child");
    let output = child.wait_with_output().expect("wait for the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{stdout}");
    println!(
        "{}",
        if output.status.signal() == Some(nix::libc::SIGINT) {
            "CHILD-SIGNALLED"
        } else {
            "CHILD-EXITED"
        }
    );
}

/// The body of the child that the launcher's spawn starts.
fn start_child_helper_body() {
    let pipe = std::env::var(PIPE_VARIABLE).expect("the pipe's link");
    let mut open = false;
    for entry in fs::read_dir("/proc/self/fd").expect("list the descriptors") {
        let Ok(entry) = entry else {
            continue;
        };
        if fs::read_link(entry.path()).is_ok_and(|link| link.to_string_lossy() == pipe) {
            open = true;
        }
    }
    println!("{}", if open { "PIPE-OPEN" } else { "PIPE-CLOSED" });
    // Both signals must be at their default: neither ignored nor caught.
    let status = fs::read_to_string("/proc/self/status").expect("read the process status");
    let mask = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| u64::from_str_radix(rest.trim(), 16).ok())
            .unwrap_or(0)
    };
    let ignored = mask("SigIgn:");
    let caught = mask("SigCgt:");
    let default =
        |signal: u32| ignored & (1 << (signal - 1)) == 0 && caught & (1 << (signal - 1)) == 0;
    println!(
        "{}",
        if default(2) && default(3) {
            "SIGNALS-DEFAULT"
        } else {
            "SIGNALS-NOT-DEFAULT"
        }
    );
    nix::sys::signal::raise(nix::sys::signal::Signal::SIGINT).expect("raise SIGINT");
    println!("SIGINT-ALIVE");
}

#[test]
fn a_relative_repository_is_made_absolute() {
    let temporary = Temporary::new("relative");
    let catalog = temporary.path().join("catalog");
    checkout(&catalog);
    let executable = std::env::current_exe().expect("the test binary");
    let output = {
        let mut command = Command::new(executable);
        command
            .current_dir(temporary.path())
            .args([
                "--exact",
                "self_publish::sandbox::tests::start_helper",
                "--nocapture",
            ])
            .env(HELPER_VARIABLE, "relative");
        command.output().expect("run the helper")
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = fs::canonicalize(&catalog).expect("resolve the checkout");
    assert!(
        stdout.contains(expected.to_str().expect("a UTF-8 path")),
        "{stdout}"
    );
}

/// The body of the process that reads a relative repository.
fn relative_repository_helper_body() {
    let repository = check_repository(Path::new("catalog")).expect("resolve the relative checkout");
    println!("{}", repository.display());
}

/// Serializes the ignored sandbox tests: each marks the test process's
/// descriptors close-on-exec, so a descriptor another test opens meanwhile must
/// not reach the sandbox.
static SANDBOX_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Returns the lock that makes one sandbox test run at a time.
fn sandbox_test_lock() -> std::sync::MutexGuard<'static, ()> {
    SANDBOX_TEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The variable through which a body test learns which run sandbox body it is.
const BODY_VARIABLE: &str = "PKGRE_SANDBOX_TEST_BODY";
/// The variable that names the catalog checkout of a run sandbox body.
const REPOSITORY_VARIABLE: &str = "PKGRE_SANDBOX_TEST_REPOSITORY";
/// The variable that names the port of a listener that a body reaches.
const PORT_VARIABLE: &str = "PKGRE_SANDBOX_TEST_PORT";

/// Runs one test body inside a run sandbox made from the launcher's own
/// arguments, and returns what it printed and the routine's exit status.
fn run_in_run_sandbox(
    body: &str,
    action: &str,
    extra: &[(&str, OsString)],
) -> (std::process::Output, i32) {
    RunSandboxProcess::start(body, action, extra).finish()
}

/// One run sandbox whose launcher is this test process.
struct RunSandboxProcess {
    /// The `bubblewrap` that makes the sandbox.
    child: std::process::Child,
    /// The run root, removed when the test ends.
    root: Temporary,
    /// The catalog checkout that the sandbox binds read-only, kept alive for
    /// the sandbox's lifetime.
    _repository: Temporary,
    /// The read end of the status pipe.
    reader: fs::File,
}

impl RunSandboxProcess {
    /// Makes the run root and starts the sandbox with the given body.
    fn start(body: &str, action: &str, extra: &[(&str, OsString)]) -> Self {
        let host = Host::detect().expect("bubblewrap and the pinned Cargo");
        let repository = Temporary::new("repository");
        let root = Temporary::new("run-root");
        let executable = fs::canonicalize(std::env::current_exe().expect("the test binary"))
            .expect("resolve the test binary");
        let toolchain = host.cargo.parent().expect("the pinned Cargo's directory");
        let binds = RunBinds {
            store: host.store.clone(),
            system: host.system.clone(),
            etc: etc_files(Path::new("/")),
            certificates: host
                .certificates
                .iter()
                .map(|(_, value)| PathBuf::from(value))
                .filter(|value| !host.visible_already(value))
                .collect(),
            repository: repository.path().to_path_buf(),
            outside: host.outside(&[toolchain, &host.bwrap, &executable]),
        };
        let marker = process_namespace().expect("the process namespace");
        let mut environment = run_environment(&marker, root.path(), &host);
        environment.push((OsString::from(BODY_VARIABLE), OsString::from(action)));
        environment.push((
            OsString::from(REPOSITORY_VARIABLE),
            repository.path().as_os_str().to_owned(),
        ));
        for (name, value) in extra {
            environment.push((OsString::from(*name), value.clone()));
        }
        let command = vec![
            executable.into_os_string(),
            OsString::from("--exact"),
            OsString::from(body),
            OsString::from("--nocapture"),
        ];
        mark_descriptors().expect("mark the launcher's descriptors close-on-exec");
        let (reader, writer) = status_pipe().expect("make the status pipe");
        let sandbox = RunSandbox {
            root: root.path(),
            binds: &binds,
            environment: &environment,
            status_fd: writer.as_raw_fd(),
            command: &command,
        };
        let arguments = sandbox.arguments();
        let child = Command::new(&host.bwrap)
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the run sandbox");
        drop(writer);
        Self {
            child,
            root,
            _repository: repository,
            reader,
        }
    }

    /// Waits for the sandbox and returns what the routine printed and its exit
    /// status.
    fn finish(mut self) -> (std::process::Output, i32) {
        let output = self
            .child
            .wait_with_output()
            .expect("wait for the run sandbox");
        let documents = read_status_documents(&mut self.reader).expect("read the status documents");
        let status = interpret_status(&documents, output.status).expect("the run sandbox ended");
        (output, status)
    }
}

/// Requires that one ignored sandbox test's body passed.
fn require_body(output: &std::process::Output, status: i32, marker: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(status, 0, "the body passed: {stdout}{stderr}");
    assert!(stdout.contains(marker), "{marker}: {stdout}{stderr}");
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn run_view() {
    let _guard = sandbox_test_lock();
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("listen on the host's loopback");
    let port = listener
        .local_addr()
        .expect("the listener's address")
        .port();
    let (output, status) = run_in_run_sandbox(
        "self_publish::sandbox::tests::run_view_body",
        "run-view",
        &[
            (PORT_VARIABLE, OsString::from(port.to_string())),
            (
                "PKGRE_SANDBOX_TEST_HOME",
                std::env::var_os("HOME").unwrap_or_default(),
            ),
        ],
    );
    require_body(&output, status, "RUN-VIEW-OK");
    listener
        .set_nonblocking(true)
        .expect("make the listener non-blocking");
    assert!(
        listener.accept().is_ok(),
        "the body reached the listener: the run sandbox shares the network"
    );
}

#[test]
fn run_view_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("run-view")) {
        return;
    }
    // The sandbox's init starts the body, and it is PID 1.
    assert_eq!(
        nix::unistd::getppid(),
        nix::unistd::Pid::from_raw(1),
        "the run sandbox starts the routine as PID 1's child"
    );
    // The home's contents are invisible: the launcher binds only the routine's
    // executable and the toolchain, so the home is an empty mount point.
    let home = PathBuf::from(std::env::var_os("PKGRE_SANDBOX_TEST_HOME").expect("the home"));
    for name in [".cargo", ".ssh", ".config", ".gitconfig", ".bashrc"] {
        assert!(
            fs::metadata(home.join(name)).is_err(),
            "the run sandbox shows {name} of the home"
        );
    }
    assert!(
        fs::metadata(home.join(".cargo/credentials.toml")).is_err(),
        "the run sandbox shows no Cargo credentials"
    );
    // The catalog checkout is read-only and the run root is writable.
    let repository =
        PathBuf::from(std::env::var(REPOSITORY_VARIABLE).expect("the catalog checkout's path"));
    assert!(
        fs::write(repository.join("attempt"), "one\n").is_err(),
        "the catalog checkout is read-only"
    );
    let root = PathBuf::from(std::env::var_os("TMPDIR").expect("the run root"));
    fs::write(root.join("written"), "one\n").expect("the run root is writable");
    // The minimal /etc holds the files that name resolution and TLS need.
    assert!(
        fs::metadata("/etc/resolv.conf")
            .expect("resolv.conf")
            .is_file()
    );
    assert!(fs::metadata("/etc/passwd").expect("passwd").is_file());
    assert!(
        fs::metadata("/etc/shadow").is_err(),
        "the rest of the host's /etc is not shown"
    );
    // The process table holds the init and the routine alone.
    require_alone().expect("the run sandbox holds only its init and the routine");
    // Nothing but the standard streams reaches the routine.
    let mut descriptors = fs::read_dir("/proc/self/fd")
        .expect("list the descriptors")
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .collect::<Vec<_>>();
    descriptors.retain(|descriptor| fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
    assert!(
        descriptors.iter().all(|descriptor| *descriptor <= 2),
        "the routine holds only the standard streams, but it holds {descriptors:?}"
    );
    // The network is the host's: a listener of the test answers.
    let port = std::env::var(PORT_VARIABLE)
        .expect("the listener's port")
        .parse::<u16>()
        .expect("parse the port");
    std::net::TcpStream::connect(("127.0.0.1", port)).expect("reach the listener");
    // A process left behind fails the check.
    let mut leftover = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("start a process in the run sandbox");
    let error = format!(
        "{:#}",
        require_alone().expect_err("a leftover process fails the check")
    );
    assert!(
        error.contains("more than its init and the routine"),
        "{error}"
    );
    leftover.kill().expect("end the leftover process");
    leftover.wait().expect("reap the leftover process");
    println!("RUN-VIEW-OK");
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn build_ends_every_process() {
    let _guard = sandbox_test_lock();
    let (output, status) = run_in_run_sandbox(
        "self_publish::sandbox::tests::build_ends_every_process_body",
        "build-processes",
        &[],
    );
    require_body(&output, status, "BUILD-ENDED-OK");
}

#[test]
fn build_ends_every_process_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("build-processes")) {
        return;
    }
    let build = BuildRoot::make_in(&std::env::temp_dir(), "pkgre-sandbox-build")
        .expect("make a build root");
    let executable = std::env::current_exe().expect("the test binary");
    let command = vec![
        executable.into_os_string(),
        OsString::from("--exact"),
        OsString::from("self_publish::sandbox::tests::detach_helper"),
        OsString::from("--nocapture"),
    ];
    run_build(build.path(), &command).expect("the build sandbox runs the detaching command");
    require_alone().expect("the run sandbox holds only its init and the routine");
    std::thread::sleep(std::time::Duration::from_secs(4));
    let marker = build.path().join("tmp/marker");
    assert!(
        !marker.exists(),
        "a process of the build outlived its sandbox and wrote {}",
        marker.display()
    );
    build.remove();
    println!("BUILD-ENDED-OK");
}

#[test]
fn detach_helper() {
    // Only a build sandbox runs this: it has no /etc, and the test host has one.
    if !in_build_sandbox() {
        return;
    }
    let executable = std::env::current_exe().expect("the test binary");
    // The process is meant to outlive this command, to the sandbox's init.
    #[allow(clippy::zombie_processes)]
    let _detached = Command::new(executable)
        .args([
            "--exact",
            "self_publish::sandbox::tests::write_later_helper",
            "--nocapture",
        ])
        .spawn()
        .expect("detach a process");
}

#[test]
fn write_later_helper() {
    if !in_build_sandbox() {
        return;
    }
    std::thread::sleep(std::time::Duration::from_secs(3));
    let marker =
        PathBuf::from(std::env::var_os("TMPDIR").expect("the build root's tmp")).join("marker");
    fs::write(marker, "a process outlived its build sandbox\n")
        .expect("write the marker of an outliving process");
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn build_reaches_nothing() {
    let _guard = sandbox_test_lock();
    // A descriptor that the caller leaves open without close-on-exec must not
    // reach the build sandbox.
    let (_reader, writer) = nix::unistd::pipe().expect("make a pipe");
    let leftover = fs::read_link(format!("/proc/self/fd/{}", writer.as_raw_fd()))
        .expect("read the pipe's link")
        .to_string_lossy()
        .into_owned();
    let home = std::env::var_os("HOME").expect("a home directory");
    let home_file = [".cargo", ".config", ".ssh"]
        .into_iter()
        .map(|name| PathBuf::from(&home).join(name))
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (output, status) = run_in_run_sandbox(
        "self_publish::sandbox::tests::build_reaches_nothing_body",
        "build-reach",
        &[
            (
                "PKGRE_SANDBOX_TEST_LEFTOVER",
                OsString::from(leftover.clone()),
            ),
            ("PKGRE_SANDBOX_TEST_HOME", home),
            ("PKGRE_SANDBOX_TEST_HOME_FILE", OsString::from(home_file)),
        ],
    );
    drop((writer, leftover));
    require_body(&output, status, "BUILD-REACH-OK");
}

#[test]
fn build_reaches_nothing_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("build-reach")) {
        return;
    }
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("listen on the run sandbox's loopback");
    let port = listener
        .local_addr()
        .expect("the listener's address")
        .port();
    let build = BuildRoot::make_in(&std::env::temp_dir(), "pkgre-sandbox-reach")
        .expect("make a build root");
    // What the build sandbox must not see, written into the build root's tmp so
    // that the build's own command can read where to look.
    fs::write(build.path().join("tmp/port"), port.to_string()).expect("write the port");
    fs::write(
        build.path().join("tmp/repository"),
        std::env::var(REPOSITORY_VARIABLE).expect("the catalog checkout's path"),
    )
    .expect("write the catalog checkout's path");
    fs::write(
        build.path().join("tmp/run-root"),
        std::env::var("TMPDIR").expect("the run root"),
    )
    .expect("write the run root's path");
    fs::write(
        PathBuf::from(std::env::var_os("TMPDIR").expect("the run root")).join("run-sandbox-marker"),
        "the run sandbox\n",
    )
    .expect("write into the run root");
    fs::write(
        build.path().join("tmp/leftover"),
        std::env::var("PKGRE_SANDBOX_TEST_LEFTOVER").expect("the leftover descriptor"),
    )
    .expect("write the leftover descriptor");
    fs::write(
        build.path().join("tmp/home"),
        std::env::var("PKGRE_SANDBOX_TEST_HOME").expect("the home directory"),
    )
    .expect("write the home directory");
    fs::write(
        build.path().join("tmp/home-file"),
        std::env::var("PKGRE_SANDBOX_TEST_HOME_FILE").expect("a file of the home"),
    )
    .expect("write a file of the home");
    let executable = std::env::current_exe().expect("the test binary");
    let command = vec![
        executable.into_os_string(),
        OsString::from("--exact"),
        OsString::from("self_publish::sandbox::tests::reach_helper"),
        OsString::from("--nocapture"),
    ];
    let stdout = run_build(build.path(), &command).expect("the build sandbox runs the probe");
    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("BUILD-REACH-NOTHING"),
        "the build sandbox reached something it must not: {stdout}"
    );
    build.remove();
    println!("BUILD-REACH-OK");
}

#[test]
fn reach_helper() {
    // Only a build sandbox runs this: it has no /etc, and the test host has one.
    if !in_build_sandbox() {
        return;
    }
    let tmp = PathBuf::from(std::env::var_os("TMPDIR").expect("the build root's tmp"));
    let port = fs::read_to_string(tmp.join("port"))
        .expect("read the port")
        .parse::<u16>()
        .expect("parse the port");
    let repository = fs::read_to_string(tmp.join("repository")).expect("read the catalog path");
    let mut reached = Vec::new();
    if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
        reached.push("the network");
    }
    if fs::read_dir("/etc").is_ok() {
        reached.push("the host's /etc");
    }
    let run_root =
        PathBuf::from(fs::read_to_string(tmp.join("run-root")).expect("read the run root's path"));
    if fs::metadata(run_root.join("run-sandbox-marker")).is_ok() {
        reached.push("the run sandbox's run root");
    }
    if fs::metadata(repository).is_ok() {
        reached.push("the catalog checkout");
    }
    let home_file = fs::read_to_string(tmp.join("home-file")).expect("read a file of the home");
    if !home_file.is_empty() && fs::metadata(&home_file).is_ok() {
        reached.push("the test's home");
    }
    let leftover = fs::read_to_string(tmp.join("leftover")).expect("read the leftover descriptor");
    if fs::read_dir("/proc/self/fd")
        .expect("list the descriptors")
        .filter_map(std::result::Result::ok)
        .any(|entry| {
            fs::read_link(entry.path()).is_ok_and(|path| path.to_string_lossy() == leftover)
        })
    {
        reached.push("the caller's descriptor");
    }
    if ("example.com", 443).to_socket_addrs().is_ok() {
        reached.push("name resolution");
    }
    if fs::metadata(std::env::var_os("CARGO_HOME").expect("the build's Cargo home"))
        .is_ok_and(|metadata| metadata.is_dir())
    {
        // The build's own Cargo home is reachable, as it must be.
    } else {
        reached.push("nothing, not even its Cargo home");
    }
    assert!(
        reached.is_empty(),
        "the build sandbox reached {}",
        reached.join(", ")
    );
    println!("BUILD-REACH-NOTHING");
}

/// The variable through which a launcher helper announces its run root.
const READY_VARIABLE: &str = "PKGRE_SANDBOX_TEST_READY";

impl RunSandboxProcess {
    /// Waits for the sandbox and returns its output, its status and the run
    /// root, which the caller removes as the launcher does.
    fn finish_keeping_root(mut self) -> (std::process::Output, i32, Temporary) {
        let output = self
            .child
            .wait_with_output()
            .expect("wait for the run sandbox");
        let documents = read_status_documents(&mut self.reader).expect("read the status documents");
        let status = interpret_status(&documents, output.status).expect("the run sandbox ended");
        (output, status, self.root)
    }
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn die_with_parent() {
    use std::os::unix::process::ExitStatusExt as _;
    let _guard = sandbox_test_lock();
    let ready = Temporary::new("ready");
    let announcement = ready.path().join("root");
    let mut launcher = Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--exact",
            "self_publish::sandbox::tests::launcher_helper",
            "--nocapture",
        ])
        .env(HELPER_VARIABLE, "die-with-parent")
        .env(READY_VARIABLE, &announcement)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the launcher");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut root = None;
    while std::time::Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(&announcement) {
            root = Some(PathBuf::from(text.trim()));
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let root = root.expect("the launcher announced its run root");
    launcher.kill().expect("kill the launcher");
    let output = launcher.wait_with_output().expect("reap the launcher");
    assert_eq!(
        output.status.signal(),
        Some(nix::libc::SIGKILL),
        "the launcher died of SIGKILL"
    );
    // The detached writers of both sandboxes would write after three seconds.
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert!(
        !root.join("marker").exists(),
        "a process of the run sandbox outlived the launcher"
    );
    let mut build_marker = None;
    for entry in fs::read_dir(&root).expect("read the run root") {
        let entry = entry.expect("read one entry of the run root");
        if entry.file_name().to_string_lossy().starts_with("build-") {
            let marker = entry.path().join("tmp/marker");
            if marker.exists() {
                build_marker = Some(marker);
            }
        }
    }
    assert!(
        build_marker.is_none(),
        "a process of the build sandbox outlived the launcher and wrote {}",
        build_marker.expect("the marker").display()
    );
    remove_tree(&root).expect("remove the run root of the killed launcher");
}

#[test]
fn launcher_helper() {
    if std::env::var_os(HELPER_VARIABLE).as_deref() != Some(OsStr::new("die-with-parent")) {
        return;
    }
    let announcement =
        PathBuf::from(std::env::var_os(READY_VARIABLE).expect("where to announce the run root"));
    let process = RunSandboxProcess::start(
        "self_publish::sandbox::tests::die_with_parent_body",
        "die-with-parent",
        &[],
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline && !process.root.path().join("ready").exists() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    fs::write(
        &announcement,
        process.root.path().to_str().expect("a UTF-8 run root"),
    )
    .expect("announce the run root");
    // The launcher lives until the test kills it.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[test]
fn die_with_parent_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("die-with-parent")) {
        return;
    }
    let build =
        BuildRoot::make_in(&std::env::temp_dir(), "pkgre-sandbox-die").expect("make a build root");
    let build_root = build.path().to_path_buf();
    let executable = std::env::current_exe().expect("the test binary");
    let command = vec![
        executable.clone().into_os_string(),
        OsString::from("--exact"),
        OsString::from("self_publish::sandbox::tests::sleep_with_writer_helper"),
        OsString::from("--nocapture"),
    ];
    // The build sandbox stays up with a detached writer in it.
    std::thread::spawn(move || {
        let _ = run_build(&build_root, &command);
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline && !build.path().join("tmp/build-ready").exists() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        build.path().join("tmp/build-ready").exists(),
        "the build sandbox started"
    );
    // A process of the run sandbox that writes into the run root after three
    // seconds.
    #[allow(clippy::zombie_processes)]
    let _detached = Command::new(executable)
        .args([
            "--exact",
            "self_publish::sandbox::tests::write_run_later_helper",
            "--nocapture",
        ])
        .spawn()
        .expect("detach a process in the run sandbox");
    let run_root = PathBuf::from(std::env::var_os("TMPDIR").expect("the run root"));
    fs::write(run_root.join("ready"), "ready\n").expect("say that the sandboxes are up");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[test]
fn sleep_with_writer_helper() {
    if !in_build_sandbox() {
        return;
    }
    let executable = std::env::current_exe().expect("the test binary");
    #[allow(clippy::zombie_processes)]
    let _detached = Command::new(executable)
        .args([
            "--exact",
            "self_publish::sandbox::tests::write_later_helper",
            "--nocapture",
        ])
        .spawn()
        .expect("detach a process in the build sandbox");
    let tmp = PathBuf::from(std::env::var_os("TMPDIR").expect("the build root's tmp"));
    fs::write(tmp.join("build-ready"), "ready\n").expect("say that the build sandbox is up");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[test]
fn write_run_later_helper() {
    if std::env::var_os(MARKER_VARIABLE).is_none() {
        return;
    }
    std::thread::sleep(std::time::Duration::from_secs(3));
    let marker = PathBuf::from(std::env::var_os("TMPDIR").expect("the run root")).join("marker");
    fs::write(marker, "a process outlived the run sandbox\n")
        .expect("write the marker of an outliving process");
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn run_root_after_a_leftover() {
    let _guard = sandbox_test_lock();
    let process = RunSandboxProcess::start(
        "self_publish::sandbox::tests::run_root_after_a_leftover_body",
        "leftover",
        &[],
    );
    let root = process.root.path().to_path_buf();
    let (output, status, root_holder) = process.finish_keeping_root();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(status, 0, "the body passed: {stdout}");
    assert!(stdout.contains("LEFTOVER-OK"), "{stdout}");
    // The leftover would write after three seconds.
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert!(
        !root.join("marker").exists(),
        "a process of the run outlived it and wrote into the run root"
    );
    assert!(
        root.exists(),
        "the run root is still there before the removal"
    );
    remove_tree(&root).expect("remove the run root");
    assert!(!root.exists(), "the run root is gone");
    drop(root_holder);
}

#[test]
fn run_root_after_a_leftover_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("leftover")) {
        return;
    }
    let executable = std::env::current_exe().expect("the test binary");
    #[allow(clippy::zombie_processes)]
    let _detached = Command::new(executable)
        .args([
            "--exact",
            "self_publish::sandbox::tests::write_run_later_helper",
            "--nocapture",
        ])
        .spawn()
        .expect("leave a process in the run sandbox");
    println!("LEFTOVER-OK");
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn build_keeps_the_bytes() {
    let _guard = sandbox_test_lock();
    let (output, status) = run_in_run_sandbox(
        "self_publish::sandbox::tests::build_keeps_the_bytes_body",
        "build-bytes",
        &[],
    );
    require_body(&output, status, "BUILD-BYTES-OK");
}

/// Writes the two-crate workspace that the byte test packages.
fn two_crate_workspace(root: &Path) {
    fs::create_dir_all(root.join("lib/src")).expect("make the library");
    fs::create_dir_all(root.join("bin/src")).expect("make the binary");
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"lib\", \"bin\"]\nresolver = \"3\"\n",
    )
    .expect("write the root manifest");
    fs::write(
        root.join("lib/Cargo.toml"),
        "[package]\nname = \"example-lib\"\nversion = \"0.1.0\"\nedition = \"2024\"\nlicense = \"MIT\"\ndescription = \"A release crate\"\npublish = [\"crates-io\"]\n",
    )
    .expect("write the library manifest");
    fs::write(root.join("lib/src/lib.rs"), "pub fn value() -> u32 { 7 }\n")
        .expect("write the library source");
    fs::write(
        root.join("bin/Cargo.toml"),
        "[package]\nname = \"example-bin\"\nversion = \"0.1.0\"\nedition = \"2024\"\nlicense = \"MIT\"\ndescription = \"A release crate\"\npublish = [\"crates-io\"]\n\n[dependencies]\nexample-lib = { path = \"../lib\", version = \"=0.1.0\" }\n",
    )
    .expect("write the binary manifest");
    fs::write(
        root.join("bin/src/main.rs"),
        "fn main() { println!(\"{}\", example_lib::value()); }\n",
    )
    .expect("write the binary source");
}

/// The members that the byte test packages, by package name.
fn two_crate_members() -> Vec<(String, Version)> {
    vec![
        (
            "example-bin".to_owned(),
            Version::parse("0.1.0").expect("parse a version"),
        ),
        (
            "example-lib".to_owned(),
            Version::parse("0.1.0").expect("parse a version"),
        ),
    ]
}

/// Runs one Cargo command in the run sandbox with a Cargo home of its own.
fn run_cargo_in_test(cargo: &Path, workspace: &Path, cargo_home: &Path, arguments: &[&str]) {
    let status = Command::new(cargo)
        .current_dir(workspace)
        .env("CARGO_HOME", cargo_home)
        .args(arguments)
        .status()
        .expect("run the pinned Cargo");
    assert!(
        status.success(),
        "cargo {arguments:?} failed in {}: {status}",
        workspace.display()
    );
}

/// Packages the two crates without verification, as `cargo publish` would, and
/// returns the archives by package name.
fn reference_archives(
    cargo: &Path,
    workspace: &Path,
    cargo_home: &Path,
    target: &Path,
    allow_dirty: bool,
) -> BTreeMap<String, Vec<u8>> {
    let mut arguments = vec![
        "package",
        "--no-verify",
        "--locked",
        "--target-dir",
        target.to_str().expect("a UTF-8 target path"),
    ];
    if allow_dirty {
        arguments.push("--allow-dirty");
    }
    for name in ["example-lib", "example-bin"] {
        arguments.push("--package");
        arguments.push(name);
    }
    run_cargo_in_test(cargo, workspace, cargo_home, &arguments);
    ["example-bin", "example-lib"]
        .into_iter()
        .map(|name| {
            let archive = target.join("package").join(format!("{name}-0.1.0.crate"));
            (
                name.to_owned(),
                fs::read(&archive).expect("read the reference archive"),
            )
        })
        .collect()
}

#[test]
fn build_keeps_the_bytes_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("build-bytes")) {
        return;
    }
    let cargo = PathBuf::from(std::env::var_os("PKGRE_CARGO").expect("the pinned Cargo"));
    let run_root = PathBuf::from(std::env::var_os("TMPDIR").expect("the run root"));
    let cargo_home = run_root.join("reference-cargo-home");
    fs::create_dir(&cargo_home).expect("make the reference Cargo home");
    // A workspace whose manifests the derivation did not rewrite packages with
    // the dirty allowance; a clean checkout packages without it.
    for (label, clean) in [("dirty", false), ("clean", true)] {
        let workspace = run_root.join(format!("workspace-{label}"));
        two_crate_workspace(&workspace);
        run_cargo_in_test(
            &cargo,
            &workspace,
            &cargo_home,
            &["generate-lockfile", "--manifest-path", "Cargo.toml"],
        );
        if clean {
            for arguments in [
                vec!["init", "--quiet"],
                vec!["config", "user.name", "Sandbox Test"],
                vec!["config", "user.email", "sandbox@example"],
                vec!["add", "."],
                vec!["commit", "--quiet", "-m", "release"],
            ] {
                let status = Command::new("git")
                    .current_dir(&workspace)
                    .args(&arguments)
                    .status()
                    .expect("run git");
                assert!(status.success(), "git {arguments:?} failed");
            }
            // A gitlink outside the released crates: the copy keeps its empty
            // directory and Cargo packages the release without the dirty
            // allowance.
            fs::create_dir(workspace.join("extern")).expect("make the gitlink's directory");
            let head = {
                let output = Command::new("git")
                    .current_dir(&workspace)
                    .args(["rev-parse", "HEAD"])
                    .output()
                    .expect("run git");
                assert!(output.status.success(), "git rev-parse failed");
                String::from_utf8(output.stdout)
                    .expect("git writes UTF-8")
                    .trim()
                    .to_owned()
            };
            let status = Command::new("git")
                .current_dir(&workspace)
                .args([
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("160000,{head},extern"),
                ])
                .status()
                .expect("run git");
            assert!(status.success(), "git update-index failed");
            let status = Command::new("git")
                .current_dir(&workspace)
                .args(["commit", "--quiet", "-m", "gitlink"])
                .status()
                .expect("run git");
            assert!(status.success(), "git commit failed");
        }
        let target = run_root.join(format!("reference-target-{label}"));
        let reference = reference_archives(&cargo, &workspace, &cargo_home, &target, !clean);
        let archives = crate::self_publish::derive::step5_in_build_sandbox(
            &workspace,
            &cargo,
            &two_crate_members(),
            !clean,
        )
        .expect("step 5 in the build sandbox");
        assert_eq!(
            archives, reference,
            "{label}: the build sandbox's archives differ from the ones that cargo publish would upload"
        );
    }
    println!("BUILD-BYTES-OK");
}

#[test]
fn the_run_sandbox_runs_the_routine_by_its_canonical_executable() {
    let command = super::routine_command(
        Path::new("/nix/store/example-pkgre/bin/pkgre-rust"),
        Path::new("/work/catalog"),
        "rust/v1.0.0",
        true,
        Some("https://github.com/example/workspace"),
    );
    assert_eq!(
        command,
        [
            "/nix/store/example-pkgre/bin/pkgre-rust",
            "self-publish",
            "/work/catalog",
            "rust/v1.0.0",
            "--upload",
            "--git=https://github.com/example/workspace",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>()
    );
    let dry = super::routine_command(
        Path::new("/work/pkgre-rust"),
        Path::new("/work/catalog"),
        "v1.0.0",
        false,
        None,
    );
    assert_eq!(
        dry,
        [
            "/work/pkgre-rust",
            "self-publish",
            "/work/catalog",
            "v1.0.0"
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>(),
        "a dry run names no upload and no git"
    );
}

#[test]
fn a_test_body_must_report_exactly_one_passed_test() {
    let passed = Command::new("sh")
        .arg("-c")
        .arg("printf 'test result: ok. 1 passed; 0 failed\\n'")
        .output()
        .expect("run sh");
    super::body_output(&passed).expect("one passed test");
    let none = Command::new("sh")
        .arg("-c")
        .arg("printf 'test result: ok. 0 passed; 0 failed\\n'")
        .output()
        .expect("run sh");
    let error = format!(
        "{:#}",
        super::body_output(&none).expect_err("a filter that matches nothing passes silently")
    );
    assert!(error.contains("did not run exactly one test"), "{error}");
    let failed = Command::new("sh")
        .arg("-c")
        .arg("printf 'test result: ok. 1 passed\\n'; exit 1")
        .output()
        .expect("run sh");
    let error = format!(
        "{:#}",
        super::body_output(&failed).expect_err("a failed body is reported")
    );
    assert!(error.contains("the test body failed"), "{error}");
}

#[test]
fn the_tests_run_sandbox_binds_the_rehearsal_directories() {
    for name in [
        "PKGRE_REHEARSAL_CATALOG",
        "PKGRE_NATIVE_REHEARSAL_REPOSITORY",
    ] {
        assert!(
            super::REHEARSAL_BIND_VARIABLES.contains(&name),
            "the run sandbox binds {name}"
        );
    }
}

/// Returns whether this process runs in a build sandbox, whose environment
/// names no `/etc`.
fn in_build_sandbox() -> bool {
    std::env::var_os("CARGO_NET_OFFLINE").as_deref() == Some(OsStr::new("true"))
}

#[test]
fn a_root_is_made_with_its_owner_mode_in_one_step() {
    let root = super::make_root(&std::env::temp_dir(), "pkgre-test-root").expect("make a root");
    assert_eq!(
        fs::metadata(&root)
            .expect("inspect the root")
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "the root is made with its owner's mode"
    );
    super::remove_tree(&root).expect("remove the root");
}

#[test]
fn the_home_directory_prefers_home_and_falls_back_to_the_entry() {
    let temporary = Temporary::new("home");
    let home = temporary.path().join("home");
    let entry = temporary.path().join("entry");
    fs::create_dir(&home).expect("make the home");
    fs::create_dir(&entry).expect("make the entry");
    assert_eq!(
        super::home_directory_from(Some(home.clone()), Some(entry.clone())).expect("HOME wins"),
        fs::canonicalize(&home).expect("resolve the home")
    );
    assert_eq!(
        super::home_directory_from(None, Some(entry.clone())).expect("the entry is the fallback"),
        fs::canonicalize(&entry).expect("resolve the entry")
    );
    let error = format!(
        "{:#}",
        super::home_directory_from(None, None).expect_err("neither is a refusal")
    );
    assert!(error.contains("find the home directory"), "{error}");
}

#[test]
fn a_finished_process_is_skipped_but_another_read_failure_is_not() {
    use std::io::{Error, ErrorKind};
    assert!(super::process_ended(&Error::from(ErrorKind::NotFound)));
    assert!(super::process_ended(&Error::from_raw_os_error(
        nix::libc::ESRCH
    )));
    assert!(!super::process_ended(&Error::from(
        ErrorKind::PermissionDenied
    )));
}

#[test]
fn a_signal_names_the_end_of_the_sandbox() {
    use std::os::unix::process::ExitStatusExt as _;
    let killed = std::process::ExitStatus::from_raw(nix::libc::SIGKILL);
    assert!(super::describe_exit(killed).contains("killed by signal 9"));
    let exited = std::process::ExitStatus::from_raw(3 << 8);
    assert!(super::describe_exit(exited).contains("exited with"));
}

#[test]
fn a_failed_build_relays_its_output_indented() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("printf 'out\\n'; printf 'err\\n' >&2; exit 1")
        .output()
        .expect("run sh");
    let error = format!(
        "{:#}",
        super::require_sandbox_success(output).expect_err("a failed command is an error")
    );
    assert!(error.contains("stdout:\n    out"), "{error}");
    assert!(error.contains("stderr:\n    err"), "{error}");
}

/// The variable that makes the missing-bubblewrap helper run.
const FIND_BWRAP_VARIABLE: &str = "PKGRE_SANDBOX_TEST_FIND_BWRAP";

#[test]
fn the_launcher_says_when_no_bwrap_is_on_the_path() {
    for path in ["/nonexistent", "relative"] {
        let mut command = Command::new(std::env::current_exe().expect("the test binary"));
        command
            .args([
                "--exact",
                "self_publish::sandbox::tests::find_bwrap_helper",
                "--nocapture",
            ])
            .env_clear()
            .env("PATH", path)
            .env(FIND_BWRAP_VARIABLE, "1");
        let output = command.output().expect("run the helper");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("no bubblewrap found"),
            "PATH {path:?}: {stdout}"
        );
    }
}

#[test]
fn find_bwrap_helper() {
    if std::env::var_os(FIND_BWRAP_VARIABLE).is_none() {
        return;
    }
    match super::find_bwrap() {
        Ok(path) => println!("FOUND {}", path.display()),
        Err(error) => println!("NOT-FOUND {error:#}"),
    }
}

/// The variable that makes the launcher test's helper run.
const LAUNCH_VARIABLE: &str = "PKGRE_SANDBOX_TEST_LAUNCH";
/// The variable that makes the launcher test an upload.
const LAUNCH_UPLOAD_VARIABLE: &str = "PKGRE_SANDBOX_TEST_LAUNCH_UPLOAD";

#[test]
#[allow(clippy::too_many_lines)]
fn the_launcher_starts_the_routine_and_leaves_nothing_behind() {
    let temporary = Temporary::new("launch");
    let repository = temporary.path().join("catalog");
    fs::create_dir(&repository).expect("make the catalog checkout");
    git(&repository, &["init", "--quiet"]);
    fs::write(repository.join("file"), "a release\n").expect("write a file");
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "--quiet", "-m", "release"]);
    let repository = fs::canonicalize(&repository).expect("resolve the checkout");
    let temp = temporary.path().join("tmp");
    fs::create_dir(&temp).expect("make the launcher's temporary directory");
    let home = temporary.path().join("home");
    fs::create_dir(&home).expect("make the home directory");
    let record = temporary.path().join("arguments");
    let stdin_record = temporary.path().join("stdin");
    let fake = temporary.path().join("bwrap");
    write_executable(
        &fake,
        &format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo 'bubblewrap 0.13.1'
  exit 0
fi
printf '%s\n' "$@" > '{record}'
readlink /proc/self/fd/0 > '{stdin}'
previous=
for argument in "$@"; do
  if [ "$previous" = "--json-status-fd" ]; then status_fd=$argument; fi
  previous=$argument
done
if [ -n "$FAKE_BWRAP_STATUS" ]; then
  eval "printf '%s' '$FAKE_BWRAP_STATUS' >&$status_fd"
  exit 0
fi
exit 1
"#,
            record = record.display(),
            stdin = stdin_record.display()
        ),
    );
    let toolchain_bin = temporary.path().join("toolchain/bin");
    fs::create_dir_all(&toolchain_bin).expect("make the fake toolchain");
    let cargo = toolchain_bin.join("cargo");
    write_executable(&cargo, "#!/bin/sh\nexit 0\n");
    // A concurrent fork can hold a just-written script open for a moment, which
    // makes exec report "Text file busy"; let the writes settle first.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let executable = fs::canonicalize(std::env::current_exe().expect("the test binary"))
        .expect("resolve the test binary");
    let tag = "rust/v1.0.0";
    for (upload, status, expected) in [
        (
            false,
            Some(r#"{"child-pid": 1, "exit-code": 0}"#),
            "LAUNCH-RETURNED 0",
        ),
        (false, None, "LAUNCH-REFUSED"),
        (
            false,
            Some(r#"{"child-pid": 1, "exit-code": 3}"#),
            "LAUNCH-RETURNED 3",
        ),
        (
            true,
            Some(r#"{"child-pid": 1, "exit-code": 0}"#),
            "LAUNCH-RETURNED 0",
        ),
    ] {
        let output = run_launch_helper(
            &repository,
            &temp,
            &home,
            &fake,
            &cargo,
            tag,
            upload,
            status,
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}{stderr}");
        assert!(
            stdout.contains(expected),
            "expected {expected}: {stdout}{stderr}"
        );
        if expected == "LAUNCH-REFUSED" {
            assert!(stdout.contains("was never made"), "{stdout}{stderr}");
        }
        let arguments = fs::read_to_string(&record).expect("read the recorded arguments");
        let arguments = arguments.lines().collect::<Vec<_>>();
        let separator = arguments
            .iter()
            .position(|argument| *argument == "--")
            .expect("the argument separator");
        let command = &arguments[separator + 1..];
        let mut expected_command = vec![
            executable.to_str().expect("a UTF-8 executable"),
            "self-publish",
            repository.to_str().expect("a UTF-8 repository"),
            tag,
        ];
        if upload {
            expected_command.push("--upload");
        }
        assert_eq!(command, expected_command, "the run sandbox's command");
        let stdin = fs::read_to_string(&stdin_record).expect("read the recorded standard input");
        if upload {
            assert!(
                stdin.contains("pipe:"),
                "an upload keeps the launcher's standard input: {stdin}"
            );
        } else {
            assert_eq!(
                stdin.trim(),
                "/dev/null",
                "a dry run gets a null standard input"
            );
        }
        let leftovers = fs::read_dir(&temp)
            .expect("read the temporary directory")
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("pkgre-self-publish-run-")
            })
            .count();
        assert_eq!(leftovers, 0, "the launcher removed its run root");
    }
}

/// Runs the launcher's helper once with the given sandbox inputs.
#[allow(clippy::too_many_arguments)]
fn run_launch_helper(
    repository: &Path,
    temp: &Path,
    home: &Path,
    fake: &Path,
    cargo: &Path,
    tag: &str,
    upload: bool,
    status: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args([
            "--exact",
            "self_publish::sandbox::tests::launch_helper",
            "--nocapture",
        ])
        .env(LAUNCH_VARIABLE, tag)
        .env(REPOSITORY_VARIABLE, repository)
        .env("TMPDIR", temp)
        .env("HOME", home)
        .env("PKGRE_BWRAP", fake)
        .env("PKGRE_CARGO", cargo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if upload {
        command.env(LAUNCH_UPLOAD_VARIABLE, "1");
    }
    if let Some(status) = status {
        command.env("FAKE_BWRAP_STATUS", status);
    }
    let mut child = command.spawn().expect("start the launcher helper");
    let stdin = child.stdin.take();
    let output = child
        .wait_with_output()
        .expect("wait for the launcher helper");
    drop(stdin);
    output
}

#[test]
fn launch_helper() {
    let Some(tag) = std::env::var_os(LAUNCH_VARIABLE) else {
        return;
    };
    let repository = PathBuf::from(std::env::var_os(REPOSITORY_VARIABLE).expect("the repository"));
    let upload = std::env::var_os(LAUNCH_UPLOAD_VARIABLE).is_some();
    match super::launch(
        &repository,
        tag.to_str().expect("a UTF-8 tag"),
        upload,
        None,
    ) {
        Ok(status) => println!("LAUNCH-RETURNED {status}"),
        Err(error) => println!("LAUNCH-REFUSED {error:#}"),
    }
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn the_routine_enters_its_run_sandbox() {
    let _guard = sandbox_test_lock();
    let (output, status) =
        run_in_run_sandbox("self_publish::sandbox::tests::enter_body", "enter", &[]);
    require_body(&output, status, "ENTER-OK");
}

#[test]
fn enter_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("enter")) {
        return;
    }
    // enter marks the descriptors this process holds, joins a session keyring
    // of its own and becomes a child subreaper; a refusal of any of them fails.
    let (_reader, writer) = nix::unistd::pipe().expect("make a pipe");
    let link = fs::read_link(format!("/proc/self/fd/{}", writer.as_raw_fd()))
        .expect("read the pipe's link")
        .to_string_lossy()
        .into_owned();
    let marker = std::env::var_os(MARKER_VARIABLE).expect("the launcher's marker");
    super::enter(&marker).expect("the routine enters its run sandbox");
    let mut command = Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args([
            "--exact",
            "self_publish::sandbox::tests::pipe_child_helper",
            "--nocapture",
        ])
        .env(PIPE_VARIABLE, link)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = super::spawn_command(command)
        .expect("start the child")
        .wait_with_output()
        .expect("wait for the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PIPE-CLOSED"),
        "enter marks the descriptors: {stdout}"
    );
    println!("ENTER-OK");
}

#[test]
fn pipe_child_helper() {
    let Some(link) = std::env::var_os(PIPE_VARIABLE) else {
        return;
    };
    let link = link.to_string_lossy().into_owned();
    let open = fs::read_dir("/proc/self/fd")
        .expect("list the descriptors")
        .filter_map(std::result::Result::ok)
        .any(|entry| fs::read_link(entry.path()).is_ok_and(|path| path.to_string_lossy() == link));
    println!("{}", if open { "PIPE-OPEN" } else { "PIPE-CLOSED" });
}

#[test]
#[ignore = "needs bubblewrap and unprivileged user namespaces"]
fn build_gets_no_standard_input() {
    let _guard = sandbox_test_lock();
    let (output, status) = run_in_run_sandbox(
        "self_publish::sandbox::tests::build_gets_no_standard_input_body",
        "build-stdin",
        &[],
    );
    require_body(&output, status, "BUILD-STDIN-OK");
}

#[test]
fn build_gets_no_standard_input_body() {
    if std::env::var_os(BODY_VARIABLE).as_deref() != Some(OsStr::new("build-stdin")) {
        return;
    }
    let build = BuildRoot::make_in(&std::env::temp_dir(), "pkgre-sandbox-stdin")
        .expect("make a build root");
    let executable = std::env::current_exe().expect("the test binary");
    let command = vec![
        executable.into_os_string(),
        OsString::from("--exact"),
        OsString::from("self_publish::sandbox::tests::stdin_helper"),
        OsString::from("--nocapture"),
    ];
    let stdout = run_build(build.path(), &command).expect("the build sandbox runs the command");
    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("STDIN-EMPTY"),
        "the build sandbox's command gets a null standard input: {stdout}"
    );
    build.remove();
    println!("BUILD-STDIN-OK");
}

#[test]
fn stdin_helper() {
    if !in_build_sandbox() {
        return;
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .expect("read the standard input");
    println!(
        "{}",
        if bytes.is_empty() {
            "STDIN-EMPTY"
        } else {
            "STDIN-CONTENT"
        }
    );
}
