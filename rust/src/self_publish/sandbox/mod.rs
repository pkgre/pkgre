//! The sandboxes that one `self-publish` run makes.
//!
//! `pkgre-rust self-publish` is both the launcher and the routine. Started by a
//! person or a script, it is the launcher: it checks the `bubblewrap`, the
//! pinned Cargo and the catalog checkout, marks every descriptor it did not open
//! close-on-exec, makes a fresh run root, and starts itself again inside a run
//! sandbox. The copy inside is the routine: it verifies that it runs in that
//! sandbox, marks its descriptors, joins a session keyring of its own, becomes a
//! child subreaper, and runs the publishing steps.
//!
//! Step 5, the verified packaging, is the routine's only step that runs package
//! code, and it runs in a build sandbox nested in the run sandbox: its own
//! namespaces including the network, no further user namespaces, only its build
//! root writable, and Cargo as the namespace's PID 1. When that sandbox's
//! `bwrap` returns, the kernel has ended every process of the namespace, so the
//! routine can verify that no package code is left before it reads a token.
//!
//! # The process check
//!
//! The check runs after step 5 in every run and again immediately before an
//! upload reads the token. Part one asks the kernel for the routine's children,
//! and part two reads the sandbox's own `/proc`: it holds PID 1, `bwrap`'s init,
//! and the routine, and nothing else.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread::JoinHandle;

use anyhow::{Context, Result, bail, ensure};
use nix::errno::Errno;
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
use nix::unistd::Pid;
use serde_json::Value;
use tracing::{debug, warn};

use super::isolation::{CERTIFICATE_VARIABLES, ChildEnvironment};

/// The variable through which the launcher tells the routine that it runs in a
/// run sandbox, and which process namespace that sandbox is.
const MARKER_VARIABLE: &str = "PKGRE_SELF_PUBLISH_SANDBOX";
/// The variable that names the `bubblewrap` of the sandboxes.
const BWRAP_VARIABLE: &str = "PKGRE_BWRAP";
/// The variable that names the pinned Cargo.
const CARGO_VARIABLE: &str = "PKGRE_CARGO";
/// The first `bubblewrap` whose setup no link can redirect out of the sandbox.
const MINIMUM_BWRAP: (u32, u32, u32) = (0, 12, 0);
/// The store of a Nix host, which holds the tools and the toolchain.
const STORE: &str = "/nix/store";
/// The system directories that a sandbox shows when they exist.
const SYSTEM_DIRECTORIES: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];
/// The files of the minimal `/etc` that the run sandbox shows, so that name
/// resolution and TLS work without the rest of the host's `/etc`.
const ETC_FILES: [&str; 11] = [
    "resolv.conf",
    "hosts",
    "nsswitch.conf",
    "host.conf",
    "gai.conf",
    "passwd",
    "group",
    "ssl/certs/ca-certificates.crt",
    "ssl/certs/ca-bundle.crt",
    "pki/tls/certs/ca-bundle.crt",
    "ssl/cert.pem",
];
/// The directories that one build root holds.
const BUILD_ROOT_DIRECTORIES: [&str; 5] = ["workspace", "cargo-home", "target", "tmp", "work"];
/// The prefix of a run root below the caller's temporary directory.
const RUN_ROOT_PREFIX: &str = "pkgre-self-publish-run";
/// The prefix of the build root of the start-up probe.
const PROBE_ROOT_PREFIX: &str = "pkgre-self-publish-probe";
/// The subdirectory of a build root that holds the generated manifest of the
/// published siblings of a resumed run.
const PUBLISHED_DIRECTORY: &str = "published";
/// The process ID of the launcher's `bubblewrap`, which a termination signal
/// ends.
static SANDBOX_BWRAP: AtomicI32 = AtomicI32::new(0);
/// Set when a termination signal arrives before the launcher stored its
/// `bubblewrap`'s process ID, so that the launcher ends it once it has.
static PENDING_TERMINATION: AtomicBool = AtomicBool::new(false);
/// Set when the launcher itself kills its `bubblewrap` after a termination
/// signal.
static LAUNCHER_ENDED: AtomicBool = AtomicBool::new(false);

/// Returns the marker's value when this process is the routine inside a run
/// sandbox, and `None` when it is the launcher.
pub(super) fn marker() -> Option<OsString> {
    std::env::var_os(MARKER_VARIABLE)
}

/// Verifies that this process is the routine inside its run sandbox, and
/// prepares it for the run.
///
/// # Errors
///
/// Returns an error when the process does not run in the sandbox that the marker
/// names, when a descriptor cannot be marked, when the kernel refuses a session
/// keyring of the routine's own, or when it refuses to make the routine a child
/// subreaper.
#[cfg(target_os = "linux")]
pub(super) fn enter(marker: &OsStr) -> Result<()> {
    require_in_run_sandbox(marker)?;
    mark_descriptors().context("mark the routine's descriptors close-on-exec")?;
    join_session_keyring().context("give the routine a session keyring of its own")?;
    nix::sys::prctl::set_child_subreaper(true)
        .context("make the routine a child subreaper of its sandbox")?;
    Ok(())
}

/// Refuses to run the routine on a system without the sandboxes it needs.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(target_os = "linux"))]
pub(super) fn enter(_marker: &OsStr) -> Result<()> {
    bail!(
        "the self-publishing routine runs only on Linux, where it can make the sandboxes that keep package code away from the upload"
    )
}

/// Marks every descriptor above 2 close-on-exec, so that nothing the caller left
/// open reaches a child process of the routine or a build sandbox.
///
/// # Errors
///
/// Returns an error when the kernel refuses the call and the walk of
/// `/proc/self/fd` cannot mark a descriptor.
#[allow(unsafe_code)]
pub(super) fn mark_descriptors() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` needs Linux 5.11.
        // SAFETY: the call reads no memory and changes the close-on-exec flag
        // of this process's own descriptors above 2 alone.
        let close_on_exec = nix::libc::c_int::try_from(nix::libc::CLOSE_RANGE_CLOEXEC)
            .expect("the close-on-exec flag of close_range fits in a C int");
        let result = unsafe { nix::libc::close_range(3, u32::MAX, close_on_exec) };
        if result == 0 {
            return Ok(());
        }
        let error = Errno::last();
        if !matches!(
            error,
            Errno::ENOSYS | Errno::EINVAL | Errno::EOPNOTSUPP | Errno::EPERM
        ) {
            return Err(error).context("mark every descriptor above 2 close-on-exec");
        }
    }
    walk_descriptors()
}

/// Marks every descriptor above 2 close-on-exec one at a time.
///
/// # Errors
///
/// Returns an error when `/proc/self/fd` cannot be read or a descriptor cannot be
/// marked.
#[allow(unsafe_code)]
fn walk_descriptors() -> Result<()> {
    for entry in fs::read_dir("/proc/self/fd").context("list the routine's descriptors")? {
        let entry = entry.context("read one descriptor of the routine")?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if fd <= 2 {
            continue;
        }
        // SAFETY: `fcntl` with `F_GETFD` reads the flags of one descriptor and
        // touches no memory; the descriptor belongs to this process.
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
        if flags < 0 {
            // The descriptor of the listing itself has closed already.
            if Errno::last() == Errno::EBADF {
                continue;
            }
            return Err(Errno::last()).with_context(|| format!("inspect descriptor {fd}"));
        }
        if flags & nix::libc::FD_CLOEXEC != 0 {
            continue;
        }
        // SAFETY: `fcntl` with `F_SETFD` sets one flag of one descriptor and
        // touches no memory; the descriptor belongs to this process.
        if unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC) } < 0 {
            return Err(Errno::last())
                .with_context(|| format!("mark descriptor {fd} close-on-exec"));
        }
    }
    Ok(())
}

/// Joins a fresh anonymous session keyring, so that no child of the routine and
/// no build sandbox sees the caller's session keyring or leaves a key in it.
///
/// # Errors
///
/// Returns an error when the kernel refuses the new session keyring.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn join_session_keyring() -> Result<()> {
    /// `KEYCTL_JOIN_SESSION_KEYRING`: joins the named keyring, or a new
    /// anonymous one for a null name.
    const KEYCTL_JOIN_SESSION_KEYRING: nix::libc::c_uint = 1;
    // SAFETY: `keyctl` takes its arguments by value; a null name asks for a new
    // anonymous session keyring, and the call changes nothing but this process's
    // session keyring.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<nix::libc::c_char>(),
        )
    };
    if result < 0 {
        return Err(Errno::last()).context("join a fresh session keyring");
    }
    Ok(())
}

/// Verifies that this process is the routine inside the run sandbox that the
/// launcher made.
///
/// # Errors
///
/// Returns an error when the marker does not name another process namespace,
/// when the routine is not the sandbox init's child, or when the init is not the
/// `bubblewrap` that the launcher found.
#[cfg(target_os = "linux")]
fn require_in_run_sandbox(marker: &OsStr) -> Result<()> {
    let marker = marker
        .to_str()
        .context("the sandbox marker is not valid UTF-8")?;
    ensure!(
        marker.starts_with("pid:[") && marker.ends_with(']'),
        "the sandbox marker {marker:?} is not the process namespace of a launcher; the routine runs only in the sandbox that it starts itself"
    );
    let own = process_namespace()?;
    ensure!(
        own.as_os_str() != OsStr::new(marker),
        "this process runs outside its run sandbox: the marker names its own process namespace, so the routine refuses to run the publishing steps here"
    );
    let parent = nix::unistd::getppid();
    ensure!(
        parent == Pid::from_raw(1),
        "the routine's parent is PID {}, but a run sandbox starts it as the child of PID 1, the sandbox's init",
        parent.as_raw()
    );
    let bwrap = find_bwrap()?;
    let init = fs::read_link("/proc/1/exe").context("read the sandbox init's executable")?;
    let init = PathBuf::from(init.to_string_lossy().trim_end_matches(" (deleted)"));
    ensure!(
        init == bwrap,
        "the sandbox's init is {}, not the bubblewrap {} that the launcher found, so this is not the sandbox that the routine was started in",
        init.display(),
        bwrap.display()
    );
    Ok(())
}

/// Returns the process namespace of this process, as `/proc/self/ns/pid` names
/// it.
///
/// # Errors
///
/// Returns an error when the namespace cannot be read.
#[cfg(target_os = "linux")]
fn process_namespace() -> Result<OsString> {
    Ok(fs::read_link("/proc/self/ns/pid")
        .context("read the process namespace of this process")?
        .into_os_string())
}

/// Runs one `self-publish` as the launcher: it makes a run sandbox, starts the
/// routine in it, waits for it, and returns the routine's exit status.
///
/// # Errors
///
/// Returns an error when `bubblewrap` or the pinned Cargo cannot be found or is
/// unusable, when the catalog checkout cannot be shown in a sandbox, when the
/// standard input of an upload lies below a bound path, when the run root cannot
/// be made, when the run sandbox cannot be started, or when it was never made.
#[cfg(target_os = "linux")]
pub(super) fn launch(repository: &Path, tag: &str, upload: bool, git: Option<&str>) -> Result<i32> {
    mark_descriptors().context("mark the launcher's descriptors close-on-exec")?;
    let host = Host::detect()?;
    let repository = check_repository(repository)?;
    let run_root = RunRoot::make(&std::env::temp_dir(), RUN_ROOT_PREFIX)?;
    let executable =
        fs::canonicalize(std::env::current_exe().context("find the running executable")?)
            .context("resolve the running executable")?;
    let toolchain = toolchain_directory(&host.cargo, cargo_home().as_deref())?;
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
        repository: repository.clone(),
        outside: host.outside(&[toolchain, &host.bwrap, &executable]),
    };
    let mut sources = binds.sources();
    sources.push(run_root.path().to_path_buf());
    check_binds(&home_directory()?, &sources)?;
    if upload {
        check_input_path(standard_input_path().as_deref(), &sources)?;
    }
    let marker = process_namespace()?;
    let environment = run_environment(&marker, run_root.path(), &host);
    let command = routine_command(&executable, &repository, tag, upload, git);
    let (reader, writer) = status_pipe()?;
    let sandbox = RunSandbox {
        root: run_root.path(),
        binds: &binds,
        environment: &environment,
        status_fd: writer.as_raw_fd(),
        command: &command,
    };
    let arguments = sandbox.arguments();
    let terminal = TerminalState::capture();
    install_signal_handlers().context("install the launcher's signal handlers")?;
    nix::sys::prctl::set_child_subreaper(true).context("make the launcher a child subreaper")?;
    debug!(bwrap = %host.bwrap.display(), ?arguments, "starting the run sandbox");
    let mut child = spawn_bwrap(
        &host.bwrap,
        &arguments,
        if upload {
            Stdio::inherit()
        } else {
            Stdio::null()
        },
    )?;
    let child_id = i32::try_from(child.id()).unwrap_or(0);
    SANDBOX_BWRAP.store(child_id, Ordering::Relaxed);
    if PENDING_TERMINATION.swap(false, Ordering::Relaxed) {
        end_the_sandbox(child_id);
    }
    drop(writer);
    let status = child.wait().context("wait for the run sandbox")?;
    SANDBOX_BWRAP.store(0, Ordering::Relaxed);
    // The sandbox's init outlives `bubblewrap` by a moment: `--die-with-parent`'s
    // SIGKILL reaches it, and as the subreaper the launcher reaps it, so the
    // run namespace is empty before the run root goes.
    reap_children().context("wait for the last processes of the run sandbox")?;
    terminal.restore();
    let documents = read_status_documents(reader)?;
    interpret_status(&documents, status)
}

/// A fresh run root, removed when it goes out of scope, so that a refusal after
/// it was made leaves nothing in the caller's temporary directory.
struct RunRoot {
    /// The root itself.
    path: PathBuf,
}

impl RunRoot {
    /// Makes a fresh run root below `parent`.
    ///
    /// # Errors
    ///
    /// Returns an error when the root cannot be made.
    fn make(parent: &Path, prefix: &str) -> Result<Self> {
        Ok(Self {
            path: make_root(parent, prefix)?,
        })
    }

    /// Returns the root itself.
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RunRoot {
    fn drop(&mut self) {
        if let Err(error) = remove_tree(&self.path) {
            warn!(
                root = %self.path.display(),
                error = %format_args!("{error:#}"),
                "could not remove the run root"
            );
        }
    }
}

/// Returns the directory to bind for one Cargo program.
///
/// A Rust toolchain's root is the directory above its `bin` directory when that
/// holds `lib/rustlib`, so that `rustc` finds its libraries too. A root that
/// holds Cargo credentials, or that is the Cargo home, is refused rather than
/// shown in a sandbox.
///
/// # Errors
///
/// Returns an error when the program has no directory, or when the toolchain
/// root must not be bound.
fn toolchain_directory<'a>(cargo: &'a Path, cargo_home: Option<&Path>) -> Result<&'a Path> {
    let bin = cargo
        .parent()
        .with_context(|| format!("{} has no directory", cargo.display()))?;
    let root = if bin.file_name() == Some(OsStr::new("bin"))
        && bin
            .parent()
            .is_some_and(|root| root.join("lib").join("rustlib").is_dir())
    {
        bin.parent().unwrap_or(bin)
    } else {
        bin
    };
    for credentials in ["credentials.toml", "credentials"] {
        ensure!(
            !root.join(credentials).is_file(),
            "the toolchain root {} holds Cargo credentials ({}), so a sandbox does not show it; point PKGRE_CARGO at a toolchain that holds none",
            root.display(),
            credentials
        );
    }
    ensure!(
        cargo_home != Some(root),
        "the toolchain root {} is the Cargo home, so a sandbox does not show it; point PKGRE_CARGO at the toolchain outside the Cargo home",
        root.display()
    );
    Ok(root)
}

/// Returns the Cargo home: `CARGO_HOME`, or the user's `~/.cargo`.
fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home_directory().ok().map(|home| home.join(".cargo")))
}

/// Returns the home directory that a sandbox must not bind: `HOME`,
/// canonicalized, or the user's password entry when `HOME` is unset.
///
/// # Errors
///
/// Returns an error when neither names a directory that resolves.
fn home_directory() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return home_directory_from(Some(PathBuf::from(home)), None);
    }
    let entry = nix::unistd::User::from_uid(nix::unistd::getuid())
        .context("read the user's password entry")?
        .map(|user| user.dir);
    home_directory_from(None, entry)
}

/// Decides [`home_directory`] from `HOME` and the password entry, which a test
/// gives directly.
///
/// # Errors
///
/// Returns an error when neither names a directory that resolves.
fn home_directory_from(home: Option<PathBuf>, entry: Option<PathBuf>) -> Result<PathBuf> {
    let Some(home) = home.or(entry) else {
        bail!(
            "find the home directory: set HOME, or give the user whose uid is {} a home directory in the password database",
            nix::unistd::getuid()
        );
    };
    // A home that does not resolve hides nothing, but it is still compared as
    // the caller gave it; only an unset HOME falls back to the password entry.
    Ok(fs::canonicalize(&home).unwrap_or(home))
}

/// Starts one `bubblewrap` with the launcher's arguments, so that the child
/// starts from the signal dispositions that the launcher leaves.
///
/// # Errors
///
/// Returns an error when `bubblewrap` cannot be started.
fn spawn_bwrap(bwrap: &Path, arguments: &[OsString], stdin: Stdio) -> Result<std::process::Child> {
    let mut command = Command::new(bwrap);
    command.args(arguments).stdin(stdin);
    spawn_command(command)
}

/// Starts one command, so that a test of the launcher starts its child the way
/// the launcher does.
///
/// # Errors
///
/// Returns an error when the command cannot be started.
fn spawn_command(mut command: Command) -> Result<std::process::Child> {
    let program = command.get_program().to_owned();
    command
        .spawn()
        .with_context(|| format!("start {}", Path::new(&program).display()))
}

/// Refuses to make a run sandbox on a system that cannot make one.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(target_os = "linux"))]
pub(super) fn launch(
    _repository: &Path,
    _tag: &str,
    _upload: bool,
    _git: Option<&str>,
) -> Result<i32> {
    bail!(
        "the self-publishing routine runs only on Linux, where bubblewrap can keep package code away from the upload; a dry run needs the same sandbox as an upload"
    )
}

/// Runs one build sandbox with the given command, and returns the command's
/// standard output.
///
/// The build sandbox is nested in the run sandbox, so the routine starts it from
/// inside one. Its command gets a null standard input, and reaches no network,
/// no `/etc`, and nothing but the build root, the store and the toolchain; when
/// `bubblewrap` returns, the kernel has ended every process that the command
/// started.
///
/// # Errors
///
/// Returns an error when `bubblewrap` or the host's paths cannot be found, when
/// the sandbox cannot be made, or when the command exits unsuccessfully; the
/// error carries the command's output, indented.
#[cfg(target_os = "linux")]
pub(super) fn run_build(root: &Path, command: &[OsString]) -> Result<Vec<u8>> {
    let host = Host::detect()?;
    let program = command
        .first()
        .context("a build sandbox runs one command, and none was given")?;
    let toolchain = toolchain_directory(Path::new(program), cargo_home().as_deref())?;
    let outside = host.outside(&[toolchain]);
    let sandbox = BuildSandbox {
        store: host.store.as_deref(),
        system: &host.system,
        outside: &outside,
        path: &host.path,
        root,
        command,
    };
    let arguments = sandbox.arguments();
    let mut running = Command::new(&host.bwrap);
    running
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    debug!(?running, "running a command in a build sandbox");
    let mut child = running
        .spawn()
        .with_context(|| format!("start bubblewrap {}", host.bwrap.display()))?;
    let stdout = read_on_thread(child.stdout.take().context("the sandbox has no output")?);
    let stderr = read_on_thread(
        child
            .stderr
            .take()
            .context("the sandbox has no error stream")?,
    );
    let status = child.wait().context("wait for the build sandbox")?;
    let output = Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    };
    require_sandbox_success(output)
}

/// Refuses to run a build sandbox on a system that cannot make one.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(target_os = "linux"))]
pub(super) fn run_build(_root: &Path, _command: &[OsString]) -> Result<Vec<u8>> {
    bail!(
        "a build sandbox needs Linux, where bubblewrap can hold package code in its own namespaces"
    )
}

/// Runs the pinned Cargo in an empty build sandbox, so that a host that cannot
/// nest one fails before any network read.
///
/// # Errors
///
/// Returns an error when the pinned Cargo cannot be found, the build root cannot
/// be made, or the sandbox cannot run `cargo --version`.
#[cfg(target_os = "linux")]
pub(super) fn probe() -> Result<()> {
    let cargo = cargo_from_environment()?;
    let root = BuildRoot::make_in(&std::env::temp_dir(), PROBE_ROOT_PREFIX)?;
    let command = vec![cargo.into_os_string(), OsString::from("--version")];
    let result = run_build(root.path(), &command)
        .context("the pinned Cargo must run in a build sandbox on this host");
    root.remove();
    result.map(|_| ())
}

/// Refuses the start-up probe on a system that cannot make a build sandbox.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(target_os = "linux"))]
pub(super) fn probe() -> Result<()> {
    bail!(
        "the self-publishing routine needs Linux, where it can make the sandboxes that keep package code away from the upload"
    )
}

/// Checks that the run sandbox holds no process but its init and the routine.
///
/// # Errors
///
/// Returns an error naming every process that the check found.
#[cfg(target_os = "linux")]
pub(super) fn require_alone() -> Result<()> {
    let own = std::process::id();
    let children = children_of_own()?;
    let entries = sandbox_processes()?;
    decide(own, children, &entries)
}

/// Refuses the process check on a system that has no sandbox to check.
///
/// # Errors
///
/// Always returns an error.
#[cfg(not(target_os = "linux"))]
pub(super) fn require_alone() -> Result<()> {
    bail!("the process check reads the process table of a Linux run sandbox")
}

/// The process check of a production run.
pub(super) static ALONE: Alone = Alone;

/// The check that a production run uses.
pub(super) struct Alone;

impl super::publish::ProcessCheck for Alone {
    fn check(&self) -> Result<()> {
        require_alone()
    }
}

/// One process of the run sandbox, as the process check found it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProcessEntry {
    /// Its process ID in the sandbox.
    pub(super) pid: u32,
    /// Its state, such as `S` for sleeping or `Z` for a zombie.
    pub(super) state: char,
    /// The process ID of its parent.
    pub(super) parent: u32,
    /// Its command line, with the arguments separated by spaces.
    pub(super) command: String,
}

/// What the first part of the process check found: the routine's own child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Children {
    /// The routine has no child at all.
    None,
    /// A child has not exited.
    Running,
    /// A child exited and waits to be reaped.
    Exited(u32),
}

/// Decides the process check from what it read.
///
/// # Errors
///
/// Returns an error naming every process that the check found, unless the
/// routine has no child and the sandbox holds only PID 1 and the routine.
fn decide(own: u32, children: Children, entries: &[ProcessEntry]) -> Result<()> {
    let strangers = entries
        .iter()
        .filter(|entry| entry.pid != 1 && entry.pid != own)
        .map(|entry| {
            format!(
                "PID {} (state {}, parent {}, command {:?})",
                entry.pid, entry.state, entry.parent, entry.command
            )
        })
        .collect::<Vec<_>>();
    let child = match children {
        Children::None => None,
        Children::Running => Some("a child that has not exited".to_owned()),
        Children::Exited(pid) => Some(format!("the exited child PID {pid}, which was not reaped")),
    };
    let found = child.into_iter().chain(strangers).collect::<Vec<_>>();
    ensure!(
        found.is_empty(),
        "the run sandbox holds more than its init and the routine: {}; the routine stops rather than read a token while another process could see it",
        found.join(", ")
    );
    Ok(())
}

/// Returns the routine's own child, if it has one.
///
/// # Errors
///
/// Returns an error when the kernel cannot be asked.
#[cfg(target_os = "linux")]
fn children_of_own() -> Result<Children> {
    let flags =
        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT | WaitPidFlag::__WALL;
    match waitid(Id::All, flags) {
        Ok(WaitStatus::StillAlive) => Ok(Children::Running),
        Ok(status) => Ok(Children::Exited(
            status.pid().map_or(0, |pid| pid.as_raw().unsigned_abs()),
        )),
        Err(Errno::ECHILD) => Ok(Children::None),
        Err(error) => Err(error).context("ask the kernel for the routine's children"),
    }
}

/// Returns every process of the sandbox's own `/proc`.
///
/// # Errors
///
/// Returns an error when `/proc` cannot be read.
#[cfg(target_os = "linux")]
fn sandbox_processes() -> Result<Vec<ProcessEntry>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir("/proc").context("list the processes of the run sandbox")? {
        let entry = entry.context("read one process of the run sandbox")?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        // A process may end between the listing and the read; it is gone either
        // way, and nothing of it can act. Every other failure is a process the
        // check must not ignore.
        if let Some(entry) = read_process(pid)? {
            entries.push(entry);
        }
    }
    entries.sort_by_key(|entry| entry.pid);
    Ok(entries)
}

/// Returns what `/proc` says about one process, when it is still there.
#[cfg(target_os = "linux")]
fn read_process(pid: u32) -> Result<Option<ProcessEntry>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if process_ended(&error) => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read the state of PID {pid}"));
        }
    };
    // The command name may hold spaces and parentheses, so the state and the
    // parent follow the last closing parenthesis.
    let parsed = (|| {
        let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
        let state = fields.next()?.chars().next()?;
        let parent = fields.next()?.parse().ok()?;
        Some((state, parent))
    })();
    let Some((state, parent)) = parsed else {
        bail!("read the state of PID {pid}: /proc/{pid}/stat is not in the expected form");
    };
    let raw = match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(raw) => raw,
        Err(error) if process_ended(&error) => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read the command of PID {pid}"));
        }
    };
    let command = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Some(ProcessEntry {
        pid,
        state,
        parent,
        command,
    }))
}

/// Returns whether a `/proc` read failed because the process ended between the
/// listing and the read.
fn process_ended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(nix::libc::ESRCH)
}

/// The directories of one build root, which only its build sandbox may write.
pub(super) struct BuildRoot {
    /// The root itself.
    path: PathBuf,
}

impl BuildRoot {
    /// Makes a fresh build root with its directories below `parent`.
    ///
    /// # Errors
    ///
    /// Returns an error when the root or one of its directories cannot be made.
    pub(super) fn make_in(parent: &Path, prefix: &str) -> Result<Self> {
        let path = make_root(parent, prefix)?;
        for directory in BUILD_ROOT_DIRECTORIES {
            let directory = path.join(directory);
            fs::create_dir(&directory)
                .with_context(|| format!("create build directory {}", directory.display()))?;
        }
        Ok(Self { path })
    }

    /// Returns the root itself.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the copy of the workspace that the build packages.
    pub(super) fn workspace(&self) -> PathBuf {
        self.path.join("workspace")
    }

    /// Returns the Cargo home of the fetches and of the build.
    pub(super) fn cargo_home(&self) -> PathBuf {
        self.path.join("cargo-home")
    }

    /// Returns the target directory of the build.
    pub(super) fn target(&self) -> PathBuf {
        self.path.join("target")
    }

    /// Returns the working directory of the fetches and of the build, outside
    /// the copy.
    pub(super) fn work(&self) -> PathBuf {
        self.path.join("work")
    }

    /// Returns the directory of the generated manifest of the published
    /// siblings.
    pub(super) fn published(&self) -> PathBuf {
        self.path.join(PUBLISHED_DIRECTORY)
    }

    /// Removes the build root, logging a failure rather than stopping the run,
    /// since the build is over either way.
    pub(super) fn remove(&self) {
        if let Err(error) = remove_tree(&self.path) {
            warn!(
                root = %self.path.display(),
                error = %format_args!("{error:#}"),
                "could not remove the build root"
            );
        }
    }
}

/// Makes a fresh directory below `parent` that only its owner may open.
///
/// # Errors
///
/// Returns an error when `parent` cannot be resolved, or when no fresh directory
/// can be made there.
pub(super) fn make_root(parent: &Path, prefix: &str) -> Result<PathBuf> {
    let parent = fs::canonicalize(parent)
        .with_context(|| format!("resolve the temporary root {}", parent.display()))?;
    for sequence in 0..100u32 {
        let path = parent.join(format!("{prefix}-{}-{sequence}", std::process::id()));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("make the directory {}", path.display()));
            }
        }
    }
    bail!(
        "could not make a fresh directory below {} for a sandbox",
        parent.display()
    )
}

/// Removes one directory tree, giving each directory `u+rwx` before it descends,
/// since package code can leave directories that its own user cannot open.
///
/// # Errors
///
/// Returns an error when an entry cannot be removed.
pub(super) fn remove_tree(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", path.display()));
        }
    };
    if !metadata.is_dir() {
        return fs::remove_file(path).with_context(|| format!("remove {}", path.display()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode() | 0o700))
        .with_context(|| format!("open the directory {}", path.display()))?;
    for entry in
        fs::read_dir(path).with_context(|| format!("read the directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("read the directory {}", path.display()))?;
        remove_tree(&entry.path())?;
    }
    fs::remove_dir(path).with_context(|| format!("remove the directory {}", path.display()))
}

/// What the sandboxes of this host bind and run.
pub(super) struct Host {
    /// The `bubblewrap` that makes both sandboxes.
    pub(super) bwrap: PathBuf,
    /// The pinned Cargo.
    pub(super) cargo: PathBuf,
    /// The store, when this host has one.
    pub(super) store: Option<PathBuf>,
    /// The system directories that exist.
    pub(super) system: Vec<PathBuf>,
    /// The canonical form of `PATH`.
    pub(super) path: OsString,
    /// The certificate variables, with canonical values.
    pub(super) certificates: Vec<(OsString, OsString)>,
}

impl Host {
    /// Finds the programs of the sandboxes and what this host lets them see.
    ///
    /// # Errors
    ///
    /// Returns an error when `bubblewrap` or the pinned Cargo cannot be found or
    /// is unusable.
    pub(super) fn detect() -> Result<Self> {
        Ok(Self {
            bwrap: find_bwrap()?,
            cargo: cargo_from_environment()?,
            store: Path::new(STORE).is_dir().then(|| PathBuf::from(STORE)),
            system: SYSTEM_DIRECTORIES
                .iter()
                .filter(|directory| Path::new(directory).is_dir())
                .map(PathBuf::from)
                .collect(),
            path: canonical_path(&std::env::var_os("PATH").unwrap_or_default()),
            certificates: certificate_variables(),
        })
    }

    /// Returns whether one path is visible without a bind of its own.
    fn visible_already(&self, path: &Path) -> bool {
        self.store
            .as_deref()
            .is_some_and(|store| path.starts_with(store))
            || self
                .system
                .iter()
                .any(|directory| path.starts_with(directory))
    }

    /// Returns the paths that a sandbox must bind besides the store and the
    /// system directories, in the order given and without duplicates.
    fn outside(&self, candidates: &[&Path]) -> Vec<PathBuf> {
        let mut outside: Vec<PathBuf> = Vec::new();
        for candidate in candidates {
            if self.visible_already(candidate) || outside.iter().any(|path| path == candidate) {
                continue;
            }
            outside.push((*candidate).to_path_buf());
        }
        // A bind inside another one would make bubblewrap create a path in a
        // directory that the outer bind shows; keep the outer one.
        let outer = outside.clone();
        outside.retain(|path| {
            !outer
                .iter()
                .any(|other| other != path && path.starts_with(other))
        });
        outside
    }
}

/// The binds of one run sandbox.
pub(super) struct RunBinds {
    /// The store, when this host has one.
    pub(super) store: Option<PathBuf>,
    /// The system directories that exist.
    pub(super) system: Vec<PathBuf>,
    /// The minimal `/etc`, as source and destination pairs, in order.
    pub(super) etc: Vec<(PathBuf, PathBuf)>,
    /// The files or directories that the certificate variables name.
    pub(super) certificates: Vec<PathBuf>,
    /// The catalog checkout.
    pub(super) repository: PathBuf,
    /// The pinned toolchain's directory, `bubblewrap` and the routine's
    /// executable, each when it lies outside the store and the system
    /// directories.
    pub(super) outside: Vec<PathBuf>,
}

impl RunBinds {
    /// Returns every path that the run sandbox takes as a bind source.
    pub(super) fn sources(&self) -> Vec<PathBuf> {
        let mut sources = Vec::new();
        sources.extend(self.store.iter().cloned());
        sources.extend(self.system.iter().cloned());
        sources.extend(self.etc.iter().map(|(source, _)| source.clone()));
        sources.extend(self.certificates.iter().cloned());
        sources.push(self.repository.clone());
        sources.extend(self.outside.iter().cloned());
        sources
    }
}

/// One run sandbox, as the launcher starts it.
pub(super) struct RunSandbox<'a> {
    /// The run root, the only writable directory.
    pub(super) root: &'a Path,
    /// What the sandbox binds.
    pub(super) binds: &'a RunBinds,
    /// The environment of the routine.
    pub(super) environment: &'a [(OsString, OsString)],
    /// The descriptor that `bubblewrap` writes its status documents to.
    pub(super) status_fd: RawFd,
    /// The routine's argument list.
    pub(super) command: &'a [OsString],
}

impl RunSandbox<'_> {
    /// Returns the argument list that makes the run sandbox.
    pub(super) fn arguments(&self) -> Vec<OsString> {
        let mut arguments = Vec::new();
        for argument in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--die-with-parent",
            "--dir",
            "/tmp",
        ] {
            arguments.push(OsString::from(argument));
        }
        if let Some(store) = &self.binds.store {
            ro_bind(&mut arguments, store, "--ro-bind");
        }
        for directory in &self.binds.system {
            ro_bind(&mut arguments, directory, "--ro-bind-try");
        }
        for (source, destination) in &self.binds.etc {
            arguments.push(OsString::from("--ro-bind"));
            arguments.push(source.clone().into_os_string());
            arguments.push(destination.clone().into_os_string());
        }
        for certificate in &self.binds.certificates {
            ro_bind(&mut arguments, certificate, "--ro-bind-try");
        }
        ro_bind(&mut arguments, &self.binds.repository, "--ro-bind");
        for path in &self.binds.outside {
            ro_bind(&mut arguments, path, "--ro-bind");
        }
        arguments.push(OsString::from("--bind"));
        arguments.push(self.root.as_os_str().to_owned());
        arguments.push(self.root.as_os_str().to_owned());
        for argument in [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--remount-ro",
            "/",
            "--chdir",
        ] {
            arguments.push(OsString::from(argument));
        }
        arguments.push(self.root.as_os_str().to_owned());
        arguments.push(OsString::from("--clearenv"));
        for (name, value) in self.environment {
            arguments.push(OsString::from("--setenv"));
            arguments.push(name.clone());
            arguments.push(value.clone());
        }
        arguments.push(OsString::from("--json-status-fd"));
        arguments.push(OsString::from(self.status_fd.to_string()));
        arguments.push(OsString::from("--"));
        arguments.extend(self.command.iter().cloned());
        arguments
    }
}

/// One build sandbox, as the routine starts it.
pub(super) struct BuildSandbox<'a> {
    /// The store, when this host has one.
    pub(super) store: Option<&'a Path>,
    /// The system directories that exist.
    pub(super) system: &'a [PathBuf],
    /// The pinned toolchain's directory, when it lies outside the store and the
    /// system directories.
    pub(super) outside: &'a [PathBuf],
    /// The canonical form of `PATH`.
    pub(super) path: &'a OsStr,
    /// The build root, the only writable directory.
    pub(super) root: &'a Path,
    /// The command to run, beginning with its program.
    pub(super) command: &'a [OsString],
}

impl BuildSandbox<'_> {
    /// Returns the argument list that makes the build sandbox.
    pub(super) fn arguments(&self) -> Vec<OsString> {
        let mut arguments = Vec::new();
        for argument in [
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--assert-userns-disabled",
            "--new-session",
            "--die-with-parent",
            "--as-pid-1",
            "--tmpfs",
            "/tmp",
        ] {
            arguments.push(OsString::from(argument));
        }
        if let Some(store) = self.store {
            ro_bind(&mut arguments, store, "--ro-bind");
        }
        for directory in self.system {
            ro_bind(&mut arguments, directory, "--ro-bind-try");
        }
        arguments.push(OsString::from("--bind"));
        arguments.push(self.root.as_os_str().to_owned());
        arguments.push(self.root.as_os_str().to_owned());
        for path in self.outside {
            ro_bind(&mut arguments, path, "--ro-bind");
        }
        for argument in ["--proc", "/proc", "--dev", "/dev", "--remount-ro", "/"] {
            arguments.push(OsString::from(argument));
        }
        arguments.push(OsString::from("--chdir"));
        arguments.push(self.root.join("work").into_os_string());
        arguments.push(OsString::from("--clearenv"));
        let rustc = self
            .command
            .first()
            .and_then(|program| Path::new(program).parent().map(|dir| dir.join("rustc")))
            .unwrap_or_default();
        let environment = [
            ("PATH", self.path.to_owned()),
            ("TMPDIR", self.root.join("tmp").into_os_string()),
            ("CARGO_HOME", self.root.join("cargo-home").into_os_string()),
            ("RUSTC", rustc.into_os_string()),
            ("CARGO_TERM_COLOR", OsString::from("never")),
            ("CARGO_NET_GIT_FETCH_WITH_CLI", OsString::from("false")),
            ("CARGO_NET_OFFLINE", OsString::from("true")),
        ];
        for (name, value) in environment {
            arguments.push(OsString::from("--setenv"));
            arguments.push(OsString::from(name));
            arguments.push(value);
        }
        arguments.push(OsString::from("--"));
        arguments.extend(self.command.iter().cloned());
        arguments
    }
}

/// Adds one read-only bind of a path onto itself.
fn ro_bind(arguments: &mut Vec<OsString>, path: &Path, flag: &str) {
    arguments.push(OsString::from(flag));
    arguments.push(path.as_os_str().to_owned());
    arguments.push(path.as_os_str().to_owned());
}

/// Returns the files of the minimal `/etc`, each with the canonical target of
/// its name as the source, so that a link that leads outside `/etc` still
/// serves.
pub(super) fn etc_files(root: &Path) -> Vec<(PathBuf, PathBuf)> {
    let mut files = Vec::new();
    for name in ETC_FILES {
        let source = root.join("etc").join(name);
        let Ok(source) = fs::canonicalize(&source) else {
            continue;
        };
        if !fs::metadata(&source).is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        files.push((source, Path::new("/etc").join(name)));
    }
    files
}

/// Returns the canonical form of `PATH`, dropping every entry that does not
/// exist, so that an entry outside a sandbox's view finds nothing there and an
/// entry that a profile links into the store still serves.
pub(super) fn canonical_path(value: &OsStr) -> OsString {
    let entries = std::env::split_paths(value)
        .filter_map(|entry| fs::canonicalize(entry).ok())
        .collect::<Vec<_>>();
    std::env::join_paths(entries).unwrap_or_else(|_| value.to_owned())
}

/// Returns the certificate variables that the caller set, with canonical values,
/// so that a file or directory that a variable names can be bound where it lies.
fn certificate_variables() -> Vec<(OsString, OsString)> {
    CERTIFICATE_VARIABLES
        .iter()
        .filter_map(|name| {
            let value = std::env::var_os(name)?;
            let canonical = fs::canonicalize(&value).ok()?;
            Some((OsString::from(*name), canonical.into_os_string()))
        })
        .collect()
}

/// Finds the `bubblewrap` of the sandboxes: `PKGRE_BWRAP` when it is set, and
/// otherwise the first `bwrap` of `PATH`.
///
/// # Errors
///
/// Returns an error when neither names a usable `bubblewrap`.
fn find_bwrap() -> Result<PathBuf> {
    if let Some(configured) = std::env::var_os(BWRAP_VARIABLE) {
        return check_bwrap(Path::new(&configured));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join("bwrap"))
        .find(|candidate| fs::metadata(candidate).is_ok_and(|metadata| metadata.is_file()));
    match found {
        Some(candidate) => check_bwrap(&candidate),
        None => bail!(
            "no bubblewrap found: set {BWRAP_VARIABLE} to an absolute path, as the development shell does, or put bwrap on PATH; the routine runs only where it can make its sandboxes"
        ),
    }
}

/// Checks that one file is a `bubblewrap` that can make the sandboxes.
///
/// # Errors
///
/// Returns an error for a relative or missing path, a file that is not a regular
/// file, a setuid file, a binary that does not report its version, and a version
/// older than the first without a sandbox-setup flaw.
pub(super) fn check_bwrap(candidate: &Path) -> Result<PathBuf> {
    ensure!(
        candidate.is_absolute(),
        "{BWRAP_VARIABLE} must be an absolute path, not {}",
        candidate.display()
    );
    let path = fs::canonicalize(candidate).with_context(|| {
        format!(
            "find bubblewrap at {}: set {BWRAP_VARIABLE} to the bwrap of the development shell",
            candidate.display()
        )
    })?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect bubblewrap {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "bubblewrap is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o4000 == 0,
        "bubblewrap is setuid, which a sandbox must not need: {}",
        path.display()
    );
    let output = Command::new(&path)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", path.display()))?;
    ensure!(
        output.status.success(),
        "bubblewrap {} --version exited with {}",
        path.display(),
        output.status
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let version = parse_version(&text).with_context(|| {
        format!(
            "bubblewrap at {} does not report a version: {:?}",
            path.display(),
            text.trim()
        )
    })?;
    ensure!(
        version >= MINIMUM_BWRAP,
        "bubblewrap {}.{}.{} is older than the first release without a sandbox-setup flaw, {}.{}.{}: set {BWRAP_VARIABLE} to a newer bwrap",
        version.0,
        version.1,
        version.2,
        MINIMUM_BWRAP.0,
        MINIMUM_BWRAP.1,
        MINIMUM_BWRAP.2
    );
    Ok(path)
}

/// Returns the first version number of one text, such as
/// `bubblewrap 0.13.1`'s.
fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    for word in text.split_whitespace() {
        let word = word.trim_start_matches('v');
        let mut parts = word.split('.');
        let Some(major) = parts.next().and_then(|part| part.parse::<u32>().ok()) else {
            continue;
        };
        let Some(minor) = parts.next().and_then(|part| part.parse::<u32>().ok()) else {
            continue;
        };
        let patch = parts
            .next()
            .and_then(|part| {
                part.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(0);
        return Some((major, minor, patch));
    }
    None
}

/// Returns the pinned Cargo, which `PKGRE_CARGO` must name.
///
/// # Errors
///
/// Returns an error when the variable is unset, relative, or names no regular
/// file.
fn cargo_from_environment() -> Result<PathBuf> {
    check_cargo(std::env::var_os(CARGO_VARIABLE).as_deref())
}

/// Checks that one path is the pinned Cargo.
///
/// # Errors
///
/// Returns an error when the path is unset, relative, or not a regular file.
fn check_cargo(configured: Option<&OsStr>) -> Result<PathBuf> {
    let configured = configured.with_context(|| {
        format!(
            "{CARGO_VARIABLE} must name the pinned Cargo, as the development shell sets it: the routine packages a release with the Cargo version that the release records"
        )
    })?;
    let configured = PathBuf::from(configured);
    ensure!(
        configured.is_absolute(),
        "{CARGO_VARIABLE} must be an absolute path, not {}",
        configured.display()
    );
    let path = fs::canonicalize(&configured)
        .with_context(|| format!("find the pinned Cargo at {}", configured.display()))?;
    ensure!(
        fs::symlink_metadata(&path)
            .with_context(|| format!("inspect the pinned Cargo {}", path.display()))?
            .file_type()
            .is_file(),
        "the pinned Cargo is not a regular file: {}",
        path.display()
    );
    Ok(path)
}

/// Requires that no bind source is the home directory, one of its ancestors, or
/// inside another one outside the store and the system directories, so that
/// `bubblewrap` never creates a path in a directory that a build could have
/// prepared.
///
/// # Errors
///
/// Returns an error naming the first pair of paths that may not be bound
/// together.
pub(super) fn check_binds(home: &Path, sources: &[PathBuf]) -> Result<()> {
    for source in sources {
        ensure!(
            !home.starts_with(source),
            "the sandbox does not bind {}: it is the home directory or one of its ancestors",
            source.display()
        );
    }
    for (position, source) in sources.iter().enumerate() {
        for other in &sources[position + 1..] {
            let (inner, outer) = if other.starts_with(source) {
                (other, source)
            } else if source.starts_with(other) {
                (source, other)
            } else {
                continue;
            };
            ensure!(
                inner == outer || visible_without_bind(outer),
                "the sandbox does not bind {} inside {}: bubblewrap would create a path in a directory that a build could have prepared",
                inner.display(),
                outer.display()
            );
        }
    }
    Ok(())
}

/// Returns whether one path is visible in every sandbox without a bind of its
/// own.
fn visible_without_bind(path: &Path) -> bool {
    path.starts_with(STORE)
        || SYSTEM_DIRECTORIES
            .iter()
            .any(|directory| path.starts_with(directory))
}

/// Returns the catalog checkout, canonical and with its Git directories inside
/// it, so that a sandbox that shows the checkout shows all of it.
///
/// # Errors
///
/// Returns an error for a path that does not resolve, a path without a Git
/// repository, a checkout whose Git directory or common directory lies outside
/// it, and a checkout that borrows objects through `objects/info/alternates`.
pub(super) fn check_repository(repository: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(repository).with_context(|| {
        format!(
            "find the catalog checkout {}: the run publishes a release of the repository that holds it",
            repository.display()
        )
    })?;
    ensure!(
        fs::metadata(path.join(".git")).is_ok(),
        "the catalog checkout {} holds no Git repository, so the run cannot read the release tag",
        path.display()
    );
    let environment = ChildEnvironment::plain();
    let directory = git_path(
        &path,
        &["rev-parse", "--path-format=absolute", "--absolute-git-dir"],
        &environment,
    )?;
    let common = git_path(
        &path,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        &environment,
    )?;
    for (what, found) in [
        ("Git directory", &directory),
        ("common Git directory", &common),
    ] {
        ensure!(
            found.starts_with(&path),
            "the catalog checkout {} has its {what} at {}, outside the checkout; a sandbox shows the checkout alone, so the run refuses a linked worktree",
            path.display(),
            found.display()
        );
    }
    let alternates = common.join("objects").join("info").join("alternates");
    ensure!(
        fs::symlink_metadata(&alternates).is_err(),
        "the catalog checkout {} borrows Git objects through {}, which a sandbox does not show",
        path.display(),
        alternates.display()
    );
    Ok(path)
}

/// Returns one Git directory of a checkout, as `git rev-parse` prints it.
///
/// # Errors
///
/// Returns an error when Git cannot run, fails, or prints no path.
fn git_path(
    checkout: &Path,
    arguments: &[&str],
    environment: &ChildEnvironment,
) -> Result<PathBuf> {
    let output = super::git::spawn(
        super::git::command(Some(checkout), arguments, environment, false),
        "read the checkout's Git directories",
    )?;
    super::git::require_success(&output, "read the checkout's Git directories")?;
    let text = String::from_utf8(output.stdout)
        .context("Git printed a Git directory that is not UTF-8")?;
    let path = PathBuf::from(text.trim());
    ensure!(
        !path.as_os_str().is_empty(),
        "Git printed no Git directory for {}",
        checkout.display()
    );
    Ok(path)
}

/// Returns the path that this process's standard input names, when it names one.
fn standard_input_path() -> Option<PathBuf> {
    let link = fs::read_link("/proc/self/fd/0").ok()?;
    link.is_absolute().then_some(link)
}

/// Requires that the standard input of an upload lies outside every bind source,
/// so that the token's pipe is in no sandbox's view.
///
/// # Errors
///
/// Returns an error naming the standard input and the bind source that would
/// show it.
pub(super) fn check_input_path(path: Option<&Path>, sources: &[PathBuf]) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    for source in sources {
        ensure!(
            path != source && !path.starts_with(source),
            "the standard input {} lies below {}, which the run sandbox would show; pipe a token from a directory outside every bound path",
            path.display(),
            source.display()
        );
    }
    Ok(())
}

/// Returns the environment of the routine inside the run sandbox.
fn run_environment(marker: &OsStr, root: &Path, host: &Host) -> Vec<(OsString, OsString)> {
    let mut environment = vec![
        (OsString::from("PATH"), host.path.clone()),
        (OsString::from("TMPDIR"), root.as_os_str().to_owned()),
        (
            OsString::from(CARGO_VARIABLE),
            host.cargo.as_os_str().to_owned(),
        ),
        (
            OsString::from(BWRAP_VARIABLE),
            host.bwrap.as_os_str().to_owned(),
        ),
    ];
    environment.extend(host.certificates.iter().cloned());
    environment.push((OsString::from(MARKER_VARIABLE), marker.to_owned()));
    environment
}

/// Returns the command that the run sandbox runs: the routine's canonical
/// executable, then its arguments, so that `bubblewrap` starts the binary that
/// the launcher found rather than a name that its `PATH` might not hold.
fn routine_command(
    executable: &Path,
    repository: &Path,
    tag: &str,
    upload: bool,
    git: Option<&str>,
) -> Vec<OsString> {
    let mut command = vec![executable.as_os_str().to_owned()];
    command.extend(routine_arguments(repository, tag, upload, git));
    command
}

/// Returns the argument list with which the launcher starts the routine: the
/// same executable and the same arguments, with the catalog checkout's canonical
/// path.
fn routine_arguments(
    repository: &Path,
    tag: &str,
    upload: bool,
    git: Option<&str>,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("self-publish"),
        repository.as_os_str().to_owned(),
        OsString::from(tag),
    ];
    if upload {
        arguments.push(OsString::from("--upload"));
    }
    if let Some(git) = git {
        arguments.push(OsString::from(format!("--git={git}")));
    }
    arguments
}

/// Makes the pipe through which `bubblewrap` reports the sandbox's status; the
/// write end stays open across `bubblewrap`'s exec, and the routine never sees
/// it.
///
/// # Errors
///
/// Returns an error when the pipe cannot be made or its write end marked.
fn status_pipe() -> Result<(fs::File, fs::File)> {
    let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
        .context("make the status pipe of the run sandbox")?;
    // The read end goes with `bubblewrap`'s exec, so that the routine never
    // holds it, and the write end stays open across it, so that `bubblewrap`
    // can write the status documents.
    nix::fcntl::fcntl(
        &writer,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .context("let bubblewrap keep the status pipe")?;
    Ok((fs::File::from(reader), fs::File::from(writer)))
}

/// Reads the status documents that `bubblewrap` wrote.
///
/// # Errors
///
/// Returns an error when the documents cannot be read or are not JSON.
fn read_status_documents(mut reader: impl Read) -> Result<Vec<Value>> {
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .context("read the status documents of the run sandbox")?;
    let mut documents = Vec::new();
    for document in serde_json::Deserializer::from_slice(&bytes).into_iter::<Value>() {
        documents.push(document.context("read a status document of the run sandbox")?);
    }
    Ok(documents)
}

/// Returns the routine's exit status, and refuses a run whose sandbox was never
/// made.
///
/// # Errors
///
/// Returns an error when `bubblewrap` wrote no exit status, naming the usual
/// causes of a sandbox that cannot be made.
fn interpret_status(documents: &[Value], status: std::process::ExitStatus) -> Result<i32> {
    let code = documents
        .iter()
        .rev()
        .find_map(|document| document.get("exit-code"))
        .and_then(Value::as_i64);
    if let Some(code) = code {
        let child = documents
            .iter()
            .find_map(|document| document.get("child-pid"))
            .and_then(Value::as_i64);
        debug!(child_pid = child, exit_code = code, "the run sandbox ended");
        return Ok(i32::try_from(code).unwrap_or(1));
    }
    if documents
        .iter()
        .any(|document| document.get("child-pid").is_some())
    {
        bail!(
            "the run sandbox ended without an exit status: {}",
            describe_exit(status)
        );
    }
    if LAUNCHER_ENDED.swap(false, Ordering::Relaxed) {
        bail!(
            "the launcher ended the run sandbox after a termination signal: {}",
            describe_exit(status)
        );
    }
    bail!(
        "the run sandbox was never made: {} and named no child process. A host makes unprivileged user namespaces only where they are enabled and unrestricted: Ubuntu 23.10 and later restrict them through AppArmor's kernel.apparmor_restrict_unprivileged_userns, and older systems through user.max_user_namespaces or kernel.unprivileged_userns_clone. bubblewrap's own message above says what it found",
        describe_exit(status)
    )
}

/// Describes how one `bubblewrap` ended, naming a signal that killed it.
fn describe_exit(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt as _;
    match status.signal() {
        Some(signal) => format!("bubblewrap was killed by signal {signal}"),
        None => format!("bubblewrap exited with {status}"),
    }
}

/// Waits for every child of the launcher, so that the run namespace has ended
/// before the run root goes.
///
/// # Errors
///
/// Returns an error when the kernel cannot be asked for a child.
fn reap_children() -> Result<()> {
    loop {
        match waitpid(Pid::from_raw(-1), None) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(Errno::ECHILD) => return Ok(()),
            Err(error) => {
                return Err(error).context("wait for the last processes of the run sandbox");
            }
        }
    }
}

/// The terminal's state before a run, which a routine killed at its token prompt
/// may have left changed.
struct TerminalState {
    /// The attributes to restore, when the standard input is a terminal.
    attributes: Option<nix::sys::termios::Termios>,
}

impl TerminalState {
    /// Captures the state of the terminal on standard input.
    fn capture() -> Self {
        let attributes = nix::sys::termios::tcgetattr(std::io::stdin()).ok();
        Self { attributes }
    }

    /// Restores the state, so that a terminal whose echo a killed prompt turned
    /// off serves the caller again.
    fn restore(&self) {
        let Some(attributes) = &self.attributes else {
            return;
        };
        if let Err(error) = nix::sys::termios::tcsetattr(
            std::io::stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            attributes,
        ) {
            warn!(%error, "could not restore the state of the terminal");
        }
    }
}

/// Does nothing, for `SIGINT` and `SIGQUIT`.
///
/// A handler rather than `SIG_IGN`, because an ignored signal stays ignored
/// across `execve`: with a handler, `bubblewrap` and the routine start with both
/// at their default, so that the terminal's interrupt reaches them.
extern "C" fn keep_running(_signal: nix::libc::c_int) {}

/// Ends the run sandbox on `SIGTERM` or `SIGHUP`, which ends every sandbox in it.
extern "C" fn end_sandbox(_signal: nix::libc::c_int) {
    let pid = SANDBOX_BWRAP.load(Ordering::Relaxed);
    if pid > 0 {
        end_the_sandbox(pid);
    } else {
        // The launcher has not stored `bubblewrap`'s process ID yet; it ends it
        // once it has.
        PENDING_TERMINATION.store(true, Ordering::Relaxed);
    }
}

/// Ends one `bubblewrap` with `SIGKILL`; only async-signal-safe calls belong
/// here, since a handler calls it.
fn end_the_sandbox(pid: i32) {
    LAUNCHER_ENDED.store(true, Ordering::Relaxed);
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    );
}

/// Installs the launcher's signal handlers.
///
/// # Errors
///
/// Returns an error when the kernel refuses a handler.
#[allow(unsafe_code)]
fn install_signal_handlers() -> Result<()> {
    let mask = nix::sys::signal::SigSet::empty();
    for signal in [
        nix::sys::signal::Signal::SIGINT,
        nix::sys::signal::Signal::SIGQUIT,
    ] {
        // SAFETY: the handler is an `extern "C"` function that does nothing, and
        // the action holds no pointer that outlives the call.
        unsafe {
            nix::sys::signal::sigaction(
                signal,
                &nix::sys::signal::SigAction::new(
                    nix::sys::signal::SigHandler::Handler(keep_running),
                    nix::sys::signal::SaFlags::empty(),
                    mask,
                ),
            )
        }
        .with_context(|| format!("install the handler of {signal}"))?;
    }
    for signal in [
        nix::sys::signal::Signal::SIGTERM,
        nix::sys::signal::Signal::SIGHUP,
    ] {
        // SAFETY: the handler calls only async-signal-safe functions, and the
        // action holds no pointer that outlives the call.
        unsafe {
            nix::sys::signal::sigaction(
                signal,
                &nix::sys::signal::SigAction::new(
                    nix::sys::signal::SigHandler::Handler(end_sandbox),
                    nix::sys::signal::SaFlags::empty(),
                    mask,
                ),
            )
        }
        .with_context(|| format!("install the handler of {signal}"))?;
    }
    Ok(())
}

/// Reads one stream of a child process on its own thread.
fn read_on_thread(mut stream: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        bytes
    })
}

/// Returns the output of one successful sandbox, and an error whose output is
/// indented so that a relayed line cannot pass for a record of the routine's own.
///
/// # Errors
///
/// Returns an error naming the exit status and the last bytes of the output when
/// the command failed.
fn require_sandbox_success(output: Output) -> Result<Vec<u8>> {
    if !output.status.success() {
        bail!(
            "the build sandbox exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            indent(&bounded_lossy(&output.stdout)),
            indent(&bounded_lossy(&output.stderr))
        );
    }
    Ok(output.stdout)
}

/// Indents every line of one text, so that no relayed line can pass for a record
/// of the routine's own.
fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Keeps the last bytes of a failed command's output in its error.
fn bounded_lossy(bytes: &[u8]) -> String {
    const LIMIT: usize = 16 * 1024;
    let start = bytes.len().saturating_sub(LIMIT);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// The variable that marks a test body that runs inside a run sandbox.
#[cfg(test)]
pub(crate) const TEST_BODY_VARIABLE: &str = "PKGRE_SELF_PUBLISH_SANDBOX_TEST";
/// The variables that name directories of the ignored live tests, which the
/// tests' run sandbox binds read-only as the launcher binds the catalog.
#[cfg(test)]
const REHEARSAL_BIND_VARIABLES: [&str; 2] = [
    "PKGRE_REHEARSAL_CATALOG",
    "PKGRE_NATIVE_REHEARSAL_REPOSITORY",
];

/// Runs one test body inside a run sandbox made from the launcher's arguments,
/// so that the ignored tests of step 5 against crates.io run as production does.
///
/// The body is a test of this binary, re-run with `--exact`; the environment
/// variables that `forwarded` names are passed into the sandbox, since
/// production clears the environment.
///
/// # Errors
///
/// Returns an error when the sandbox cannot be made or the body fails.
#[cfg(test)]
pub(crate) fn run_test_body(body: &str, forwarded: &[&str]) -> Result<()> {
    let host = Host::detect()?;
    let repository = make_root(&std::env::temp_dir(), "pkgre-test-repository")?;
    let root = make_root(&std::env::temp_dir(), "pkgre-test-run")?;
    let executable = fs::canonicalize(std::env::current_exe()?).context("find the test binary")?;
    let toolchain = host
        .cargo
        .parent()
        .with_context(|| format!("the pinned Cargo {} has no directory", host.cargo.display()))?;
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("the crate's directory has no parent")?;
    let mut outside = host.outside(&[toolchain, &host.bwrap, &executable, checkout]);
    // A linked worktree keeps its Git directories outside itself; the tests
    // bind them read-only so that a clone works, where production refuses such
    // a checkout.
    if let Ok(common) = git_path(
        checkout,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        &ChildEnvironment::plain(),
    ) {
        if !common.starts_with(checkout) && !outside.iter().any(|path| path == &common) {
            outside.push(common);
        }
    }
    for name in REHEARSAL_BIND_VARIABLES {
        if let Some(path) = std::env::var_os(name) {
            let path = fs::canonicalize(&path).with_context(|| format!("resolve {name}"))?;
            if !outside.iter().any(|bound| bound == &path) {
                outside.push(path);
            }
        }
    }
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
        repository: repository.clone(),
        outside,
    };
    let marker = process_namespace()?;
    let mut environment = run_environment(&marker, &root, &host);
    environment.push((OsString::from(TEST_BODY_VARIABLE), OsString::from("1")));
    for name in forwarded {
        if let Some(value) = std::env::var_os(name) {
            environment.push((OsString::from(*name), value));
        }
    }
    let command = vec![
        executable.into_os_string(),
        OsString::from("--exact"),
        OsString::from(body),
        OsString::from("--nocapture"),
    ];
    mark_descriptors().context("mark the test launcher's descriptors close-on-exec")?;
    let (reader, writer) = status_pipe()?;
    let sandbox = RunSandbox {
        root: &root,
        binds: &binds,
        environment: &environment,
        status_fd: writer.as_raw_fd(),
        command: &command,
    };
    let arguments = sandbox.arguments();
    let mut running = Command::new(&host.bwrap);
    running
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = spawn_command(running)?;
    drop(writer);
    let output = child
        .wait_with_output()
        .context("wait for the run sandbox")?;
    let documents = read_status_documents(reader)?;
    let status = interpret_status(&documents, output.status)?;
    let body = body_output(&output)?;
    if let Err(error) = remove_tree(&root) {
        debug!(%error, "the test run root is removed later");
    }
    if let Err(error) = remove_tree(&repository) {
        debug!(%error, "the test repository is removed later");
    }
    ensure!(
        status == 0,
        "the test body failed in its run sandbox (status {status}):\n{body}"
    );
    Ok(())
}

/// Prints one test body's output to the outer test's own output and requires
/// that it ran exactly one test and passed.
///
/// A filter that matches no test exits successfully with `0 passed`, so the
/// status alone would let a renamed body pass silently.
///
/// # Errors
///
/// Returns an error when the output does not report exactly one passed test, or
/// when the body failed; the error carries the output.
#[cfg(test)]
fn body_output(output: &Output) -> Result<String> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    print!("{stdout}");
    eprint!("{stderr}");
    ensure!(
        stdout.contains("test result: ok. 1 passed"),
        "the test body did not run exactly one test, so its filter matched nothing: {stdout}{stderr}"
    );
    ensure!(
        output.status.success(),
        "the test body failed ({}): {stdout}{stderr}",
        output.status
    );
    Ok(format!("{stdout}{stderr}"))
}

#[cfg(test)]
#[path = "../../../tests/unit/self_publish/sandbox/mod.rs"]
mod tests;
