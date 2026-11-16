//! Integration tests of `pkgre install`, which run the built binary.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

/// The text that `pkgre install` writes to an absent configuration file.
const ADDED_TEXT: &str = "[registries.pkgre]\nindex = \"sparse+https://rust.pkg.re/\"\n";

/// The binary under test, with `CARGO_HOME` pointed at `cargo_home`.
fn pkgre(cargo_home: &Path) -> Command {
    let mut command = binary();
    command.env("CARGO_HOME", cargo_home);
    command
}

/// The binary under test, with an inherited environment except for the
/// variable that would override the index it configures.
fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pkgre"));
    command.env_remove("CARGO_REGISTRIES_PKGRE_INDEX");
    command
}

/// The output of `command`.
fn run(command: &mut Command) -> Output {
    command.output().expect("the pkgre binary runs")
}

/// The standard output of `output`, as text.
fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The standard error of `output`, as text.
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn install_creates_the_configuration_file() {
    let home = TempDir::new().expect("a temporary directory");
    let output = run(pkgre(home.path()).arg("install"));

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(home.path().join("config.toml")).expect("the configuration file"),
        ADDED_TEXT
    );
    let printed = stdout(&output);
    assert!(printed.contains("added the pkgre registry"), "{printed}");
    assert!(printed.contains("config.toml"), "{printed}");
    assert!(printed.contains("registry = \"pkgre\""), "{printed}");
}

#[test]
fn a_second_run_changes_nothing() {
    let home = TempDir::new().expect("a temporary directory");
    assert!(run(pkgre(home.path()).arg("install")).status.success());
    let file = home.path().join("config.toml");
    let before = fs::read(&file).expect("the configuration file");

    let output = run(pkgre(home.path()).arg("install"));

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fs::read(&file).expect("the configuration file"), before);
    let printed = stdout(&output);
    assert!(printed.contains("nothing to do"), "{printed}");
}

#[test]
fn config_wins_over_config_toml() {
    let home = TempDir::new().expect("a temporary directory");
    let config = home.path().join("config");
    let config_toml = home.path().join("config.toml");
    fs::write(&config, "[build]\njobs = 4\n").expect("the config file");
    fs::write(&config_toml, "[build]\njobs = 8\n").expect("the config.toml file");

    let output = run(pkgre(home.path()).arg("install"));

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(&config).expect("the config file"),
        format!("[build]\njobs = 4\n\n{ADDED_TEXT}")
    );
    assert_eq!(
        fs::read_to_string(&config_toml).expect("the config.toml file"),
        "[build]\njobs = 8\n"
    );
    let printed = stderr(&output);
    assert!(printed.contains("both"), "{printed}");
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_refused() {
    use std::os::unix::fs::symlink;

    let home = TempDir::new().expect("a temporary directory");
    let store = TempDir::new().expect("a temporary directory");
    let target = store.path().join("cargo-config.toml");
    fs::write(&target, "[build]\njobs = 4\n").expect("the configuration file");
    symlink(&target, home.path().join("config.toml")).expect("a symbolic link");

    let output = run(pkgre(home.path()).arg("install"));

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fs::read_to_string(&target).expect("the configuration file"),
        "[build]\njobs = 4\n"
    );
    let printed = stderr(&output);
    assert!(printed.contains("symbolic link"), "{printed}");
    assert!(printed.contains("[registries.pkgre]"), "{printed}");
}

#[test]
fn a_different_index_is_refused() {
    let home = TempDir::new().expect("a temporary directory");
    let file = home.path().join("config.toml");
    let text = "[registries.pkgre]\nindex = \"https://example.invalid/\"\n";
    fs::write(&file, text).expect("the configuration file");

    let output = run(pkgre(home.path()).arg("install"));

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fs::read_to_string(&file).expect("the configuration file"),
        text
    );
    let printed = stderr(&output);
    assert!(printed.contains("https://example.invalid/"), "{printed}");
    assert!(printed.contains("sparse+https://rust.pkg.re/"), "{printed}");
}

#[test]
fn a_dry_run_writes_nothing() {
    let directory = TempDir::new().expect("a temporary directory");
    let home = directory.path().join("cargo-home");

    let output = run(pkgre(&home).arg("install").arg("--dry-run"));

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!home.exists(), "a dry run created the Cargo home");
    let printed = stdout(&output);
    assert!(printed.contains("dry run"), "{printed}");
    assert!(printed.contains(ADDED_TEXT.trim_end()), "{printed}");
}

#[test]
fn a_relative_cargo_home_is_resolved() {
    let directory = TempDir::new().expect("a temporary directory");
    let mut command = binary();
    command.env("CARGO_HOME", "relative-cargo-home");
    command.current_dir(directory.path());
    command.arg("install");

    let output = run(&mut command);

    assert!(output.status.success(), "{}", stderr(&output));
    let file = directory
        .path()
        .join("relative-cargo-home")
        .join("config.toml");
    assert_eq!(
        fs::read_to_string(&file).expect("the configuration file"),
        ADDED_TEXT
    );
}
