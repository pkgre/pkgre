#![forbid(unsafe_code)]
//! The `pkgre` command-line tool.
//!
//! This module parses the arguments and turns the results of the commands
//! into output and exit codes; the commands themselves live in their own
//! modules.

mod install;

use std::process::ExitCode;

use clap::{Arg, ArgAction, Command};

use crate::install::{Outcome, State};

/// The exit code that `clap` uses for a usage error.
const USAGE_ERROR: u8 = 2;

fn main() -> ExitCode {
    let matches = match command().try_get_matches() {
        Ok(matches) => matches,
        Err(error) => error.exit(),
    };

    match matches.subcommand() {
        Some(("install", arguments)) => match install::run(arguments.get_flag("dry-run")) {
            Ok(outcome) => report(&outcome),
            Err(error) => fail(&error),
        },
        Some(_) | None => ExitCode::from(USAGE_ERROR),
    }
}

/// The command line.
fn command() -> Command {
    Command::new("pkgre")
        .about("Use the pkgre curated package registries")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("install")
                .about("Add the pkgre registry to the user's Cargo configuration")
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .help("Print the result and the file it would write, and write nothing")
                        .action(ArgAction::SetTrue),
                ),
        )
}

/// Prints what happened and returns the exit code for it.
fn report(outcome: &Outcome) -> ExitCode {
    for note in &outcome.notes {
        eprintln!("pkgre: warning: {note}");
    }
    match &outcome.state {
        State::AlreadyConfigured => {
            println!(
                "{} already configures the pkgre registry; nothing to do",
                outcome.file.display()
            );
            ExitCode::SUCCESS
        }
        State::Added { text } => report_added(outcome, text),
        State::Refused(refusal) => {
            eprintln!("pkgre: leaving {} alone", outcome.file.display());
            eprintln!();
            eprintln!("{}", refusal.explain());
            ExitCode::FAILURE
        }
    }
}

/// Prints the result of adding the registry, or the text that a dry run would
/// have written.
fn report_added(outcome: &Outcome, text: &str) -> ExitCode {
    let file = outcome.file.display();
    if outcome.dry_run {
        println!("dry run: {file} would become:");
        println!();
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
        return ExitCode::SUCCESS;
    }

    println!("added the pkgre registry to {file}");
    println!();
    println!("Dependencies can now name the registry:");
    println!();
    println!("    anyhow = {{ version = \"1.0\", registry = \"pkgre\" }}");
    println!();
    println!("and programs install with:");
    println!();
    println!("    cargo install --registry pkgre NAME");
    ExitCode::SUCCESS
}

/// Prints an error, with the chain of causes that led to it.
fn fail(error: &anyhow::Error) -> ExitCode {
    eprintln!("pkgre: {error:#}");
    ExitCode::FAILURE
}
