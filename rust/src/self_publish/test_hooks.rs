//! What one test observes and changes in one run.
//!
//! Nothing here is built outside `cfg(test)`. Every test runs on a thread of
//! its own, so the state is thread-local and tests that run in parallel never
//! see each other's hooks.

use std::cell::RefCell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// A point of one run at which a test can change a checkout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Point {
    /// After the native contract accepted the checkout, before the
    /// derivation's clean check.
    AfterNativeContract,
    /// After the derivation packaged the release, before the clean check that a
    /// native tag gets.
    AfterPackaging,
    /// Before step 5's verified packaging copies the checkout.
    BeforeVerifiedCopy,
    /// After step 5 copied the checkout, before the copy's clean check.
    VerifiedCopy,
}

/// One action that a test runs at one point of a run.
type Action = Box<dyn FnOnce(&Path)>;

/// What one test thread recorded and registered.
#[derive(Default)]
struct State {
    /// The arguments of each packaging command, in the order they ran.
    arguments: Vec<Vec<OsString>>,
    /// The checkout that the last derivation of this thread worked in.
    checkout: Option<PathBuf>,
    /// One action to run at one point of the next run.
    point: Option<(Point, Action)>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Forgets what an earlier run of the same test recorded.
pub(crate) fn clear() {
    STATE.with_borrow_mut(|state| *state = State::default());
}

/// Records the arguments of one packaging command.
pub(crate) fn record_arguments(arguments: &[OsString]) {
    STATE.with_borrow_mut(|state| state.arguments.push(arguments.to_vec()));
}

/// Returns the recorded packaging commands and forgets them.
pub(crate) fn take_arguments() -> Vec<Vec<OsString>> {
    STATE.with_borrow_mut(|state| std::mem::take(&mut state.arguments))
}

/// Records the checkout that a derivation fetched and packaged.
pub(crate) fn record_checkout(checkout: &Path) {
    STATE.with_borrow_mut(|state| state.checkout = Some(checkout.to_path_buf()));
}

/// Returns the checkout that the last derivation of this thread worked in.
pub(crate) fn checkout() -> Option<PathBuf> {
    STATE.with_borrow(|state| state.checkout.clone())
}

/// Runs `action` when a later run of this thread reaches `point`, once.
pub(crate) fn on(point: Point, action: impl FnOnce(&Path) + 'static) {
    STATE.with_borrow_mut(|state| state.point = Some((point, Box::new(action))));
}

/// Runs the action that a test registered for `point`, and forgets it.
pub(crate) fn run(point: Point, path: &Path) {
    let action = STATE.with_borrow_mut(|state| {
        let held = state.point.take();
        match held {
            Some((held, action)) if held == point => Some(action),
            other => {
                state.point = other;
                None
            }
        }
    });
    if let Some(action) = action {
        action(path);
    }
}
