//! Scratch directories for the unit tests inside this binary.
//!
//! Entirely `#[cfg(test)]`, so none of it is compiled into a shipped build.
//!
//! The integration tests get `CARGO_TARGET_TMPDIR` and a run root of their own
//! (`tests/harness/mod.rs`). Cargo sets that variable for integration tests and
//! benches only — measured, not assumed: `option_env!` reads `None` from here — so
//! the unit tests in `src/` have nowhere but `env::temp_dir()`, which is the
//! developer's ambient `$TMPDIR` shared with everything else on the host. That
//! makes both halves of the harness's naming argument load-bearing here rather than
//! merely tidy, and neither of them was done.
//!
//! What that cost, measured before this existed: `/tmp/nomux-226959-rundir-symlink`
//! and `/tmp/nomux-615195-rundir-mode` were still there a day after the run that
//! made them, because the cleanup sat on the success path and those runs had
//! failed. The second was left at mode `d-wx------`, which its own owner cannot
//! open — and which `remove_dir_all` therefore cannot empty either, so it would
//! have survived any amount of tidying up that did not know to repair it first.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Mode a directory has to be in before it can be removed: readable to list, and
/// executable to reach what is listed.
const REMOVABLE: u32 = 0o700;

/// A directory of this process's own, emptied and removed however the test ends.
///
/// On drop rather than at the end of the test body, which is the whole point: an
/// assertion that fires is exactly the case that used to leave one behind.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    /// An empty scratch directory named for `name` and for this process.
    ///
    /// The wipe on the way in stays even though the name carries this process's pid,
    /// for the reason the integration harness gives: pids are reused, and a run that
    /// crashed hard between the sweep and here leaves its directory behind.
    pub(crate) fn new(name: &str) -> Self {
        sweep_finished_runs();
        let dir = std::env::temp_dir().join(format!("nomux-{}-{name}", std::process::id()));
        make_removable(&dir);
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(&dir).expect("create a scratch directory");
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, tail: &str) -> PathBuf {
        self.0.join(tail)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        make_removable(&self.0);
        drop(fs::remove_dir_all(&self.0));
    }
}

/// Puts `dir` and every directory under it back into a mode that can be removed.
///
/// The mode tests deliberately leave directories nobody can open, including their
/// owner, and `remove_dir_all` has to read a directory to empty it. Restoring here
/// rather than at the end of the test body is what makes it happen on the path that
/// matters — the one where an assertion has already fired.
///
/// Symlinks are not followed: `read_dir` reports a link's own type, so a link
/// planted in place of a run directory is removed as the link it is and whatever it
/// points at is left alone. Which is the same promise `ensure_dir_at` makes, and it
/// would be an odd thing for the test's own cleanup to break.
fn make_removable(dir: &Path) {
    drop(fs::set_permissions(
        dir,
        fs::Permissions::from_mode(REMOVABLE),
    ));
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            make_removable(&entry.path());
        }
    }
}

/// Removes the scratch directories of test processes that have exited.
///
/// The pid in the name is what lets two runs proceed at once, and it is equally
/// what stops a run from reusing what the last one left. A directory goes only once
/// `/proc` says its process is gone — a live pid is either this one or a run in
/// flight, and taking either away is the exact fault the naming exists to prevent.
fn sweep_finished_runs() {
    let temp = std::env::temp_dir();
    let Ok(entries) = fs::read_dir(&temp) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let owner = name
            .to_string_lossy()
            .strip_prefix("nomux-")
            .and_then(|tail| tail.split_once('-'))
            .and_then(|(pid, _)| pid.parse::<u32>().ok());
        if owner.is_some_and(|pid| !Path::new(&format!("/proc/{pid}")).exists()) {
            let path = entry.path();
            make_removable(&path);
            drop(fs::remove_dir_all(&path));
        }
    }
}
