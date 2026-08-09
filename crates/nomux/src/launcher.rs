//! Starts a session daemon as a direct child of the relay.
//!
//! Nothing here tries to leave the login session the relay was started in: `setsid(2)` and
//! the daemon's own fork are the whole of the detachment, and host policy at logout is the
//! host's to decide (`startup::detach_from_controlling_terminal`).

use std::env;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::process::CommandExt;
use std::process::{ChildStderr, Command, Stdio};

use crate::rundir::SpawnLock;

/// Starts the daemon while `spawn_lock` continues to serialise this session id.
///
/// # Errors
///
/// Propagates command construction and process-spawn failures.
pub(crate) fn spawn_daemon(
    session_id: &str,
    label: Option<&str>,
    spawn_lock: &SpawnLock,
) -> io::Result<Option<ChildStderr>> {
    let lock_fd = spawn_lock.raw_fd();
    let mut command = direct_command(session_id, label, lock_fd)?;
    configure_stdio_and_lock(&mut command, lock_fd);
    command.spawn().map(|mut child| child.stderr.take())
}

/// Execs the exact inode this relay is already running rather than whatever the install
/// path names by the time the child gets there — between the two loads that path decides
/// what the daemon *is*. `arg0` puts the ordinary name back on the command line, so what
/// `ps` shows is the program rather than the link it was reached through.
fn direct_command(session_id: &str, label: Option<&str>, lock_fd: i32) -> io::Result<Command> {
    let mut command = Command::new("/proc/self/exe");
    command.arg0(env::current_exe()?);
    daemon_args(&mut command, session_id, label, lock_fd);
    Ok(command)
}

fn daemon_args(command: &mut Command, session_id: &str, label: Option<&str>, lock_fd: i32) {
    command
        .arg("daemon")
        .arg(session_id)
        .arg("--lock-fd")
        .arg(lock_fd.to_string());
    let label = label
        .map(crate::sanitize::sanitize_label)
        .filter(|label| !label.is_empty());
    if let Some(label) = label.as_deref() {
        command.arg("--label").arg(label);
    }
}

fn configure_stdio_and_lock(command: &mut Command, lock_fd: i32) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // The caller reads this pipe only if publication misses its deadline.
        .stderr(Stdio::piped());

    let pre_exec = move || -> io::Result<()> {
        rustix::process::setsid()?;
        // `SpawnLock` opens `CLOEXEC`. Clear it only in the forked child, so the descriptor
        // survives the exec below. The daemon validates it against the current lock path and
        // restores `CLOEXEC` before the shell.
        // SAFETY: `lock_fd` belongs to the lock held across `Command::spawn` by the caller.
        let lock = unsafe { BorrowedFd::borrow_raw(lock_fd) };
        rustix::io::fcntl_setfd(lock, rustix::io::FdFlags::empty())?;
        Ok(())
    };
    // SAFETY: the closure runs after fork and calls only async-signal-safe operations.
    unsafe {
        command.pre_exec(pre_exec);
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    /// The caller's label reaches `exec` already cut and already stripped of the terminal
    /// control it arrived with — the daemon records what it is given, so the bound and the
    /// escaping both have to be spent on this side of the handoff.
    #[test]
    fn launcher_labels_are_bounded_before_the_daemon_exec() {
        let label = format!("\u{1b}]0;ignored\u{7}  $HOME/{}", "é".repeat(200));
        let expected = crate::sanitize::sanitize_label(&label);
        assert!(expected.len() <= crate::sanitize::MAX_LABEL_LEN);
        assert!(label.len() > crate::sanitize::MAX_LABEL_LEN, "cut nothing");

        let direct = direct_command("session", Some(&label), 19).unwrap();
        assert_eq!(
            direct.get_args().last().and_then(OsStr::to_str),
            Some(&*expected)
        );
    }

    #[test]
    fn the_daemon_command_line_carries_the_lock_and_the_raw_label() {
        let command = direct_command("session", Some("cost $5"), 23).unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            ["daemon", "session", "--lock-fd", "23", "--label", "cost $5"]
        );
    }
}
