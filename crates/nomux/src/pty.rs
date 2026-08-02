//! PTY allocation and child spawn.
//!
//! The session runs whatever a plain `ssh host` would have run, because nomux is
//! already inside an SSH session and inherits its setup rather than reconstructing
//! it (`IMPLEMENTATION.md` § 6.1.1). The one thing that must be done by hand is the
//! dash-prefixed `argv[0]`, which is what makes it a *login* shell.

use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nomux_proto::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use crate::passwd;

/// What the session's child needs to know at spawn.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spawn<'a> {
    /// Value for the child's `TERM`, taken from the creating `Hello`.
    pub term: &'a str,
    /// Initial dimensions, applied before the child can observe them.
    pub win: WinSize,
    /// Exported as `NOMUX_SESSION`.
    pub session_id: &'a str,
    /// Working directory for the child. The daemon itself has already moved to
    /// `/` (`IMPLEMENTATION.md` § 6.2), so this must be passed explicitly or the
    /// shell would start there instead of in the user's home.
    pub cwd: &'a Path,
    /// `ssh-agent` socket to export as `SSH_AUTH_SOCK`, when forwarding is on.
    pub agent_sock: Option<&'a Path>,
}

/// How long the child's group has to act on `SIGHUP` before `SIGKILL` follows.
const TERM_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Interval between liveness checks while waiting out [`TERM_GRACE`].
const TERM_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// A running session: the PTY master plus the child holding its slave.
#[derive(Debug)]
pub(crate) struct Pty {
    master: OwnedFd,
    child: Child,
}

impl Pty {
    /// Allocates a PTY and spawns the user's login shell on its slave.
    ///
    /// # Errors
    ///
    /// Propagates failures from `openpt`, `grantpt`, `unlockpt`, opening the slave,
    /// or spawning the shell.
    pub(crate) fn spawn(config: &Spawn<'_>) -> io::Result<Self> {
        // `CLOEXEC` on both ends, or every process in the session inherits a
        // writable handle to its own PTY master: anything that walks
        // `/proc/self/fd`, or writes to an fd it did not open, could inject output
        // into the stream or read the user's keystrokes. It does not cost the child
        // its stdio — `dup2` onto 0/1/2 clears the flag on the copies.
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let slave_path = ptsname(&master, Vec::new())?;

        // The master is non-blocking so that a child which has stopped reading —
        // and therefore filled the PTY's input buffer — cannot wedge the event
        // loop. Output for every other part of the session keeps flowing; the
        // unwritten input waits in `pending_input` until the PTY is writable
        // again. The slave is a separate open and stays blocking, which is what
        // the child expects of its own stdio.
        let flags = rustix::fs::fcntl_getfl(&master)?;
        rustix::fs::fcntl_setfl(&master, flags | OFlags::NONBLOCK)?;

        let slave: OwnedFd = rustix::fs::open(
            OsStr::from_bytes(slave_path.as_bytes()),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let slave = File::from(slave);

        // Set the size before the child can observe it, so the shell's first prompt
        // is already laid out correctly.
        tcsetwinsize(&master, to_winsize(config.win))?;

        let (shell, argv0) = login_shell();
        let mut command = Command::new(&shell);
        command
            .arg0(&argv0)
            .current_dir(config.cwd)
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?))
            .env("TERM", config.term)
            .env("NOMUX_SESSION", config.session_id)
            .env_remove("NOMUX_BOOTSTRAP");
        if let Some(sock) = config.agent_sock {
            // Overwrites whatever sshd forwarded: that socket dies with the
            // connection that created it, ours lives as long as the session
            // (`IMPLEMENTATION.md` § 6.7).
            command.env("SSH_AUTH_SOCK", sock);
        }

        // Valid between fork and exec: `slave` outlives `spawn` in this frame, and
        // CLOEXEC only takes effect at exec.
        let slave_fd = slave.as_raw_fd();
        // SAFETY: the closure runs in the forked child before exec, so it must be
        // async-signal-safe. `setsid`, `ioctl` and `signal` are; nothing here
        // allocates, takes a lock, or touches the Rust runtime.
        unsafe {
            command.pre_exec(move || {
                rustix::process::setsid()?;
                // SAFETY: `slave_fd` is open in the child, inherited across fork.
                let slave = BorrowedFd::borrow_raw(slave_fd);
                rustix::process::ioctl_tiocsctty(slave)?;
                // The daemon ignores SIGHUP (§ 6.2) and an ignored disposition
                // survives exec. Left alone, the child would inherit it and shrug
                // off the SIGHUP that idle reaping and `terminate` send first,
                // leaving SIGKILL to do all the work.
                // SAFETY: `signal` is async-signal-safe and SIG_DFL is a valid
                // handler value.
                if libc::signal(libc::SIGHUP, libc::SIG_DFL) == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = command.spawn()?;
        drop(slave);
        Ok(Self { master, child })
    }

    /// The PTY master, for reading output and writing input.
    #[must_use]
    pub(crate) fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }

    /// Applies new dimensions, which delivers `SIGWINCH` to the foreground group.
    ///
    /// # Errors
    ///
    /// Propagates `TIOCSWINSZ` failures.
    pub(crate) fn resize(&self, win: WinSize) -> io::Result<()> {
        tcsetwinsize(&self.master, to_winsize(win))?;
        Ok(())
    }

    /// Nudges the child into repainting by resizing to one column narrower and
    /// back, delivering two `SIGWINCH`es.
    ///
    /// This is the gap-recovery repaint of `IMPLEMENTATION.md` § 4.3, modelled on
    /// `dtach -r winch`. Most full-screen programs redraw; a bare shell does not.
    ///
    /// # Errors
    ///
    /// Propagates `TIOCSWINSZ` failures.
    pub(crate) fn nudge_repaint(&self, win: WinSize) -> io::Result<()> {
        if win.cols > 1 {
            let narrower = WinSize {
                cols: win.cols - 1,
                ..win
            };
            self.resize(narrower)?;
        }
        self.resize(win)
    }

    /// Reaps the child if it has exited, without blocking.
    ///
    /// # Errors
    ///
    /// Propagates `waitpid` failures.
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Terminates the child's process group, then the child itself.
    ///
    /// The group matters: signalling only the child leaves backgrounded
    /// grandchildren running, which is exactly the orphan case reaping exists to
    /// prevent. The child is its own group leader — `setsid` in `pre_exec` made it
    /// one — so its pgid is its pid.
    ///
    /// `kill_process_group` takes that **positive** pid and negates it itself.
    /// Handing it a pre-negated one double-negates back to `kill(pid)`, which
    /// signals the child alone and quietly reintroduces the orphan case; in a debug
    /// build it does not even get that far, because `Pid::from_raw` asserts its
    /// argument is non-negative.
    pub(crate) fn terminate(&mut self) {
        let pid = i32::try_from(self.child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw);
        if let Some(pid) = pid {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::HUP);
            // Real grace, not a formality: checking microseconds after the signal
            // finds everything still running, so `SIGKILL` would follow at once and
            // no shell would ever run its exit trap or flush its history.
            //
            // The wait is on the *group* emptying, via a signal-0 probe, not on the
            // direct child. By the time this runs the child has usually been reaped
            // already, and waiting on it would return immediately while the
            // backgrounded grandchildren this exists to collect are still there.
            let deadline = std::time::Instant::now() + TERM_GRACE;
            while std::time::Instant::now() < deadline {
                if rustix::process::test_kill_process_group(pid).is_err() {
                    break;
                }
                std::thread::sleep(TERM_POLL_INTERVAL);
            }
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

const fn to_winsize(win: WinSize) -> Winsize {
    Winsize {
        ws_row: win.rows,
        ws_col: win.cols,
        ws_xpixel: win.xpixel,
        ws_ypixel: win.ypixel,
    }
}

/// Resolves the shell to run and the dash-prefixed `argv[0]` that makes it a login
/// shell.
///
/// Precedence is `IMPLEMENTATION.md` § 6.1.1: `$SHELL` as inherited from the SSH
/// login, then the password database, then `/bin/sh`. The middle step matters for
/// a session started by something that scrubs the environment, where `$SHELL` is
/// absent and `/bin/sh` would silently downgrade the user's shell.
///
/// The leading `-` is what causes `/etc/profile` and `~/.bash_profile` to be
/// sourced. Without it the user gets a stunted environment and correctly concludes
/// the tool is broken.
fn login_shell() -> (PathBuf, String) {
    let shell = env::var_os("SHELL")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| passwd::current().and_then(|entry| entry.shell))
        .unwrap_or_else(|| PathBuf::from("/bin/sh"));
    let base = shell
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("sh")
        .to_owned();
    let argv0 = format!("-{base}");
    (shell, argv0)
}

/// Resolves the child's working directory, preferring `$HOME` the way sshd does.
///
/// `fallback` is the daemon's own directory from before it moved to `/`, i.e. the
/// directory the attaching connection was in. Neither existing leaves `/`, which is
/// always valid if never useful.
pub(crate) fn child_dir(fallback: Option<&Path>) -> PathBuf {
    let home = env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from);
    pick_dir(home.as_deref(), fallback)
}

/// The choice behind [`child_dir`], with the environment lifted out so it is
/// testable without mutating it.
fn pick_dir(home: Option<&Path>, fallback: Option<&Path>) -> PathBuf {
    [home, fallback]
        .into_iter()
        .flatten()
        .find(|dir| dir.is_dir())
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
}

/// Splits an `ExitStatus` into the wire representation of [`nomux_proto::Frame::Exit`].
#[must_use]
pub(crate) fn exit_parts(status: std::process::ExitStatus) -> (i32, nomux_proto::ExitKind) {
    use std::os::unix::process::ExitStatusExt;
    status.code().map_or_else(
        || {
            (
                status.signal().unwrap_or(0),
                nomux_proto::ExitKind::Signalled,
            )
        },
        |code| (code, nomux_proto::ExitKind::Exited),
    )
}

/// Outcome of one read from the PTY master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Read {
    /// Bytes are available in the buffer.
    Data(usize),
    /// The last process holding the slave is gone.
    Eof,
    /// Nothing buffered right now. Distinct from [`Read::Eof`], which is the whole
    /// reason this is an enum: on a non-blocking master both arrive as an error
    /// return, and confusing `EAGAIN` for the end of the session would report the
    /// child as exited every time the poll set woke up spuriously.
    WouldBlock,
}

/// Reads from the PTY master.
///
/// When the last process holding the slave exits, Linux fails master reads with
/// `EIO` rather than returning 0. Callers want that to look like a clean EOF.
///
/// # Errors
///
/// Propagates read failures other than `EIO`, `EAGAIN` and `EINTR`.
pub(crate) fn read_pty(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Read> {
    loop {
        return match rustix::io::read(fd, &mut *buf) {
            Ok(0) | Err(rustix::io::Errno::IO) => Ok(Read::Eof),
            Ok(n) => Ok(Read::Data(n)),
            Err(rustix::io::Errno::AGAIN) => Ok(Read::WouldBlock),
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => Err(err.into()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shell that starts in `/` because `$HOME` was wrong is a visible
    /// regression, so every fallback step is pinned.
    #[test]
    fn child_dir_prefers_home_then_the_daemons_own_directory() {
        let home = Path::new("/tmp");
        let gone = Path::new("/nonexistent-nomux-home");
        assert_eq!(pick_dir(Some(home), Some(Path::new("/"))), home);
        assert_eq!(pick_dir(Some(gone), Some(Path::new("/"))), Path::new("/"));
        assert_eq!(pick_dir(Some(gone), Some(gone)), Path::new("/"));
        assert_eq!(pick_dir(None, Some(home)), home);
        assert_eq!(pick_dir(None, None), Path::new("/"));
    }
}
