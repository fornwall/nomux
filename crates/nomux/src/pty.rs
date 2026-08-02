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
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use nomux_proto::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

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
    pub(crate) fn spawn(term: &str, win: WinSize, session_id: &str) -> io::Result<Self> {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let slave_path = ptsname(&master, Vec::new())?;

        let slave: OwnedFd = rustix::fs::open(
            OsStr::from_bytes(slave_path.as_bytes()),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )?;
        let slave = File::from(slave);

        // Set the size before the child can observe it, so the shell's first prompt
        // is already laid out correctly.
        tcsetwinsize(&master, to_winsize(win))?;

        let (shell, argv0) = login_shell();
        let mut command = Command::new(&shell);
        command
            .arg0(&argv0)
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?))
            .env("TERM", term)
            .env("NOMUX_SESSION", session_id)
            .env_remove("NOMUX_BOOTSTRAP");

        // Valid between fork and exec: `slave` outlives `spawn` in this frame, and
        // CLOEXEC only takes effect at exec.
        let slave_fd = slave.as_raw_fd();
        // SAFETY: the closure runs in the forked child before exec, so it must be
        // async-signal-safe. `setsid` and `ioctl` are; nothing here allocates,
        // takes a lock, or touches the Rust runtime.
        unsafe {
            command.pre_exec(move || {
                rustix::process::setsid()?;
                // SAFETY: `slave_fd` is open in the child, inherited across fork.
                let slave = BorrowedFd::borrow_raw(slave_fd);
                rustix::process::ioctl_tiocsctty(slave)?;
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
    /// prevent.
    pub(crate) fn terminate(&mut self) {
        let pid = self.child.id();
        if let Ok(pid) = i32::try_from(pid)
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let group = rustix::process::Pid::from_raw(-pid.as_raw_nonzero().get());
            for signal in [rustix::process::Signal::HUP, rustix::process::Signal::KILL] {
                if let Some(group) = group {
                    let _ = rustix::process::kill_process_group(group, signal);
                }
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                let _ = rustix::process::kill_process(pid, signal);
            }
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
/// The leading `-` is what causes `/etc/profile` and `~/.bash_profile` to be
/// sourced. Without it the user gets a stunted environment and correctly concludes
/// the tool is broken.
fn login_shell() -> (PathBuf, String) {
    let shell = env::var_os("SHELL")
        .filter(|value| !value.is_empty())
        .map_or_else(|| PathBuf::from("/bin/sh"), PathBuf::from);
    let base = shell
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("sh")
        .to_owned();
    let argv0 = format!("-{base}");
    (shell, argv0)
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

/// Reads from a file descriptor, treating the PTY's end-of-session `EIO` as EOF.
///
/// When the last process holding the slave exits, Linux fails master reads with
/// `EIO` rather than returning 0. Callers want that to look like a clean EOF.
///
/// # Errors
///
/// Propagates read failures other than `EIO` and `EINTR`.
pub(crate) fn read_pty(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        return match rustix::io::read(fd, &mut *buf) {
            Ok(n) => Ok(n),
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::IO) => Ok(0),
            Err(err) => Err(err.into()),
        };
    }
}
