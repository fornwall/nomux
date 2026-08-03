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
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nomux_proto::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use crate::passwd;

/// What the session's child needs to know at spawn.
#[derive(Debug)]
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
///
/// Named for the signal actually sent. `control.rs` has a `TERM_GRACE` of its own
/// for the different two seconds a *daemon* gets after `SIGTERM`, and one name for
/// two graces of different lengths, in different processes, after different signals
/// is a collision worth not having.
const HANGUP_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Interval between liveness checks while waiting out [`HANGUP_GRACE`].
const HANGUP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

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
        // `CLOEXEC` on both ends, or every process in the session inherits a writable
        // handle to its own PTY master — `IMPLEMENTATION.md` § 6.1 for what that
        // hands them. It does not cost the child its stdio: `dup2` onto 0/1/2 clears
        // the flag on the copies.
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

        // As the `CString` `ptsname` returned. Going through `OsStr` would strip the
        // terminator and have rustix copy the path back into a buffer to re-append
        // it; a `&CStr` is passed straight through.
        let slave: OwnedFd = rustix::fs::open(
            slave_path.as_c_str(),
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
        // Bound out here rather than written inside the `unsafe` block below, and
        // that is load-bearing rather than a matter of shape: unsafe context reaches
        // lexically into a closure body, so every unsafe call in here would compile
        // with no block of its own and `undocumented_unsafe_blocks` — the tree's one
        // mechanical guarantee that each unsafe site carries a justification — would
        // have nothing to fire on.
        let pre_exec = move || {
            rustix::process::setsid()?;
            // SAFETY: `slave_fd` is open in the child, inherited across fork.
            let slave = unsafe { BorrowedFd::borrow_raw(slave_fd) };
            rustix::process::ioctl_tiocsctty(slave)?;
            // The daemon ignores SIGHUP (§ 6.2) and an ignored disposition survives
            // exec. Left alone, the child would inherit it and shrug off the SIGHUP
            // that idle reaping and `terminate` send first, leaving SIGKILL to do
            // all the work. SIGTERM and SIGINT need no such treatment even though
            // the daemon handles both: exec resets every *handled* signal to its
            // default, and only ignoring is inherited through it.
            //
            // SAFETY: `signal` is async-signal-safe and SIG_DFL is a valid handler
            // value.
            if unsafe { libc::signal(libc::SIGHUP, libc::SIG_DFL) } == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: the closure runs in the forked child before exec, so it must be
        // async-signal-safe. `setsid` and `ioctl_tiocsctty` are rustix on the
        // `linux_raw` backend, which every shipped target selects — inline syscalls
        // with no libc between them and the kernel (`IMPLEMENTATION.md` § 8 makes
        // that a property of the whole tree) — so both are trivially reentrant
        // whatever signal-safety(7) says about the C functions of the same names.
        // `libc::signal` above is the one real libc call here, and it *is* on that
        // list. Nothing allocates, takes a lock, or touches the Rust runtime, which
        // is what the guarantee rests on.
        unsafe {
            command.pre_exec(pre_exec);
        }

        let child = command.spawn()?;
        // Both the copy in this frame and the three `Stdio::from` took: std only
        // *borrows* an owned descriptor for the child, so `Command` holds all three
        // until it is itself dropped. The master reports `EIO` — which `read_pty`
        // turns into the end of the session — only once no descriptor onto the slave
        // is left in this process, so a copy outliving this function is a child that
        // exits without the daemon ever noticing. Explicit rather than left to the
        // end of the scope, since that is an invariant something depends on.
        drop(command);
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
    /// A terminal one column wide gets the second resize alone, since there is no
    /// narrower size to go to; § 4.3 records why that weaker repaint is accepted.
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

    /// Terminates everything the session started, then the child itself.
    ///
    /// Two reaches, because neither alone covers the session. The process *group* is
    /// the cheap one and gets the ordinary case in a single syscall: the child is its
    /// own group leader — `setsid` in `pre_exec` made it one — so its pgid is its
    /// pid, and a shell without job control keeps everything it runs in that group.
    ///
    /// A shell *with* job control does not. It puts each `&` job in a process group
    /// of its own, which `kill_process_group(child)` then reaches none of — nor does
    /// the `SIGHUP` the kernel sends when the master closes, since that goes to the
    /// foreground group and a background job is by definition not it. So the orphan
    /// case this exists to prevent survived the group kill exactly, and only for the
    /// shells anybody actually uses interactively.
    ///
    /// What every one of those jobs *does* share is the session, because nothing a
    /// shell does to a job calls `setsid`. `kill(2)` cannot address a session, so
    /// [`session_members`] walks `/proc` for it. That walk is the reason the two
    /// reaches are ordered rather than merged: it costs a directory scan and a read
    /// per process, so it runs after the group probe says the common case is already
    /// over, and on most shutdowns happens once.
    pub(crate) fn terminate(&mut self) {
        let raw = i32::try_from(self.child.id()).unwrap_or(0);
        if let Some(pid) = rustix::process::Pid::from_raw(raw) {
            // The same probe the `SIGKILL` escalation below is guarded by, one
            // signal earlier and for the same reason. An ordinary exit reaps the
            // child long before `shutdown` gets here, so `raw` names a pid the
            // kernel is free to have reissued, and neither reach below can tell that
            // apart from its own session. It costs nothing in the case they exist
            // for: while anything is left of the session the child's own group holds
            // a member — a zombie counts, which is why `shutdown` reaching here
            // unreaped answers `Ok` — so the `&&` short-circuits and the guard is
            // one `kill(-pgid, 0)`.
            // What the last probe said, so neither signal below is sent to a group
            // this has already watched go.
            let mut group_alive = rustix::process::test_kill_process_group(pid).is_ok();
            let mut settled = !group_alive && session_members(raw).is_empty();
            if !settled {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::HUP);
                signal_session(raw, rustix::process::Signal::HUP);

                // Real grace, not a formality: checking microseconds after the
                // signal finds everything still running, so `SIGKILL` would follow
                // at once and no shell would ever run its exit trap or flush its
                // history.
                //
                // The condition is the session emptying, not the direct child
                // exiting. Waiting on the child alone would be satisfied the moment
                // it goes, while the backgrounded grandchildren this exists to
                // collect are still running — they are the whole reason for the
                // `/proc` walk.
                let deadline = std::time::Instant::now() + HANGUP_GRACE;
                while std::time::Instant::now() < deadline {
                    // Reaped here, every pass, and not merely for tidiness: an
                    // unreaped zombie is still a member of its own process group, so
                    // `test_kill_process_group` answers `Ok` for it and the `&&`
                    // below short-circuits before `session_members` — which *does*
                    // filter zombies — is ever consulted. `shutdown` reaches
                    // `terminate` with the child unreaped, because `reap` only runs
                    // once the PTY has reported end of file, which on the
                    // `nomux kill` path it has not.
                    let _ = self.child.try_wait();
                    group_alive = rustix::process::test_kill_process_group(pid).is_ok();
                    if !group_alive && session_members(raw).is_empty() {
                        settled = true;
                        break;
                    }
                    std::thread::sleep(HANGUP_POLL_INTERVAL);
                }
            }
            // Only if something is still standing. Settling means the group is gone
            // *and* the session is empty, so there is nothing left for these to
            // reach — and once the child has been reaped its pid is free for the
            // kernel to reissue, which is the one case where signalling a group that
            // no longer exists could land somewhere it was never meant to.
            //
            // The two reaches are separately conditional for that reason, because
            // the two conditions come apart: a backgrounded job in a group of its
            // own — the case this whole function exists for — outlives the grace
            // while the *child's* group is already gone and reaped. Signalling that
            // group anyway is a `SIGKILL` sent to a pid the kernel is free to have
            // reissued, which is exactly what the paragraph above refuses to do.
            if !settled {
                if group_alive {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                signal_session(raw, rustix::process::Signal::KILL);
            }
        }
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// Signals every live process still in session `sid`.
///
/// Individually, because a session is not something `kill(2)` addresses — the
/// negative-pid form means a process *group*, and the point here is precisely the
/// groups job control created that nobody is tracking.
fn signal_session(sid: i32, signal: rustix::process::Signal) {
    for member in session_members(sid) {
        if let Some(pid) = rustix::process::Pid::from_raw(member) {
            let _ = rustix::process::kill_process(pid, signal);
        }
    }
}

/// Pids of the live processes in session `sid`, from `/proc`.
///
/// Signalling by a number read out of `/proc` is the sort of thing that goes very
/// wrong when it goes wrong, so this is deliberately narrow: `sid` comes from a
/// child this process forked, no pid is returned unless its own `stat` line claims
/// that session, and this process is excluded by pid whatever `/proc` says.
///
/// Zombies are left out. One is a process that has already exited and is waiting
/// to be collected; signalling it does nothing, and counting it would keep the
/// caller's grace loop spinning for its whole budget over the child it is itself
/// about to reap.
fn session_members(sid: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let self_pid = i32::try_from(std::process::id()).unwrap_or(0);
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| *pid != self_pid)
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| stat_session(&stat))
                .is_some_and(|(session, zombie)| session == sid && !zombie)
        })
        .collect()
}

/// The session id and whether the process is a zombie, from one `/proc/<pid>/stat`.
///
/// Parsed from the last `)` rather than by splitting on whitespace from the left,
/// because field two is the executable's name in parentheses and the kernel does
/// not escape it: a process called `foo bar) 1 2 3` is a name somebody can choose,
/// and splitting from the left hands back whatever they put there. Everything after
/// the final `)` is fixed-width and space-separated, so it is safe to count through
/// — state, ppid, pgrp, then the session.
///
/// Bytes rather than a `&str` for the same reason, taken one step further. That
/// name is copied from the executable's basename, and the kernel escapes only `\n`
/// and `\\` in it, so a binary called `ba<0xff>sh` puts a byte in this line that is
/// not UTF-8. Read as a string the whole line is then undecodable, the pid drops
/// out of the walk, and the consequences are silent and both bad: [`Pty::terminate`]
/// never signals that process, and — because the walk is also what decides the
/// session has settled — it skips the `SIGKILL` escalation and reports a clean
/// shutdown over a job that is still running. Only the fixed-width tail is decoded,
/// which is ASCII by construction.
fn stat_session(stat: &[u8]) -> Option<(i32, bool)> {
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    let rest = str::from_utf8(stat.get(close + 1..)?).ok()?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?;
    let session = fields.nth(2)?.parse().ok()?;
    Some((session, state == "Z"))
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
/// Precedence and the reason for the leading `-` are both `IMPLEMENTATION.md`
/// § 6.1.1: `$SHELL` as inherited from the SSH login, then the password database,
/// then `/bin/sh`. The middle step matters for a session started by something that
/// scrubs the environment, where `$SHELL` is absent and `/bin/sh` would silently
/// downgrade the user's shell.
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
    match crate::nbio::read(fd, buf) {
        Ok(0) | Err(rustix::io::Errno::IO) => Ok(Read::Eof),
        Ok(n) => Ok(Read::Data(n)),
        Err(rustix::io::Errno::AGAIN) => Ok(Read::WouldBlock),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `comm` field is whatever the process called its executable, parentheses
    /// and spaces included, and the fields that matter here sit after it.
    #[test]
    fn a_stat_line_parses_past_a_hostile_process_name() {
        let ordinary = b"42 (bash) S 1 42 42 34816 99 4194304 0 0";
        assert_eq!(stat_session(ordinary), Some((42, false)));

        // A name chosen to break a left-to-right split: it contains spaces, a
        // closing paren, and digits that would be read as the session id.
        let hostile = b"42 (evil) 1 2 3) S 1 42 7 34816 99 4194304 0 0";
        assert_eq!(
            stat_session(hostile),
            Some((7, false)),
            "the session must come from after the *last* paren"
        );

        // A `comm` the kernel does not escape and UTF-8 cannot hold. Read as a
        // string the whole line is undecodable, and this process would then be
        // invisible to the walk that is supposed to signal it — so it would
        // survive `nomux kill` while the daemon reported a clean shutdown.
        let not_utf8 = b"42 (ba\xffsh) S 1 42 42 34816 99 4194304 0 0";
        assert_eq!(
            stat_session(not_utf8),
            Some((42, false)),
            "a name outside UTF-8 must not hide the process from the walk"
        );

        let zombie = b"42 (sh) Z 1 42 42 0 -1 4194304 0 0";
        assert_eq!(stat_session(zombie), Some((42, true)));

        assert_eq!(stat_session(b"truncated"), None);
        assert_eq!(
            stat_session(b"42 (sh) S 1"),
            None,
            "too few fields to answer"
        );
    }

    /// The daemon must never appear in the set it is about to signal, whatever
    /// `/proc` says.
    #[test]
    fn the_walk_never_returns_this_process() {
        let Ok(sid) = rustix::process::getsid(None) else {
            return;
        };
        let sid = rustix::process::Pid::as_raw(Some(sid));
        let members = session_members(sid);
        let self_pid = i32::try_from(std::process::id()).unwrap_or(0);
        assert!(
            !members.contains(&self_pid),
            "the reaper found itself among the reaped: {members:?}"
        );
    }

    /// The case the process-group kill cannot reach, and the reason for the
    /// `/proc` walk: a shell with job control gives each `&` job a process group
    /// of its own, so the only thing still holding them together is the session.
    ///
    /// `set -m` is what makes this test test something. Without it the job stays
    /// in the shell's own group, the group kill reaches it, and the test passes
    /// against the very bug it describes. The `trap` closes the other way out —
    /// `SIGHUP` alone must not be what collects it, or the walk is again not the
    /// thing being exercised.
    #[test]
    fn terminate_collects_a_backgrounded_job_in_its_own_process_group() {
        let config = Spawn {
            term: "dumb",
            win: WinSize {
                cols: 80,
                rows: 24,
                xpixel: 0,
                ypixel: 0,
            },
            session_id: "terminate_test",
            cwd: Path::new("/tmp"),
            agent_sock: None,
        };
        let mut pty = Pty::spawn(&config).expect("spawn a shell on a pty");

        let script = "set -m\n(trap '' HUP; sleep 30) &\necho NOMUX-JOB=$!\n";
        rustix::io::write(pty.master(), script.as_bytes()).expect("write the script");
        let job = read_marker(&pty, "NOMUX-JOB=").expect("the shell reported its job pid");
        assert!(
            !collected(job),
            "the job should be running before terminate"
        );

        pty.terminate();

        // `terminate` returns only once it has signalled, but the kernel's own
        // teardown and the reparenting reap are asynchronous, so the assertion is
        // on the job going away rather than on it having gone already.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !collected(job) {
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(
            collected(job),
            "a backgrounded job in its own process group outlived the session"
        );
    }

    /// The other side of that guard: a reaped child whose session is *not* empty
    /// still gets both reaches.
    ///
    /// What an ordinary exit leaves behind when the shell had a job running. The
    /// child's own group is empty by then and its pid is dead, so a guard written
    /// on the group alone would skip — and the walk is the whole answer here, the
    /// session being the only thing still holding that job. Skipping would leave it
    /// running and report a clean shutdown, which is § 6.5's orphan by another
    /// route. The pid cannot have been reissued in this state either: the kernel
    /// keeps one reserved for as long as anything still names it as a session.
    #[test]
    fn terminate_still_collects_a_job_whose_shell_has_been_reaped() {
        let config = Spawn {
            term: "dumb",
            win: WinSize {
                cols: 80,
                rows: 24,
                xpixel: 0,
                ypixel: 0,
            },
            session_id: "terminate_orphan",
            cwd: Path::new("/tmp"),
            agent_sock: None,
        };
        let mut pty = Pty::spawn(&config).expect("spawn a shell on a pty");

        // `exit` twice, because a shell with job control may answer the first one
        // by pointing out that a job is still running and asking again — zsh does.
        // Where the first is taken the second is never read by anybody.
        let script = "set -m\n(trap '' HUP; sleep 30) &\necho NOMUX-JOB=$!\nexit\nexit\n";
        rustix::io::write(pty.master(), script.as_bytes()).expect("write the script");
        let job = read_marker(&pty, "NOMUX-JOB=").expect("the shell reported its job pid");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut reaped = false;
        while std::time::Instant::now() < deadline && !reaped {
            reaped = pty.try_wait().expect("wait for the shell").is_some();
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(reaped, "the shell never exited");
        assert!(
            !collected(job),
            "the job should outlive the shell that started it"
        );

        pty.terminate();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !collected(job) {
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(
            collected(job),
            "a job whose shell had already been reaped outlived the session"
        );
    }

    /// Regression: with the child reaped and nothing left of its session,
    /// `terminate` sends no signal at all.
    ///
    /// An ordinary exit reaps the child (`daemon::collect_status`) long before
    /// `shutdown` calls this, so by then `raw` is a number the kernel is free to
    /// have handed to somebody else — and a `SIGHUP` at that pid's group and session
    /// is one aimed at whoever holds it now. The `SIGKILL` escalation was guarded
    /// against exactly this and the `SIGHUP` above it was not.
    ///
    /// Watched as the syscall rather than as its effect, which is the only thing
    /// that *can* be watched: where the guard skips, what it skips would have landed
    /// nowhere by construction — the group is gone and the session is empty — so no
    /// observer can be put where the signal would have arrived. A recycled pid is
    /// not arrangeable either, since the kernel hands them out in sequence and keeps
    /// one reserved for as long as any process still names it as a session or group.
    ///
    /// A build that does signal may well fail inside rustix rather than on the
    /// assertion below, and that is the same failure wearing a different hat: the
    /// kernel rolls the registers back before raising `SIGSYS`, so a trapped `kill`
    /// returns its own syscall number and rustix's debug assertion on the range of a
    /// return value fires on it.
    #[test]
    fn terminate_signals_nothing_once_the_child_has_been_reaped_and_its_session_is_gone() {
        let config = Spawn {
            term: "dumb",
            win: WinSize {
                cols: 80,
                rows: 24,
                xpixel: 0,
                ypixel: 0,
            },
            session_id: "terminate_reaped",
            cwd: Path::new("/tmp"),
            agent_sock: None,
        };
        let mut pty = Pty::spawn(&config).expect("spawn a shell on a pty");
        rustix::io::write(pty.master(), b"exit\n").expect("ask the shell to leave");

        // Collected here the way the daemon collects at an ordinary exit, which is
        // what frees the pid the two reaches below are addressed to.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut reaped = false;
        while std::time::Instant::now() < deadline && !reaped {
            reaped = pty.try_wait().expect("wait for the shell").is_some();
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(reaped, "the shell never exited");

        let raw = i32::try_from(pty.child.id()).unwrap_or(0);
        let pid = rustix::process::Pid::from_raw(raw).expect("the reaped child's pid");
        // Deterministic rather than hopeful, for the reason above: a pid is not
        // reissued while anything still names it.
        assert!(
            rustix::process::test_kill_process_group(pid).is_err()
                && session_members(raw).is_empty(),
            "nothing of the session may be left, or this test is about the other case"
        );

        if !trap_kills_of(raw) {
            // A host that will not take the filter cannot answer the question, the
            // way `the_walk_never_returns_this_process` cannot without a session id.
            return;
        }
        pty.terminate();

        assert!(
            !SIGNALLED_A_FREED_PID.load(std::sync::atomic::Ordering::Relaxed),
            "terminate signalled a pid the kernel had already taken back"
        );
    }

    /// Set by [`note_sigsys`] when [`trap_kills_of`] catches a signal going out.
    static SIGNALLED_A_FREED_PID: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    extern "C" fn note_sigsys(_signum: libc::c_int) {
        SIGNALLED_A_FREED_PID.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Traps every `kill(2)` at `pid` or at its process group carrying a real
    /// signal, so that issuing one sets [`SIGNALLED_A_FREED_PID`] instead of
    /// reaching the kernel. `false` where the filter was refused.
    ///
    /// Signal 0 is deliberately let through: that is the liveness probe the guard
    /// under test makes, and trapping it would break the very thing being measured.
    ///
    /// This thread's alone — no `TSYNC` flag — which is what keeps it off the rest
    /// of a `cargo test` run, where the other tests in this binary have threads of
    /// their own. It cannot be removed once installed, and is not: the thread a test
    /// runs on ends with it.
    fn trap_kills_of(pid: i32) -> bool {
        // `struct seccomp_data`: the syscall number at 0, then the arguments from
        // 16, eight bytes each. Only the low half of an argument is loaded, which is
        // the whole of a pid and is where it sits on every little-endian target.
        const NUMBER: u32 = 0;
        const TARGET: u32 = 16;
        const SIGNAL: u32 = 24;

        let load = u16::try_from(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS).expect("a BPF opcode");
        let equals =
            u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K).expect("a BPF opcode");
        let answer = u16::try_from(libc::BPF_RET | libc::BPF_K).expect("a BPF opcode");
        let jump = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
        // Jump offsets count from the instruction after the one carrying them, so
        // both destinations are the last two entries: allow at 7, trap at 8.
        let mut filter = [
            jump(load, 0, 0, NUMBER),
            jump(
                equals,
                0,
                5,
                u32::try_from(libc::SYS_kill).expect("the kill syscall"),
            ),
            jump(load, 0, 0, SIGNAL),
            jump(equals, 3, 0, 0),
            jump(load, 0, 0, TARGET),
            jump(equals, 2, 0, pid.cast_unsigned()),
            jump(equals, 1, 0, pid.wrapping_neg().cast_unsigned()),
            jump(answer, 0, 0, libc::SECCOMP_RET_ALLOW),
            jump(answer, 0, 0, libc::SECCOMP_RET_TRAP),
        ];

        // Before the filter, or the first trap is a core dump.
        //
        // SAFETY: `signal` with a handler that does nothing but store to an atomic,
        // which is async-signal-safe.
        unsafe { libc::signal(libc::SIGSYS, note_sigsys as *const () as libc::sighandler_t) };
        // SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes no pointer arguments. It
        // is what lets an unprivileged process install the filter below.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return false;
        }
        let program = libc::sock_fprog {
            len: u16::try_from(filter.len()).expect("a filter of a few instructions"),
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: `seccomp` is handed a program whose length matches the array it
        // points at, both of which outlive the call.
        let installed = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                std::ptr::from_ref(&program),
            )
        };
        installed == 0
    }

    /// Whether `pid` is gone, counting a zombie as gone: it has exited and is
    /// waiting on a parent that this test does not control.
    fn collected(pid: i32) -> bool {
        std::fs::read(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat_session(&stat))
            .is_none_or(|(_, zombie)| zombie)
    }

    /// Reads the PTY until `marker` is followed by a complete number.
    ///
    /// The terminal echoes input, so the literal `NOMUX-JOB=$!` of the command
    /// arrives before the shell's answer does. Requiring digits *and* something
    /// after them is what tells the echo from the reply, and what keeps a number
    /// split across two reads from being taken half-finished.
    fn read_marker(pty: &Pty, marker: &str) -> Option<i32> {
        let mut seen = String::new();
        let mut buf = [0u8; 4096];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match read_pty(pty.master(), &mut buf) {
                Ok(Read::Data(n)) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                Ok(Read::WouldBlock) => std::thread::sleep(HANGUP_POLL_INTERVAL),
                Ok(Read::Eof) | Err(_) => break,
            }
            for (at, _) in seen.match_indices(marker) {
                let tail = &seen[at + marker.len()..];
                let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
                if !digits.is_empty()
                    && digits.len() < tail.len()
                    && let Ok(pid) = digits.parse()
                {
                    return Some(pid);
                }
            }
        }
        None
    }

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
