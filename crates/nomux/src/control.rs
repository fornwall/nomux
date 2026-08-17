//! The frozen control surface: `list` and `kill` (§ 6.6, `DESIGN.md` § 6.4).
//!
//! These must work against a daemon of *any* version, so the contract here is the
//! on-disk layout — never a protocol frame, never `PROTOCOL_VERSION`.
//!
//! The socket probe all of this is written against is [`crate::usock::liveness`], where the
//! daemon's bind and the attach paths reach it without reading a line of a file § 6.6 froze.

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal, test_kill_process};

use crate::rundir::{
    MAX_PID_LEN, MAX_SESSION_ID_LEN, SessionPaths, check_run_dir, parse_pid, read_label,
    read_prefix, run_dir, session_ids,
};
use crate::usock::{Liveness, liveness};

/// A full listener backlog can make `connect` block rather than refuse.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Listing need not wait because only settled [`Liveness::Stale`] errors change its result.
const LIST_PROBE: Duration = Duration::ZERO;

/// Shared deadline for lock release, pid publication, and graceful shutdown.
const GRACE: Duration = Duration::from_secs(2);

/// Final wait after signalling before a socket is declared still live.
const KILL_GRACE: Duration = Duration::from_millis(500);

/// Poll cadence, limiting each two-second stage to about 80 queued probes.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The kernel's longest path, which is as long as `argv[0]` gets for a daemon *this*
/// program starts: `spawn` sets it from `env::current_exe`, a path the kernel resolved.
const PATH_MAX: usize = 4096;

/// Bounded `/proc/<pid>/cmdline` prefix, long enough for complete `argv[0] daemon <id>`.
const MAX_CMDLINE_LEN: usize = PATH_MAX + 1 + "daemon".len() + 1 + MAX_SESSION_ID_LEN + 1;

/// Prints one line per live session and collects the dead ones, as § 6.6's `list output` has
/// it down to the `EPIPE` and the id named on stderr.
///
/// # Errors
///
/// Fails on a run directory that is not this user's alone (§ 6.3). A missing one is not an
/// error — no session has ever been created.
pub(crate) fn list() -> io::Result<()> {
    let dir = run_dir()?;
    // § 6.3, before any name in this directory is trusted.
    if !check_run_dir(&dir)? {
        return Ok(());
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut listening = true;
    for id in session_ids(&dir)? {
        // Against the directory already resolved above rather than one per entry: it is the
        // directory these names came out of, so re-reading the environment could only
        // disagree with the `read_dir` this is iterating.
        let paths = match SessionPaths::in_dir(&dir, &id) {
            Ok(paths) => paths,
            // § 6.3's `sun_path` refusal, a property of this directory rather than of the id,
            // so this is the one session `list` can neither print nor collect.
            Err(err) => {
                let complaint = format!("{err}; its files are left where they are");
                crate::write_stderr(format_args!("nomux: {}\n", complaint.escape_debug()));
                continue;
            }
        };
        // Only death collects (§ 6.3); a probe that failed for any other reason leaves a
        // session to list.
        if matches!(liveness(&paths.socket(), LIST_PROBE), Liveness::Stale(_)) {
            collect(&paths);
            continue;
        }
        // Nowhere left to print to, and the sweep above is why the loop goes on anyway.
        if !listening {
            continue;
        }
        let mut buf = [0u8; MAX_PID_LEN];
        let (filed, _) = pidfile(&paths.pid(), &mut buf).unwrap_or_default();
        let pid = identified(&paths, filed)
            .map_or_else(|| "?".to_owned(), |pid| pid.as_raw_nonzero().to_string());
        // Sanitised on read as well as on write (§ 6.6): the daemon that wrote it may
        // be any version.
        let label = read_label(&paths.label());
        match writeln!(out, "{id}\t{pid}\t{label}") {
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => listening = false,
            outcome => outcome?,
        }
    }
    Ok(())
}

/// Terminates a session and removes its run files.
///
/// An id whose run files overrun § 6.3's `sun_path` bound is refused here rather than acted
/// on: [`SessionPaths::new`] is what turns one into the paths this signals and unlinks, so
/// there is nothing for it to address. Neither mode can collect such a session.
///
/// # Errors
///
/// Fails on an invalid session id, on a run directory that is not this user's alone
/// (§ 6.3), and on the states § 6.6 lists behind a non-zero `kill` — plus [`unprobeable`]
/// and [`bound_since`], which come from the probe rather than from the session. A session
/// that is already gone is not an error: the postcondition already holds.
pub(crate) fn kill(session_id: &str) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    // The same check `list` makes, and this is where it bites hardest: what follows reads a
    // pid out of a file and signals it.
    if !check_run_dir(paths.dir())? {
        return Ok(());
    }
    // Held from here to the end of the function (§ 6.6): without it, an attach that starts a
    // fresh daemon between the signal below and the unlink that follows loses its socket to a
    // kill it was never the target of. Bounded rather than a blocking `flock`, because a
    // process that stopped letting go is no reason for the escape hatch to hang forever.
    let lock = paths.lock_spawn_until(Instant::now() + GRACE)?;
    if let Some(chosen) = resolve(&paths)? {
        let term = chosen.signal(Signal::TERM);
        // Liveness first, deadline second, so a daemon that let go on the last interval is
        // not signalled again — `SIGKILL` being the one signal nothing survives, and the
        // descriptor guaranteeing only that it lands on the process this call pinned.
        let mut deadline = Instant::now() + GRACE;
        let mut killed = None;
        loop {
            match liveness(&paths.socket(), PROBE_TIMEOUT) {
                Liveness::Stale(_) => break,
                Liveness::Alive(_) => {}
                // A probe that never reached the socket answers nothing about the daemon,
                // so it may neither be waited out nor escalated on: the `SIGKILL` below
                // would go to a number nothing here ties to this session.
                Liveness::Unknown(err) => return Err(unprobeable(&paths, &err)),
            }
            if Instant::now() >= deadline {
                // Both graces out with the socket still answering — reached only from the arm
                // above that accepted a connection. What the escalation actually did is
                // [`still_answering`]'s to say rather than this call site's.
                if let Some(kill) = &killed {
                    return Err(refuse(still_answering(paths.id(), &chosen, &term, kill)));
                }
                killed = Some(chosen.signal(Signal::KILL));
                deadline = Instant::now() + KILL_GRACE;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
    // Probed once more under the lock (§ 6.6), where [`collect`] also decides and the two
    // must agree. A daemon can no longer bind inside this region: direct starts must take
    // this lock, and spawned daemons inherit the relay's locked descriptor (§ 6.3).
    match liveness(&paths.socket(), PROBE_TIMEOUT) {
        // The one *successful* exit from the locked region, and so the one place the files
        // go: already gone, stopped on `SIGTERM` and killed outright all end up here.
        Liveness::Stale(_) => paths.unlink_all_locked(&lock),
        Liveness::Alive(_) => Err(bound_since(&paths)),
        Liveness::Unknown(err) => Err(unprobeable(&paths, &err)),
    }
}

/// Which process a locked session's daemon is, or `None` where nothing is listening and
/// the files are all that is left.
///
/// Liveness first, and only then the pid: a daemon that died without unlinking leaves its
/// pidfile behind and the kernel reuses pids, so signalling a number read off disk
/// unchecked is how `nomux kill` terminates an unrelated process of the user's. What
/// comes back is a [`Chosen`] rather than the number itself, because the same reuse
/// happens again between here and each of the two signals.
fn resolve(paths: &SessionPaths) -> io::Result<Option<Chosen>> {
    let deadline = Instant::now() + GRACE;
    loop {
        // The probe's errno is kept rather than matched away, because every refusal below is
        // [`unresolved`]'s to word and that is what it words them by. The connection is not:
        // the match drops it, so nothing holds one open across the grace.
        let unprobed = match liveness(&paths.socket(), PROBE_TIMEOUT) {
            Liveness::Stale(_) => return Ok(None),
            Liveness::Alive(_) => None,
            Liveness::Unknown(err) => Some(err),
        };
        let mut buf = [0u8; MAX_PID_LEN];
        let waiting_on = match pidfile(&paths.pid(), &mut buf) {
            Ok((filed, body)) if !body.trim_ascii().is_empty() => {
                // A pid `/proc` does not rule out is taken whatever the probe did:
                // [`chosen`] identifies a *process*, by a route the socket has no part in, so
                // a mode or a descriptor limit keeping this process off the socket is no
                // reason to stop signalling a daemon this one has positively named.
                return chosen(paths, filed).map(Some).ok_or_else(|| {
                    let problem = unidentified(paths.id(), filed, body);
                    unresolved(paths, unprobed.as_ref(), &problem)
                });
            }
            // The same publish window one syscall later, so it is waited out too:
            // `SessionPaths::write_pid` creates the file and fills it in two steps.
            Ok(_) => "it was created but never written",
            Err(err) if err.kind() == io::ErrorKind::NotFound => "it never appeared",
            // Unreadable is not the publish window and never becomes it, so it is
            // settled now rather than waited on.
            Err(err) => return Err(unresolved(paths, unprobed.as_ref(), &err.to_string())),
        };
        if Instant::now() >= deadline {
            return Err(unresolved(paths, unprobed.as_ref(), waiting_on));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// The pid a session's pidfile names, and the body it was read from — which
/// [`unidentified`] reports on and `list` discards. Both modes read it through here,
/// because § 6.6 has the number a user reads be the number that would be acted on.
///
/// A number that no longer names a process this user may signal is dropped rather than
/// carried: it is not evidence, so it is neither signalled nor reported as a pid. That
/// check cannot tell a reissued number from the original, which is why [`chosen`] asks
/// [`is_daemon_for`] as well.
fn pidfile<'a>(path: &Path, buf: &'a mut [u8; MAX_PID_LEN]) -> io::Result<(Option<Pid>, &'a [u8])> {
    let body = read_prefix(path, buf)?;
    let pid = parse_pid(body)
        .and_then(Pid::from_raw)
        .filter(|pid| test_kill_process(*pid).is_ok());
    Ok((pid, body))
}

/// The pidfile number and a hold on the process it named before [`GRACE`] elapsed.
#[derive(Debug)]
struct Chosen {
    pid: Pid,
    reach: io::Result<OwnedFd>,
}

impl Chosen {
    /// Signals through the pidfd; the later socket probe settles the outcome, while the
    /// result is retained so a refusal never claims a syscall that failed was sent.
    fn signal(&self, sig: Signal) -> io::Result<()> {
        let pidfd = self
            .reach
            .as_ref()
            .map_err(|err| io::Error::new(err.kind(), err.to_string()))?;
        pidfd_send_signal(pidfd, sig).map_err(Into::into)
    }
}

/// Pins a pid before validation; failure never falls back to the reusable bare number.
fn pin(pid: Pid) -> io::Result<OwnedFd> {
    pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from)
}

/// The published pid, unless `/proc` establishes it belongs to another process.
fn identified(paths: &SessionPaths, filed: Option<Pid>) -> Option<Pid> {
    let pid = filed?;
    (is_daemon_for(pid, paths.id()) != Some(false)).then_some(pid)
}

/// Pins before identification so `/proc` validation and signals concern one process.
fn chosen(paths: &SessionPaths, filed: Option<Pid>) -> Option<Chosen> {
    let reach = pin(filed?);
    identified(paths, filed).map(|pid| Chosen { pid, reach })
}

/// Whether `pid` is a `nomux daemon <id>` process, where that can be established. `None`
/// is "could not tell", which [`chosen`] admits and § 6.6 has the weighing of — including
/// how narrowly truncation is allowed to produce it.
fn is_daemon_for(pid: Pid, id: &str) -> Option<bool> {
    let mut buf = [0u8; MAX_CMDLINE_LEN];
    let cmdline = PathBuf::from(format!("/proc/{}/cmdline", pid.as_raw_nonzero()));
    let body = read_prefix(&cmdline, &mut buf).ok()?;
    // Every argv element is NUL-*terminated*, so everything up to the last NUL is
    // arguments this read saw the end of, and comparing the tail is comparing half a word.
    let whole = body
        .iter()
        .rposition(|byte| *byte == 0)
        .and_then(|end| body.get(..end))
        .unwrap_or(&[]);
    if names_daemon_prefix(whole, id, body.len() == MAX_CMDLINE_LEN) {
        return Some(true);
    }
    // A full buffer is still a definitive "no" wherever `argv[1]` arrived whole — exactly
    // when `whole` holds a NUL (§ 6.6).
    (body.len() < MAX_CMDLINE_LEN || whole.contains(&0)).then_some(false)
}

/// Whether a NUL-separated command line is `<exe> daemon <id>`, however it was spelled.
///
/// Parsed the way [`main::parse_session_args`](crate::main) parses it rather than searched,
/// which is § 6.6's rule and its reason.
/// If the read filled its buffer, a final bare option may have its value in the discarded
/// tail; a valid placeholder preserves that one deliberately inconclusive case.
fn names_daemon_prefix(whole: &[u8], id: &str, truncated: bool) -> bool {
    let mut args = whole.split(|byte| *byte == 0);
    args.next();
    if args.next() != Some(b"daemon".as_slice()) {
        return false;
    }
    let missing = if truncated {
        match args.clone().next_back() {
            Some(b"--label") => Some(OsString::new()),
            Some(b"--lock-fd") => Some(OsString::from("3")),
            _ => None,
        }
    } else {
        None
    };
    crate::parse_session_args(
        args.map(|arg| OsString::from_vec(arg.to_vec()))
            .chain(missing),
        true,
    )
    .is_ok_and(|parsed| parsed.session.as_deref() == Some(id))
}

#[cfg(test)]
fn names_daemon_for(whole: &[u8], id: &str) -> bool {
    names_daemon_prefix(whole, id, false)
}

/// The shape every refusal here takes: something in the run directory said what this
/// call would not act on, which is [`io::ErrorKind::InvalidData`] and § 10's code for it.
fn refuse(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The refusal to touch a live session whose pid is not knowable. It names the pidfile
/// because that is the one thing the user can repair.
fn running_but(paths: &SessionPaths, problem: &str) -> io::Error {
    refuse(format!(
        "session {id} is running, but {pid}: {problem}",
        id = paths.id(),
        pid = paths.pid().display(),
    ))
}

/// Which refusal a session [`resolve`] could not name a process for has earned — decided
/// by the probe rather than by the pidfile: only an accepted connection establishes the
/// "is running" that [`running_but`] opens with (§ 6.3), so a failed probe earns
/// [`unprobeable`] instead.
fn unresolved(paths: &SessionPaths, unprobed: Option<&io::Error>, problem: &str) -> io::Error {
    unprobed.map_or_else(
        || running_but(paths, problem),
        |err| unprobeable(paths, err),
    )
}

/// Why [`chosen`] came back with nothing over a session that is answering, in the words
/// [`running_but`] finishes. A body that reached the bound ([`parse_pid`]) is quoted as
/// bytes rather than as a number whose end was never read (§ 6.6).
fn unidentified(id: &str, filed: Option<Pid>, body: &[u8]) -> String {
    let quoted = String::from_utf8_lossy(body);
    match filed {
        Some(filed) => format!(
            "it names pid {filed}, which is not a `nomux daemon {id}` process",
            filed = filed.as_raw_nonzero(),
        ),
        None if body.len() >= MAX_PID_LEN => format!(
            "it runs past the {MAX_PID_LEN} bytes a pidfile may be, so any number in it \
             is cut off rather than read; it begins {quoted:?}"
        ),
        None => parse_pid(body).map_or_else(
            || format!("it holds {quoted:?}"),
            |pid| format!("pid {pid} names no process this user can signal"),
        ),
    }
}

/// The refusal to collect a session that was answering still when both graces ran out,
/// naming exactly which syscalls reached the pinned process and which failed (§ 6.6).
fn still_answering(
    id: &str,
    chosen: &Chosen,
    term: &io::Result<()>,
    kill: &io::Result<()>,
) -> String {
    let pid = chosen.pid.as_raw_nonzero();
    match (term, kill) {
        (Ok(()), Ok(())) => format!(
            "session {id} is still answering after SIGTERM and SIGKILL to pid {pid}, so \
             that pid is not the process serving it"
        ),
        (Err(term), Err(kill)) => format!(
            "session {id} is still answering, and neither SIGTERM nor SIGKILL was sent \
             to pid {pid} (SIGTERM: {term}; SIGKILL: {kill})"
        ),
        (Ok(()), Err(kill)) => format!(
            "session {id} is still answering after SIGTERM to pid {pid}; SIGKILL could \
             not be sent ({kill})"
        ),
        (Err(term), Ok(())) => format!(
            "session {id} is still answering after SIGKILL to pid {pid}, so that pid is \
             not the process serving it; SIGTERM could not be sent ({term})"
        ),
    }
}

/// The refusal to decide a session's fate on a probe that never reached it: § 6.3 makes
/// its errno evidence of neither death nor life, and naming it is the whole of what is
/// known.
fn unprobeable(paths: &SessionPaths, problem: &io::Error) -> io::Error {
    refuse(format!(
        "session {id}: {sock} could not be probed: {problem}",
        id = paths.id(),
        sock = paths.socket().display(),
    ))
}

/// The refusal to collect a session that answered again under the lock: a live session to
/// leave alone, and a `kill` overtaken by a spawn, which running the command again
/// repairs (§ 6.6).
fn bound_since(paths: &SessionPaths) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "session {id} is answering on {sock} again: a daemon bound the id after this \
             kill established it was gone",
            id = paths.id(),
            sock = paths.socket().display(),
        ),
    )
}

/// Removes a dead session's files, or leaves them to whoever comes next.
///
/// The probe that got us here is a hint rather than a verdict, so collection takes
/// `<id>.lock` and decides liveness again under it (§ 6.6). It gives up rather than waits:
/// the entry stays collectable for as long as it stays dead.
///
/// A host that can hold no lock at all is given up on in the same silence, `list`'s job being
/// to print rather than to explain why a sweep behind it did nothing. A user who wants that
/// session gone runs `kill`, which says.
fn collect(paths: &SessionPaths) {
    let Some(lock) = paths.try_lock_spawn() else {
        return;
    };
    if matches!(liveness(&paths.socket(), LIST_PROBE), Liveness::Stale(_)) {
        // Ignored, unlike `kill`: this is opportunistic tidying behind a `list`, with no
        // caller waiting on an answer and nothing lost by trying again.
        drop(paths.unlink_all_locked(&lock));
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use std::{fs, io, thread};

    use rustix::io::Errno;
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open};

    use super::{
        Chosen, MAX_CMDLINE_LEN, bound_since, is_daemon_for, names_daemon_for, pin, still_answering,
    };
    use crate::rundir::SessionPaths;

    /// Joins argv the way `/proc/<pid>/cmdline` presents it, minus the trailing NUL
    /// that [`is_daemon_for`](super::is_daemon_for) has already trimmed.
    fn cmdline(args: &[&str]) -> Vec<u8> {
        args.join("\0").into_bytes()
    }

    /// Whether this host has `pidfd_open` at all, asked of the syscall rather than
    /// through [`pin`](super::pin) — a skip the code under test can talk its way into is
    /// no skip. Pid 1 always names a process and needs no permission to hold, so a
    /// failure can only mean the call is not there; the reason is printed because a
    /// silent skip is a pass.
    fn kernel_has_pidfds(what: &str) -> bool {
        let opened = pidfd_open(Pid::INIT, PidfdFlags::empty());
        if let Err(err) = &opened {
            eprintln!("skipped: this host has no pidfds ({err}), so {what}");
        }
        opened.is_ok()
    }

    /// A descriptor onto a process goes on meaning that process and no other: once it
    /// has exited *and been reaped* — the reaping is the point of the `wait`, freeing
    /// the number — a signal through it answers `ESRCH` rather than reaching whoever
    /// wears the number next. This is the property [`pin`](super::pin)'s ordering turns
    /// into [`kill`](super::kill)'s guarantee, pinned here because no test can make the
    /// kernel reissue a chosen number. `SIGCONT` because the assertion is that it
    /// arrives nowhere, and one that did reach a stranger should cost them nothing.
    #[test]
    fn a_pidfd_outlives_its_process_without_ever_meaning_another() {
        if !kernel_has_pidfds("there is nothing to hold a process by") {
            return;
        }
        let mut child = Command::new("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start a process to hold");
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("a pid fits in an i32"))
            .expect("a spawned child has a pid");

        let Ok(pidfd) = pin(pid) else {
            child.kill().expect("stop the process");
            child.wait().expect("reap it");
            panic!("`pin` gave up no descriptor on a host that has them");
        };
        child.kill().expect("stop the held process");
        // Reaped, so the number is the kernel's to hand out again.
        child.wait().expect("reap the held process");

        let chosen = Chosen {
            pid,
            reach: Ok(pidfd),
        };
        assert_eq!(
            chosen
                .signal(Signal::CONT)
                .map_err(|err| err.raw_os_error()),
            Err(Some(libc::ESRCH)),
            "the signal reached something, so the descriptor is following the number \
             rather than the process it was opened on"
        );
    }

    /// The refusal after both graces says what the escalation did, and a
    /// [`Chosen::reach`](super::Chosen::reach) that sent nothing is never described as
    /// having sent two signals. Put to the sentence where it is built rather than to a
    /// `kill`: a declined descriptor over a session that goes on answering is a state
    /// nothing a test may do can arrange.
    #[test]
    fn a_refusal_names_no_signal_that_was_never_sent() {
        let pid = Pid::from_raw(999_999_999).expect("a positive number is a pid");
        let unheld = Chosen {
            pid,
            reach: Err(Errno::MFILE.into()),
        };
        let term = unheld.signal(Signal::TERM);
        let kill = unheld.signal(Signal::KILL);
        let unheld = still_answering("one", &unheld, &term, &kill);
        assert!(
            !unheld.contains("SIGTERM and SIGKILL to"),
            "no signal went out, so none may be named as having gone out — that sentence \
             also says the pid is the wrong one, which nothing here established: \
             {unheld:?}"
        );
        assert!(
            unheld.contains("neither SIGTERM nor SIGKILL was sent")
                && unheld.contains("Too many open files"),
            "what happened is that the process could not be held, and the errno that \
             declined it is the whole of what says why: {unheld:?}"
        );

        // The other direction, and the one every test of `kill` reaches: a signal that
        // did go out is still reported as having gone out, over a session that outlived
        // it. A held descriptor is the only reach that signals, so it is the only one
        // this half can be asked of.
        if kernel_has_pidfds("nothing here signals, so the sentence goes unchecked") {
            let pidfd = pidfd_open(Pid::INIT, PidfdFlags::empty()).expect("hold pid 1");
            let signalled = Chosen {
                pid,
                reach: Ok(pidfd),
            };
            let signalled = still_answering("one", &signalled, &Ok(()), &Ok(()));
            assert!(
                signalled.contains("still answering after SIGTERM and SIGKILL to pid 999999999"),
                "a session that outlasted a signal that was sent says so, and names the \
                 number it was sent to: {signalled:?}"
            );
        }
    }

    /// A `kill` overtaken by a spawn refuses as `AddrInUse` and names both the id and the
    /// socket now bound — the two things that tell this apart from a `kill` that merely
    /// failed, and the pair that makes running the command again the obvious repair.
    ///
    /// Put to the sentence rather than to a `kill`, because the state cannot be arranged from
    /// outside: [`resolve`](super::resolve) answers `Ok(None)` only from a `Stale` probe, and
    /// the re-probe under the lock is the next statement, with no sleep, lock wait or syscall
    /// between the two for a test to gate a spawn on. The window is microseconds wide, so an
    /// integration test would be asserting on a race it loses almost every run.
    #[test]
    fn a_kill_overtaken_by_a_spawn_names_the_session_and_the_socket_it_left_alone() {
        let paths = SessionPaths::in_dir(Path::new("/run/user/1000/nomux"), "one")
            .expect("a short id under a short directory resolves");
        let err = bound_since(&paths);

        assert_eq!(
            err.kind(),
            io::ErrorKind::AddrInUse,
            "a daemon holding the id is an address in use, not the invalid data every other \
             refusal here reports: {err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("session one is answering")
                && message.contains("/run/user/1000/nomux/one.sock"),
            "the refusal has to say which session was left alone and where it is answering: \
             {message:?}"
        );
    }

    /// Regression: a command line too long to read the end of is still a definitive "no"
    /// where `argv[1]` arrived whole — read as "could not tell", a recycled pid whose
    /// command line overran the buffer would be signalled (§ 6.6).
    ///
    /// A shell blocked on `read`: it takes the padding as `$0`, execs nothing, and leaves
    /// no grandchild behind when this stops it. The command line is waited for rather
    /// than assumed, `/proc/<pid>/cmdline` showing the *parent's* argv until the `exec`
    /// lands.
    #[test]
    fn a_long_command_line_that_is_not_a_daemon_is_answered_rather_than_left_unknown() {
        let padding = "x".repeat(MAX_CMDLINE_LEN);
        let mut child = Command::new("sh")
            .args(["-c", "read line", &padding])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start a process whose command line runs past the buffer");
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("a pid fits in an i32"))
            .expect("a spawned child has a pid");

        let cmdline = format!("/proc/{}/cmdline", child.id());
        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = loop {
            let seen = fs::read(&cmdline).unwrap_or_default();
            if seen.len() > MAX_CMDLINE_LEN || Instant::now() >= deadline {
                break seen;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let answer = is_daemon_for(pid, "one");
        child.kill().expect("stop the process");
        child.wait().expect("reap it");

        assert!(
            seen.len() > MAX_CMDLINE_LEN,
            "the fixture must overrun the buffer, or this asserts nothing: {} bytes",
            seen.len()
        );
        assert_eq!(
            answer,
            Some(false),
            "a command line whose `argv[1]` was read in full and is not `daemon` is a \
             positive `it is not`, whatever the read could not reach past it"
        );
    }

    /// Regression: a label is not an id, however much it looks like one in argv. The
    /// collision needs no attacker — a label equal to some other tab's id does it, and a
    /// client mints both.
    #[test]
    fn a_label_never_stands_in_for_the_id() {
        for (argv, describing) in [
            (vec!["nomux", "daemon", "one", "--label", "two"], "after"),
            (vec!["nomux", "daemon", "--label", "two", "one"], "before"),
            (vec!["nomux", "daemon", "--label=two", "one"], "joined"),
        ] {
            let whole = cmdline(&argv);
            assert!(
                names_daemon_for(&whole, "one"),
                "a daemon with its label {describing} the id is still `one`'s: {argv:?}"
            );
            assert!(
                !names_daemon_for(&whole, "two"),
                "a label {describing} the id made this daemon `two`'s as well: {argv:?}"
            );
        }
    }

    /// The process class § 6.6 names as excluded, in both relay modes. The `attach
    /// --label` forms stay because this reads `/proc`, where a command line from any
    /// version may be found, rather than what this build's `main` will accept.
    #[test]
    fn a_relay_is_not_the_daemon_whatever_its_label_says() {
        for argv in [
            vec!["nomux", "attach", "--label", "daemon", "one"],
            vec!["nomux", "attach", "one", "--label", "daemon"],
            vec!["nomux", "attach", "one"],
            vec!["nomux", "spawn", "--label", "daemon", "one"],
            vec!["nomux", "spawn", "one", "--label", "daemon"],
            vec!["nomux", "spawn", "one"],
        ] {
            assert!(
                !names_daemon_for(&cmdline(&argv), "one"),
                "a relay was taken for the daemon it spawned: {argv:?}"
            );
        }
    }

    /// The ordinary shapes still resolve, including the hand-typed one § 6.2 documents.
    #[test]
    fn the_plain_command_lines_still_name_their_session() {
        assert!(names_daemon_for(
            &cmdline(&["nomux", "daemon", "one"]),
            "one"
        ));
        assert!(names_daemon_for(
            &cmdline(&["/opt/nomux-0.2.0", "daemon", "one"]),
            "one"
        ));
        assert!(names_daemon_for(
            &cmdline(&["nomux", "daemon", "--lock-fd", "7", "one"]),
            "one"
        ));
        assert!(names_daemon_for(
            &cmdline(&["nomux", "daemon", "--lock-fd=7", "one"]),
            "one"
        ));
        assert!(names_daemon_for(
            &cmdline(&["nomux", "daemon", "one", "--lock-fd=7"]),
            "one"
        ));
        assert!(
            !names_daemon_for(&cmdline(&["nomux", "daemon", "--lock-fd", "7", "one"]), "7"),
            "the inherited descriptor number is not the session id"
        );
        // Whole arguments, so one id is never a prefix of another.
        assert!(!names_daemon_for(
            &cmdline(&["nomux", "daemon", "one0"]),
            "one"
        ));
        assert!(!names_daemon_for(&cmdline(&["nomux", "daemon"]), "one"));
        assert!(!names_daemon_for(&[], "one"));
    }

    /// Identification must reject every daemon-like command line the actual daemon
    /// parser rejects, or `kill` can signal a process that only shares its argv prefix.
    #[test]
    fn malformed_daemon_command_lines_do_not_name_a_session() {
        for argv in [
            vec!["nomux", "daemon", "one", "extra"],
            vec!["nomux", "daemon", "--unknown", "one"],
            vec!["nomux", "daemon", "--label"],
            vec!["nomux", "daemon", "--label=a", "--label=b", "one"],
            vec!["nomux", "daemon", "--lock-fd=2", "one"],
            vec!["nomux", "daemon", "--lock-fd=nope", "one"],
            vec!["nomux", "daemon", "--lock-fd=7", "--lock-fd=8", "one"],
        ] {
            assert!(
                !names_daemon_for(&cmdline(&argv), "one"),
                "accepted malformed daemon argv: {argv:?}"
            );
        }

        assert!(
            !names_daemon_for(b"nomux\0daemon\0one\0--label\0\xff", "one"),
            "accepted an argv value the command-line parser cannot decode"
        );
    }
}
