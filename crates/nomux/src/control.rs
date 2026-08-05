//! The frozen control surface: `list` and `kill` (§ 6.6, `DESIGN.md` § 6.4).
//!
//! These must work against a daemon of *any* version, so the contract here is the
//! on-disk layout — never a protocol frame, never `PROTOCOL_VERSION`.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process, test_kill_process};

use crate::rundir::{
    MAX_PID_LEN, MAX_SESSION_ID_LEN, SessionPaths, SpawnLock, check_run_dir, connect_within,
    nothing_is_listening, parse_pid, read_label, read_prefix, run_dir, session_ids,
};

/// How long a probe of a session socket waits for an answer.
///
/// Bounded at all because an `AF_UNIX` `connect` to a full backlog blocks rather than being
/// refused (§ 6.3). Two seconds, the budget every other wait here is given.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// What `list` gives a probe instead. Nothing, because only [`Liveness::Stale`] changes
/// what it does with a session, and every errno behind `Stale` is settled on the first
/// attempt ([`connect_within`]) — waiting a full backlog out would cost two seconds per
/// wedged daemon to print the same line.
const LIST_PROBE: Duration = Duration::ZERO;

/// How long a terminated daemon has to exit before it is killed outright.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// How long a killed daemon has to actually go before `kill` concludes that the signal
/// never reached whatever is serving the socket.
///
/// Nothing survives `SIGKILL`, so this is never observed of an ordinary daemon. What it
/// bounds is the case where the pid signalled is *not* the process behind the socket.
const KILL_GRACE: Duration = Duration::from_millis(500);

/// How often to look again while waiting any of the graces out. One interval for all of
/// them: each waits on another process reaching a point of its own.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// How long `kill` waits for the spawn lock before giving up (see [`hold_spawn_lock`]).
const SPAWN_LOCK_GRACE: Duration = Duration::from_secs(2);

/// How long `kill` waits for a live daemon to publish `<id>.pid` (§ 6.6): the daemon binds
/// its socket before it writes the pidfile (§ 6.2), so a `kill` landing in that window
/// finds a session unmistakably there and no pid to signal.
const PUBLISH_GRACE: Duration = Duration::from_secs(2);

/// The kernel's longest path, which is what bounds a resolved `argv[0]`.
const PATH_MAX: usize = 4096;

/// Longest `/proc/<pid>/cmdline` prefix [`is_daemon_for`] reads: `argv[0]`, bounded by the
/// kernel's [`PATH_MAX`] rather than by anything this program picks, then the mode, then an
/// id of at most [`MAX_SESSION_ID_LEN`], with a NUL after each. Deliberately *not* sized
/// for the whole command line, which has no bound: nothing past the id is read as
/// anything but padding.
const MAX_CMDLINE_LEN: usize = PATH_MAX + 1 + "daemon".len() + 1 + MAX_SESSION_ID_LEN + 1;

/// State of one session as seen from the run directory alone.
#[derive(Debug)]
pub(crate) enum Liveness {
    /// A daemon accepted this connection, so a process is serving the socket.
    Alive(UnixStream),
    /// Nothing is listening; the daemon died. Carries the errno, which is what says
    /// whether a socket file was left behind to replace.
    Stale(io::Error),
    /// The `connect` failed for a reason that is not death, carrying it.
    ///
    /// § 6.3's "`EACCES` is not staleness": the same conservative answer as
    /// [`Self::Alive`] for the *unlink*, and its opposite everywhere else, since only an
    /// accepted connection may escalate to `SIGKILL`.
    Unknown(io::Error),
}

/// Turns the § 6.3 run-directory check into "is there one?" rather than an error to be
/// matched. Both modes read its absence as the question already answered.
fn present(checked: io::Result<()>) -> io::Result<bool> {
    match checked {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Prints one line per live session: id, pid and label.
///
/// A reader that closes stdout early ends the listing (§ 10) but not the sweep, since
/// returning early would make `head` the reason a stale session survived.
///
/// # Errors
///
/// Fails on a run directory that is not this user's alone (§ 6.3). A missing one is not
/// an error — no session has ever been created.
pub(crate) fn list() -> io::Result<()> {
    let dir = run_dir()?;
    // § 6.3, before any name in this directory is trusted.
    if !present(check_run_dir(&dir))? {
        return Ok(());
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut listening = true;
    for id in session_ids(&dir) {
        let Ok(paths) = SessionPaths::new(&id) else {
            continue;
        };
        // Only death collects (§ 6.3); a probe that failed for any other reason leaves a
        // session to list.
        if matches!(liveness(&paths.socket(), LIST_PROBE), Liveness::Stale(_)) {
            collect(&paths);
            continue;
        }
        // Nowhere left to print to, and the sweep above is the whole reason the loop
        // goes on anyway.
        if !listening {
            continue;
        }
        let mut buf = [0u8; MAX_PID_LEN];
        let (filed, _) = pidfile(&paths.pid(), &mut buf).unwrap_or_default();
        let pid = chosen(&paths, filed)
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
/// # Errors
///
/// Fails on an invalid session id, on a run directory that is not this user's alone
/// (§ 6.3), and on the states § 6.6 lists behind a non-zero `kill` — plus [`unprobeable`]
/// and [`bound_since`], which come from the probe rather than from the session. A session
/// that is already gone is not an error: the postcondition already holds.
pub(crate) fn kill(session_id: &str) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    // The same check `list` makes, and this is where it bites hardest: what follows reads
    // a pid out of a file and signals it.
    if !present(paths.check_dir())? {
        return Ok(());
    }
    // Held from here to the end of the function (§ 6.6): without it, an attach that starts
    // a fresh daemon between the signal below and the unlink that follows loses its socket
    // to a kill it was never the target of. What the lock does not exclude is a daemon
    // started by hand, which is why the unlink probes again rather than trusting this.
    let lock = hold_spawn_lock(&paths)?;
    if let Some(pid) = resolve(&paths)? {
        let _ = kill_process(pid, Signal::TERM);
        // Liveness first, deadline second, so a daemon that let go on the last interval
        // is not signalled again: the pid it published is reusable the moment it is
        // reaped, and `SIGKILL` is the one signal nothing survives.
        let mut deadline = Instant::now() + TERM_GRACE;
        let mut killed = false;
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
                // Still answering after `SIGKILL`, which nothing survives — so the pid
                // signalled is not the process serving this socket. Reachable only from
                // the arm above that accepted a connection, which makes every clause of
                // the sentence below true.
                if killed {
                    return Err(refuse(format!(
                        "session {id} is still answering after SIGTERM and SIGKILL to \
                         pid {pid}, so that pid is not the process serving it; leaving \
                         it alone rather than unlinking a live session's files",
                        id = paths.id(),
                        pid = pid.as_raw_nonzero(),
                    )));
                }
                let _ = kill_process(pid, Signal::KILL);
                killed = true;
                deadline = Instant::now() + KILL_GRACE;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
    // Probed once more, under the lock and immediately before the unlink, because that is
    // the only point at which the answer cannot change between being read and being acted
    // on (§ 6.6) — where [`collect`] also decides, and the two must agree. What it closes
    // is the daemon somebody started by hand, which § 6.3 lets bind *without* the spawn
    // lock when it cannot take one, and so inside this locked region.
    match liveness(&paths.socket(), PROBE_TIMEOUT) {
        // The one *successful* exit from the locked region, and so the one place the files
        // go: already gone, stopped on `SIGTERM` and killed outright all end up here.
        Liveness::Stale(_) => paths.unlink_all_locked(&lock),
        Liveness::Alive(_) => Err(bound_since(&paths)),
        Liveness::Unknown(err) => Err(unprobeable(&paths, &err)),
    }
}

/// Takes the spawn lock for the whole of a `kill`, waiting briefly for it (§ 6.6).
///
/// Bounded rather than a blocking `flock` because a process that stopped holding it is
/// not a reason for the escape hatch to hang forever.
///
/// # Errors
///
/// Reports [`io::ErrorKind::ResourceBusy`] when the lock is still held at the deadline,
/// rather than claim a postcondition it did not establish.
fn hold_spawn_lock(paths: &SessionPaths) -> io::Result<SpawnLock> {
    let deadline = Instant::now() + SPAWN_LOCK_GRACE;
    loop {
        if let Some(lock) = paths.try_lock_spawn() {
            return Ok(lock);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "session {} is being started or removed by another process",
                    paths.id()
                ),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Which process a locked session's daemon is, or `None` where nothing is listening and
/// the files are all that is left.
///
/// Liveness first, and only then the pid: a daemon that died without unlinking leaves its
/// pidfile behind and the kernel reuses pids, so signalling a number read off disk
/// unchecked is how `nomux kill` terminates an unrelated process of the user's.
///
/// # Errors
///
/// Reports the reason a live session's pid could not be had.
fn resolve(paths: &SessionPaths) -> io::Result<Option<Pid>> {
    let deadline = Instant::now() + PUBLISH_GRACE;
    loop {
        if matches!(liveness(&paths.socket(), PROBE_TIMEOUT), Liveness::Stale(_)) {
            return Ok(None);
        }
        let mut buf = [0u8; MAX_PID_LEN];
        let waiting_on = match pidfile(&paths.pid(), &mut buf) {
            Ok((filed, body)) if !body.trim_ascii().is_empty() => {
                return chosen(paths, filed)
                    .map(Some)
                    .ok_or_else(|| running_but(paths, &unidentified(paths.id(), filed, body)));
            }
            // Present but empty is the same window one syscall later, so it is waited
            // out too: `SessionPaths::write_pid` creates the file and fills it in two
            // steps, and a reader can land between them.
            Ok(_) => "it was created but never written",
            Err(err) if err.kind() == io::ErrorKind::NotFound => "it never appeared",
            // Unreadable is not the publish window and never becomes it, so it is
            // settled now rather than waited on.
            Err(err) => return Err(running_but(paths, &err.to_string())),
        };
        if Instant::now() >= deadline {
            return Err(running_but(paths, waiting_on));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// The pid a session's pidfile names, and the body it was read from — which
/// [`unidentified`] reports on and `list` discards. Both modes read it through here,
/// because § 6.6 has the number a user reads be the number that would be acted on.
fn pidfile<'a>(path: &Path, buf: &'a mut [u8; MAX_PID_LEN]) -> io::Result<(Option<Pid>, &'a [u8])> {
    let body = read_prefix(path, buf)?;
    Ok((parse_pid(body).and_then(extant), body))
}

/// The published pid, where `/proc` does not rule it out.
///
/// Shared by both modes, so the number `list` prints is the number `kill` would signal —
/// which matters most in the case `kill` refuses, since it recommends no repair there and
/// a user who wants to act asks `list` what to signal.
///
/// Only a *positive* "it is not" declines it, which is § 6.6's weighing: refusing on
/// "could not tell" would strand every session whose daemon sits behind `hidepid`.
///
/// It asks what a process *is*, not which holds the *fd*: matching a `sockfs` inode would
/// mean parsing `/proc/net/unix` on the surface that has to keep working anywhere, and
/// what that gives up — a second `nomux daemon <id>` that is not this one — § 6.3's bind
/// already makes unreachable.
fn chosen(paths: &SessionPaths, filed: Option<Pid>) -> Option<Pid> {
    filed.filter(|pid| is_daemon_for(*pid, paths.id()) != Some(false))
}

/// A number that still names a process this user may signal, or nothing.
///
/// A number naming nothing is not evidence, so it is neither signalled nor reported as a
/// pid. It cannot tell a reissued number from the original, which is why [`chosen`] asks
/// [`is_daemon_for`] as well.
fn extant(pid: i32) -> Option<Pid> {
    let pid = Pid::from_raw(pid)?;
    test_kill_process(pid).is_ok().then_some(pid)
}

/// Whether `pid` is a `nomux daemon <id>` process, where that can be established.
///
/// The command line rather than the executable's name, since § 5.2 installs under a
/// version-stamped one: `spawn` starts the daemon as `<exe> daemon <id>` and § 6.2
/// documents the same words typed by hand.
///
/// `None` is "could not tell", and keeping it apart from `Some(false)` is the whole reason
/// this returns an `Option`: an invisible daemon is a session [`chosen`] refuses to
/// identify for as long as it runs. So finding the pair is an answer whether or not the
/// read reached the end — which keeps a session with a long `--label` killable — and only
/// *failing* to find it leaves the truncation to decide.
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
    if names_daemon_for(whole, id) {
        return Some(true);
    }
    // Not there — which is only news if the read saw everything there was.
    (body.len() < MAX_CMDLINE_LEN).then_some(false)
}

/// Whether a NUL-separated command line is `<exe> daemon <id>`, however it was spelled.
///
/// Parsed the way [`main::parse_session_args`](crate::main) parses it, rather than
/// searched: a search answers to any command line that merely *contains* both words, and
/// `--label` puts caller-supplied text into that same argv.
///
/// Read against whatever `/proc` holds rather than against what this build can produce,
/// which is why an `attach --label` still parses here after `main` stopped accepting one.
fn names_daemon_for(whole: &[u8], id: &str) -> bool {
    let mut args = whole.split(|byte| *byte == 0);
    args.next();
    if args.next() != Some(b"daemon".as_slice()) {
        return false;
    }
    let mut session = None;
    while let Some(arg) = args.next() {
        if arg == b"--label" {
            // The value is the next argument, and must not be read as the id.
            args.next();
        } else if !arg.starts_with(b"-") {
            session.get_or_insert(arg);
        }
    }
    session == Some(id.as_bytes())
}

/// The shape every refusal here takes: something in the run directory said what this
/// call would not act on, which is [`io::ErrorKind::InvalidData`] and § 10's code for it.
fn refuse(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The refusal to touch a live session whose pid is not knowable.
///
/// It names the pidfile because that is the one thing the user can repair, and it says
/// what was *not* done, since "kill failed" reads like "the session is still running" —
/// which is exactly right here, and is the point.
fn running_but(paths: &SessionPaths, problem: &str) -> io::Error {
    refuse(format!(
        "session {id} is running, but {pid}: {problem}; leaving it alone rather than \
         unlinking a live session's files",
        id = paths.id(),
        pid = paths.pid().display(),
    ))
}

/// Why [`chosen`] came back with nothing over a session that is answering, in the words
/// [`running_but`] finishes.
///
/// The three read very differently to whoever has to act on them, and only the middle one —
/// a body that reached the bound ([`parse_pid`]) — is a file to repair. That one is quoted
/// as bytes rather than as a number: its end was never read, so showing a pid and calling it
/// unusable would be worse than showing none.
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

/// The refusal to decide a session's fate on a probe that never reached it.
///
/// § 6.3 makes an `EACCES`, a descriptor limit and an undrained backlog evidence of
/// neither death nor life, so none may be built into a refusal that says a session is
/// *answering*. Naming the errno is the whole of what is known, and the useful half:
/// each is repairable from outside.
fn unprobeable(paths: &SessionPaths, problem: &io::Error) -> io::Error {
    refuse(format!(
        "session {id}: {sock} could not be probed, so whether it has stopped was never \
         established: {problem}; leaving its files alone rather than unlinking what \
         may be a live session",
        id = paths.id(),
        sock = paths.socket().display(),
    ))
}

/// The refusal to collect a session that answered again under the lock.
///
/// Rare by construction and reported rather than swallowed, because it reads two ways: a
/// daemon that bound the id inside this locked region is a live session to leave alone,
/// and it is also this `kill` having been overtaken by a spawn. Running the command again
/// is the whole of the repair.
fn bound_since(paths: &SessionPaths) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "session {id} is answering on {sock} again: a daemon has bound the id since \
             this kill established it was gone, so those files are its own and not this \
             call's to remove",
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

/// Probes the socket. A refused connection means the daemon is gone; the socket file
/// outlives the process that bound it.
///
/// Through [`connect_within`], which owns the argument for the deadline.
pub(crate) fn liveness(socket: &Path, within: Duration) -> Liveness {
    match connect_within(socket, within) {
        Ok(stream) => Liveness::Alive(stream),
        Err(err) if nothing_is_listening(&err) => Liveness::Stale(err),
        // Evidence of neither death nor life — see [`Liveness::Unknown`].
        Err(err) => Liveness::Unknown(err),
    }
}

#[cfg(test)]
mod tests {
    use super::names_daemon_for;

    /// Joins argv the way `/proc/<pid>/cmdline` presents it, minus the trailing NUL
    /// that [`is_daemon_for`](super::is_daemon_for) has already trimmed.
    fn cmdline(args: &[&str]) -> Vec<u8> {
        args.join("\0").into_bytes()
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
        // Whole arguments, so one id is never a prefix of another.
        assert!(!names_daemon_for(
            &cmdline(&["nomux", "daemon", "one0"]),
            "one"
        ));
        assert!(!names_daemon_for(&cmdline(&["nomux", "daemon"]), "one"));
        assert!(!names_daemon_for(&[], "one"));
    }
}
