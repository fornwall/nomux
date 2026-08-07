//! The frozen control surface: `list` and `kill` (§ 6.6, `DESIGN.md` § 6.4).
//!
//! These must work against a daemon of *any* version, so the contract here is the
//! on-disk layout — never a protocol frame, never `PROTOCOL_VERSION`.
//!
//! Those two modes and nothing else. The socket probe all of this is written against is
//! [`crate::usock::liveness`], where the daemon's bind and the attach paths reach it
//! without reading a line of a file § 6.6 froze.

use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal, test_kill_process};

use crate::rundir::{
    MAX_PID_LEN, MAX_SESSION_ID_LEN, SessionPaths, SpawnLock, check_run_dir, parse_pid, read_label,
    read_prefix, run_dir, session_ids,
};
use crate::usock::{Liveness, liveness};

/// How long a probe of a session socket waits for an answer.
///
/// Bounded at all because an `AF_UNIX` `connect` to a full backlog blocks rather than being
/// refused (§ 6.3). Two seconds, the budget every other wait here is given, and spent in
/// full only against that backlog — a session that really has stopped answers
/// `ECONNREFUSED` on the first attempt.
///
/// Deliberately *not* clamped to whatever grace remains, so each deadline below is checked
/// after a probe rather than bounding one. § 6.6 has why, and what a stage overrunning its
/// grace by a whole probe compounds to.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// What `list` gives a probe instead. Nothing, because only [`Liveness::Stale`] changes
/// what it does with a session, and every errno behind `Stale` is settled on the first
/// attempt ([`crate::usock::connect_within`]) — waiting a full backlog out would cost two
/// seconds per wedged daemon to print the same line.
const LIST_PROBE: Duration = Duration::ZERO;

/// How long `kill` gives another process to reach a point of its own: the spawn lock to
/// come free (§ 6.6), a live daemon to publish `<id>.pid`, and a terminated one to exit
/// before it is killed outright.
///
/// One figure for the three because each is the same bet — a process still on its way arrives
/// in milliseconds, and an escape hatch that waited longer would be one nobody can use. The
/// publish wait is the least obvious of them: the daemon binds its socket before it writes
/// the pidfile (§ 6.2), so a `kill` landing in that window finds a session unmistakably there
/// and no pid to signal.
const GRACE: Duration = Duration::from_secs(2);

/// How long a killed daemon has to actually go before `kill` concludes that the signal
/// never reached whatever is serving the socket.
///
/// Nothing survives `SIGKILL`, so this is never observed of an ordinary daemon. What it
/// bounds is the case where the pid signalled is *not* the process behind the socket —
/// and the case where there was no signal to survive, [`pin`] having given nothing to send
/// one through, which is why the refusal at the end of it is [`still_answering`]'s to word
/// rather than one sentence.
const KILL_GRACE: Duration = Duration::from_millis(500);

/// How often to look again while waiting any of the graces out. One interval for all of
/// them: each waits on another process reaching a point of its own.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The kernel's longest path, which is as long as `argv[0]` gets for a daemon *this*
/// program starts: `spawn` execs it by a resolved path (§ 5.2).
const PATH_MAX: usize = 4096;

/// Longest `/proc/<pid>/cmdline` prefix [`is_daemon_for`] reads: enough for a well-formed
/// `nomux daemon <id>`, which is a path of at most [`PATH_MAX`], the mode, and an id of at
/// most [`MAX_SESSION_ID_LEN`], with a NUL after each.
///
/// A bound on what this program *writes*, and on nothing it may be pointed at: `execve` lets
/// `argv[0]` be any length at all, and the pid here is whatever number a pidfile named. What
/// settles a read that filled this buffer is [`is_daemon_for`]'s rule about `argv[1]`, never
/// the size of it.
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
    for id in session_ids(&dir) {
        // Against the directory already resolved above rather than one per entry: it is the
        // directory these names came out of, so re-reading the environment could only
        // disagree with the `read_dir` this is iterating.
        let paths = match SessionPaths::in_dir(&dir, &id) {
            Ok(paths) => paths,
            // § 6.3's `sun_path` refusal, a property of this directory rather than of the id,
            // so this is the one session `list` can neither print nor collect.
            Err(err) => {
                eprintln!("nomux: {err}; its files are left where they are");
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
    // kill it was never the target of.
    let lock = hold_spawn_lock(&paths)?;
    if let Some(chosen) = resolve(&paths)? {
        chosen.signal(Signal::TERM);
        // Liveness first, deadline second, so a daemon that let go on the last interval is
        // not signalled again — `SIGKILL` being the one signal nothing survives, and the
        // descriptor guaranteeing only that it lands on the process this call pinned.
        let mut deadline = Instant::now() + GRACE;
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
                // Both graces out with the socket still answering — reached only from the arm
                // above that accepted a connection. What the escalation actually did is
                // [`still_answering`]'s to say rather than this call site's.
                if killed {
                    return Err(refuse(still_answering(paths.id(), &chosen)));
                }
                chosen.signal(Signal::KILL);
                killed = true;
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

/// Takes the spawn lock for the whole of a `kill`, waiting briefly for it (§ 6.6).
///
/// Bounded rather than a blocking `flock` because a process that stopped holding it is
/// not a reason for the escape hatch to hang forever.
///
/// # Errors
///
/// Reports [`io::ErrorKind::ResourceBusy`] when the lock is still held at the deadline,
/// rather than claim a postcondition it did not establish — and passes on the refusal a
/// host that can hold no lock at all earns, which polling would only turn into that same
/// busy message about a process that does not exist.
fn hold_spawn_lock(paths: &SessionPaths) -> io::Result<SpawnLock> {
    let deadline = Instant::now() + GRACE;
    loop {
        if let Some(lock) = paths.try_lock_spawn_or_refuse()? {
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
                // reason to stop signalling a daemon this one has positively named. Nothing
                // is unlinked on the strength of it — every exit from [`kill`] still goes
                // through a probe that has to say the session stopped.
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
fn pidfile<'a>(path: &Path, buf: &'a mut [u8; MAX_PID_LEN]) -> io::Result<(Option<Pid>, &'a [u8])> {
    let body = read_prefix(path, buf)?;
    Ok((parse_pid(body).and_then(extant), body))
}

/// The process `kill` acts on: the number the pidfile named, and a hold on the process
/// that number meant when it was read.
///
/// The two are not the same thing, and that is the whole reason this is a struct. A pid is a
/// number the kernel is free to reissue the moment its process is reaped, while [`kill`]
/// signals twice with a [`GRACE`] in between and reads `/proc` before either.
#[derive(Debug)]
struct Chosen {
    /// What the refusals print and what `list` shows: a descriptor is nothing a user can
    /// carry to another command, so the number is still the whole of what is reportable.
    pid: Pid,
    /// What the signals go through, or the errno that would give none up — the only thing
    /// here that ever signals, for [`pin`]'s reason.
    ///
    /// An error is no descriptor, so nothing is signalled and [`kill`] settles what became of
    /// the session by probing the socket alone. Only [`still_answering`] reads the errno,
    /// that being the one path where the difference is visible.
    reach: io::Result<OwnedFd>,
}

impl Chosen {
    /// Signals the daemon, where [`pin`] got a descriptor to signal it through.
    ///
    /// The outcome is dropped because there is none worth reading: a process that took the
    /// first signal and died answers the second with `ESRCH`, which is this working rather
    /// than failing, and [`kill`] settles what happened by probing the socket either way.
    fn signal(&self, sig: Signal) {
        if let Ok(pidfd) = &self.reach {
            let _ = pidfd_send_signal(pidfd, sig);
        }
    }
}

/// Takes hold of the process a number names, before anything at all is established about it.
///
/// The order is the whole of this. Every check [`chosen`] then makes reads `/proc/<pid>`, and
/// a check made through a number can only describe whoever wears it at the instant of the
/// read — so pinning first is what makes the check and the signal be about one process. Reuse
/// before this call leaves the impostor to fail the check below; reuse after it leaves this
/// descriptor still meaning the process that passed. The one impostor that could pass is a
/// second `nomux daemon <id>`, which the spawn lock `kill` holds excludes (§ 6.3).
///
/// A descriptor is had without permission to signal, which is why [`extant`] still asks that
/// separately.
///
/// A failure of any kind signals nothing at all, § 6.6 delegating the argument here. There is
/// no falling back on the bare number: doing that accepts the reuse race this call exists to
/// close, and the errno that most invites it — `ESRCH`, a process already reaped — is the one
/// under which the race is not a risk but a certainty. A host with no `pidfd_open` (`ENOSYS`
/// below 5.3, or a sandbox answering `EINVAL`/`EPERM`) therefore gets a `kill` that refuses
/// and names the errno rather than one that signals a number it cannot vouch for. That
/// refusal is recoverable — `list` still prints the pid, so the number is a `kill(1)` away —
/// where a signal delivered to a stranger's process is not.
fn pin(pid: Pid) -> io::Result<OwnedFd> {
    pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from)
}

/// The published pid, where `/proc` does not rule it out.
///
/// Shared by both modes, so the number `list` prints is the number `kill` would signal —
/// which matters most in the case `kill` refuses, since it recommends no repair there and a
/// user who wants to act asks `list` what to signal. § 6.6 has the rest of the weighing.
fn identified(paths: &SessionPaths, filed: Option<Pid>) -> Option<Pid> {
    let pid = filed?;
    (is_daemon_for(pid, paths.id()) != Some(false)).then_some(pid)
}

/// [`identified`], held by the process rather than by the number ([`pin`]).
///
/// For `kill`, which is what needs the hold. These two lines are in that order for [`pin`]'s
/// reason and no other: swapping them gives the window back. `list` prints a number and
/// signals nothing, so it goes through [`identified`] alone rather than opening a descriptor
/// per session to drop unread.
fn chosen(paths: &SessionPaths, filed: Option<Pid>) -> Option<Chosen> {
    let reach = pin(filed?);
    identified(paths, filed).map(|pid| Chosen { pid, reach })
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
/// `None` is "could not tell", which [`chosen`] admits — so a `None` here is a `SIGTERM` and
/// then a `SIGKILL` to whatever wears the number. § 6.6 has why it is kept apart from
/// `Some(false)` all the same, and how narrowly truncation is allowed to produce it.
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
    // Not there. A read that ended before the buffer did saw the whole command line, and one
    // that filled it still settles the question wherever `argv[1]` arrived whole — which is
    // exactly when `whole` holds a NUL, [`names_daemon_for`] bailing on the mode strictly
    // before the truncation could reach anything it reads. Both are a definitive "no".
    (body.len() < MAX_CMDLINE_LEN || whole.contains(&0)).then_some(false)
}

/// Whether a NUL-separated command line is `<exe> daemon <id>`, however it was spelled.
///
/// Parsed the way [`main::parse_session_args`](crate::main) parses it rather than searched,
/// which is § 6.6's rule and its reason.
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
        if arg == b"--label" || arg == b"--lock-fd" {
            // Option values are never session ids. `--lock-fd` is the private
            // descriptor capability a relay hands its daemon at `exec`.
            args.next();
        } else if !arg.starts_with(b"--label=")
            && !arg.starts_with(b"--lock-fd=")
            && !arg.starts_with(b"-")
        {
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

/// The refusal to touch a live session whose pid is not knowable. It names the pidfile
/// because that is the one thing the user can repair.
fn running_but(paths: &SessionPaths, problem: &str) -> io::Error {
    refuse(format!(
        "session {id} is running, but {pid}: {problem}; leaving it alone rather than \
         unlinking a live session's files",
        id = paths.id(),
        pid = paths.pid().display(),
    ))
}

/// Which refusal a session [`resolve`] could not name a process for has earned — decided
/// by the probe rather than by the pidfile.
///
/// [`running_but`] opens by saying the session *is running*, and only a connection a daemon
/// accepted ever established that. Where the probe failed instead, § 6.3 makes it evidence of
/// neither death nor life, so [`unprobeable`] names the errno and leaves the pidfile
/// unmentioned — a file that was never going to be asked for.
fn unresolved(paths: &SessionPaths, unprobed: Option<&io::Error>, problem: &str) -> io::Error {
    unprobed.map_or_else(
        || running_but(paths, problem),
        |err| unprobeable(paths, err),
    )
}

/// Why [`chosen`] came back with nothing over a session that is answering, in the words
/// [`running_but`] finishes.
///
/// A body that reached the bound ([`parse_pid`]) is quoted as bytes rather than as a
/// number: its end was never read, so showing a pid and calling it unusable would be worse
/// than showing none.
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

/// The refusal to collect a session that was answering still when both graces ran out, in
/// the words the [`Chosen::reach`] it was escalated *through* earns.
///
/// The answering is established either way — the caller reaches this only from a connection a
/// daemon accepted. The rest turns on whether a signal went out. Through a descriptor one
/// did, so a session that outlived `SIGKILL`, which nothing survives, says the pid signalled
/// is not the process serving the socket. Through an errno none did: `pidfd_open` declined
/// the process before either grace began, so the same two-and-a-half seconds of answering say
/// nothing whatever about the pid, and the errno that declined it is both what is reportable
/// and the only part of the state anybody can repair.
///
/// The graces are waited out under that reach all the same, and not as a formality: the
/// socket is what decides, and [`pin`]'s `ESRCH` is a daemon already on its way out, whose
/// socket falling silent inside them reaches the unlink instead of this sentence.
fn still_answering(id: &str, chosen: &Chosen) -> String {
    let pid = chosen.pid.as_raw_nonzero();
    match &chosen.reach {
        Ok(_) => format!(
            "session {id} is still answering after SIGTERM and SIGKILL to pid {pid}, so \
             that pid is not the process serving it; leaving it alone rather than \
             unlinking a live session's files"
        ),
        Err(err) => format!(
            "session {id} is still answering, and pid {pid} could not be held to be \
             signalled ({err}), so neither SIGTERM nor SIGKILL was sent and nothing here \
             established what is serving it; leaving it alone rather than unlinking a \
             live session's files"
        ),
    }
}

/// The refusal to decide a session's fate on a probe that never reached it: § 6.3 makes an
/// `EACCES`, a descriptor limit and an undrained backlog evidence of neither death nor
/// life, so none may be built into a refusal that says a session is *answering*. Naming the
/// errno is the whole of what is known, and each is repairable from outside.
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
/// Reported rather than swallowed, because it reads two ways: a daemon that bound the id
/// inside this locked region is a live session to leave alone, and it is also this `kill`
/// having been overtaken by a spawn, which running the command again repairs.
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
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

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
    /// through [`pin`](super::pin): the two tests below stand down where it does not,
    /// and a skip the code under test can talk its way into is no skip — a `pin` that
    /// had stopped opening descriptors entirely would otherwise turn both green.
    ///
    /// Pid 1 is the one number that always names a process in whatever pid namespace
    /// this runs in, and no permission is needed to hold a descriptor onto it, so the
    /// only thing left for a failure to mean is the call not being there.
    ///
    /// The reason is printed rather than swallowed, since a skip nobody can see is a
    /// pass — which is how a suite comes to run a check it never exercises.
    fn kernel_has_pidfds(what: &str) -> bool {
        let opened = pidfd_open(Pid::INIT, PidfdFlags::empty());
        if let Err(err) = &opened {
            eprintln!("skipped: this host has no pidfds ({err}), so {what}");
        }
        opened.is_ok()
    }

    /// A descriptor onto a process goes on meaning that process and no other: once it
    /// has exited *and been reaped*, a signal through it answers `ESRCH` rather than
    /// reaching whoever the kernel handed the number to next.
    ///
    /// This is the property [`kill`](super::kill) rests on rather than one of its own
    /// paths, and it is the half no test of `kill` can reach: making the kernel reissue
    /// a chosen number takes `/proc/sys/kernel/ns_last_pid` and the privilege to write
    /// it, so a test that stopped one daemon and started another would assert only that
    /// two spawns usually get different numbers, and would pass whatever `kill` did.
    /// What can be pinned is the descriptor's half of the argument, which is what the
    /// ordering in [`pin`](super::pin) turns into the guarantee.
    ///
    /// The reaping is the point of the `wait`, not tidiness: a descriptor onto a zombie
    /// still has a task behind it, and the whole question is what the descriptor means
    /// after that task is released and the number is free again. `SIGCONT` is what is
    /// sent because the assertion is that it arrives nowhere — a signal that did reach a
    /// stranger should be one that costs them nothing.
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

        assert_eq!(
            pidfd_send_signal(&pidfd, Signal::CONT),
            Err(Errno::SRCH),
            "the signal reached something, so the descriptor is following the number \
             rather than the process it was opened on"
        );
    }

    /// The refusal after both graces says what the escalation did, and a
    /// [`Chosen::reach`](super::Chosen::reach) that sent nothing is never described as
    /// having sent two signals.
    ///
    /// Put to the sentence where it is built rather than to a `kill`, because the state
    /// behind it cannot be arranged from a test: a declined descriptor over a session that
    /// goes on answering needs `pidfd_open` to fail at that one call, and nothing a test
    /// may do produces such a failure. `RLIMIT_NOFILE` is the lever that looks like it
    /// would: it cannot, because the probe and the pidfile read each take a descriptor
    /// and give it back strictly before the open, so any limit tight enough to refuse it
    /// refuses the `connect` first and `kill` answers with the unprobeable socket
    /// instead. A test that arranged the limit anyway would assert only that, and pass
    /// whatever this sentence said.
    #[test]
    fn a_refusal_names_no_signal_that_was_never_sent() {
        let pid = Pid::from_raw(999_999_999).expect("a positive number is a pid");
        let unheld = still_answering(
            "one",
            &Chosen {
                pid,
                reach: Err(Errno::MFILE.into()),
            },
        );
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
            let signalled = still_answering(
                "one",
                &Chosen {
                    pid,
                    reach: Ok(pidfd),
                },
            );
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
    /// where `argv[1]` arrived whole.
    ///
    /// [`chosen`](super::chosen) admits `None` — "could not tell" is not a positive "it is
    /// not" — so a rule that let a full buffer decide had `nomux kill` send `SIGTERM` and
    /// then `SIGKILL` to any recycled pid whose command line ran past the buffer. That is
    /// no corner: `java -cp <20 KiB of classpath>` reaches it, and so does anything else
    /// that keeps its length in `argv[1..]`, which is where every real program keeps it.
    ///
    /// A shell blocked on `read` rather than anything shorter: it takes the padding as
    /// `$0` and ignores it, it is a builtin so nothing replaces the command line by
    /// `exec`ing, and it leaves no grandchild behind when this stops it. The command line
    /// is waited for rather than assumed, `/proc/<pid>/cmdline` showing the *parent's*
    /// argv until the `exec` lands.
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
}
