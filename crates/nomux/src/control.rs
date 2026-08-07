//! The frozen control surface: `list` and `kill` (§ 6.6, `DESIGN.md` § 6.4).
//!
//! These must work against a daemon of *any* version, so the contract here is the
//! on-disk layout — never a protocol frame, never `PROTOCOL_VERSION`.

use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal, test_kill_process};

use crate::rundir::{
    MAX_PID_LEN, MAX_SESSION_ID_LEN, SessionPaths, SpawnLock, check_run_dir, parse_pid, read_label,
    read_prefix, run_dir, session_ids,
};
use crate::usock::{connect_within, nothing_is_listening};

/// How long a probe of a session socket waits for an answer.
///
/// Bounded at all because an `AF_UNIX` `connect` to a full backlog blocks rather than being
/// refused (§ 6.3). Two seconds, the budget every other wait here is given, and spent in
/// full only against that backlog — a session that really has stopped answers
/// `ECONNREFUSED` on the first attempt.
///
/// Deliberately *not* clamped to whatever grace remains, so the deadlines below are each
/// checked after a probe rather than bounding one, and a stage can overrun its grace by a
/// whole probe: § 6.6 states what that compounds to. A clamp would buy the wall clock back
/// by turning a wedged session into [`Liveness::Unknown`], which § 6.3 makes evidence of
/// neither death nor life — so `kill` would refuse a session it could have collected. A
/// slow refusal is the better failure.
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
/// bounds is the case where the pid signalled is *not* the process behind the socket —
/// and the case where there was no signal to survive, [`pin`] having given nothing to send
/// one through, which is why the refusal at the end of it is [`still_answering`]'s to word
/// rather than one sentence.
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
/// returning early would make `head` the reason a stale session survived. An id this
/// directory cannot address goes to stderr instead, being the one session that can be
/// neither printed nor collected (§ 6.3).
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
        let paths = match SessionPaths::new(&id) {
            Ok(paths) => paths,
            // § 6.3's `sun_path` refusal, a property of this directory rather than of the
            // id: files are here that no mode can address, so this is the one session
            // `list` can neither print nor collect. Named on stderr rather than in § 6.6's
            // three frozen columns, every id in which is one a client may hand straight
            // back to `attach`.
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
        // Nowhere left to print to, and the sweep above is the whole reason the loop
        // goes on anyway.
        if !listening {
            continue;
        }
        let mut buf = [0u8; MAX_PID_LEN];
        let (filed, _) = pidfile(&paths.pid(), &mut buf).unwrap_or_default();
        let pid = chosen(&paths, filed).map_or_else(
            || "?".to_owned(),
            |chosen| chosen.pid.as_raw_nonzero().to_string(),
        );
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
/// there is nothing for it to address. [`list`] names such a session on stderr instead of in
/// § 6.6's three columns, and between the two it is one this host holds that neither mode
/// can collect.
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
    // a pid out of a file and signals it. Checked and never created — being told to remove
    // a session must not be what brings a run directory into existence.
    if !present(check_run_dir(paths.dir()))? {
        return Ok(());
    }
    // Held from here to the end of the function (§ 6.6): without it, an attach that starts
    // a fresh daemon between the signal below and the unlink that follows loses its socket
    // to a kill it was never the target of. What the lock does not exclude is a daemon
    // started by hand, which is why the unlink probes again rather than trusting this.
    let lock = hold_spawn_lock(&paths)?;
    if let Some(chosen) = resolve(&paths)? {
        chosen.signal(Signal::TERM);
        // Liveness first, deadline second, so a daemon that let go on the last interval is
        // not signalled again — `SIGKILL` being the one signal nothing survives, and the
        // descriptor guaranteeing only that it lands on the process this call pinned.
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
                // Both graces out with the socket still answering. Reachable only from
                // the arm above that accepted a connection, which is what makes the
                // answering true of every reach — and the whole of what is true of every
                // reach, [`Chosen::signal`] being a no-op on one of the three. What the
                // escalation did is therefore [`still_answering`]'s to say rather than
                // this call site's.
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
/// unchecked is how `nomux kill` terminates an unrelated process of the user's. What
/// comes back is a [`Chosen`] rather than the number itself, because the same reuse
/// happens again between here and each of the two signals.
fn resolve(paths: &SessionPaths) -> io::Result<Option<Chosen>> {
    let deadline = Instant::now() + PUBLISH_GRACE;
    loop {
        // The probe's errno is kept rather than matched away, because every refusal below
        // is [`unresolved`]'s to word and that is what it words them by. The connection is
        // not kept: the match drops it where the discarded probe always dropped it, so
        // nothing holds one open across the grace.
        let unprobed = match liveness(&paths.socket(), PROBE_TIMEOUT) {
            Liveness::Stale(_) => return Ok(None),
            Liveness::Alive(_) => None,
            Liveness::Unknown(err) => Some(err),
        };
        let mut buf = [0u8; MAX_PID_LEN];
        let waiting_on = match pidfile(&paths.pid(), &mut buf) {
            Ok((filed, body)) if !body.trim_ascii().is_empty() => {
                // A pid `/proc` does not rule out is taken whatever the probe did, and
                // that is deliberate: [`chosen`] identifies a *process*, by a route the
                // socket has no part in, so a mode or a descriptor limit that keeps this
                // process off the socket is no reason to stop signalling a daemon this
                // one has positively named. Nothing is unlinked on the strength of it —
                // every exit from [`kill`] still goes through a probe that has to say the
                // session stopped.
                return chosen(paths, filed).map(Some).ok_or_else(|| {
                    let problem = unidentified(paths.id(), filed, body);
                    unresolved(paths, unprobed.as_ref(), &problem)
                });
            }
            // Present but empty is the same window one syscall later, so it is waited
            // out too: `SessionPaths::write_pid` creates the file and fills it in two
            // steps, and a reader can land between them.
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
/// The two are not the same thing, and that is the whole reason this is a struct. A pid
/// is a number the kernel is free to reissue the moment its process is reaped, while
/// [`kill`] signals twice with a grace of [`TERM_GRACE`] in between and reads `/proc`
/// before either. Everything it establishes is about a process; everything a number can
/// deliver is about whoever wears it at the instant of the call.
#[derive(Debug)]
struct Chosen {
    /// What the refusals print and what `list` shows: a descriptor is nothing a user can
    /// carry to another command, so the number is still the whole of what is reportable.
    pid: Pid,
    /// What the signals go through.
    reach: Reach,
}

/// What there is to reach a [`Chosen`] process *with*.
#[derive(Debug)]
enum Reach {
    /// A descriptor onto the process the number named when it was opened. It goes on
    /// meaning that one process for as long as it is held, so a signal through it either
    /// arrives there or answers `ESRCH` — never at whoever the kernel handed the number
    /// to in between. The only thing here that ever signals.
    Pidfd(OwnedFd),
    /// No descriptor, so nothing is signalled and [`kill`] establishes what became of the
    /// session by probing the socket alone. Carries the errno that declined the
    /// descriptor, which is the whole of what says why no signal went out: it is
    /// [`pin`]'s `ESRCH` — a daemon that has exited, and the postcondition arriving
    /// early — or one of the errnos that cannot be told from it, where the session goes
    /// on running and every clause about a signal is false. That set now includes a host
    /// with no `pidfd_open` at all ([`pin`]). Only [`still_answering`] reads it, that
    /// being the one path where the difference is visible.
    Nothing(io::Error),
}

impl Chosen {
    /// Signals the daemon, where [`pin`] got a descriptor to signal it through.
    ///
    /// The outcome is dropped because there is none worth reading: a process that took
    /// the first signal and died answers the second with `ESRCH`, which is this working
    /// rather than failing, and [`kill`] settles what actually happened by probing the
    /// socket either way.
    fn signal(&self, sig: Signal) {
        match &self.reach {
            Reach::Pidfd(pidfd) => drop(pidfd_send_signal(pidfd, sig)),
            Reach::Nothing(_) => {}
        }
    }
}

/// Takes hold of the process a number names, before anything at all is established about
/// it.
///
/// The order is the whole of this. Every check [`chosen`] then makes reads `/proc/<pid>`,
/// and a check made through a number can only describe whoever wears it at the instant of
/// the read — so pinning first is what makes the check and the signal be about one
/// process. Reuse before this call leaves the impostor to fail the check below and
/// nothing is signalled; reuse after it leaves this descriptor still meaning the process
/// that passed. The one impostor that could pass is a second `nomux daemon <id>`, and the
/// spawn lock `kill` holds across all of it excludes that (§ 6.3).
///
/// A descriptor is had without permission to signal, which is why [`extant`] still asks
/// that separately.
///
/// A failure of any kind signals nothing at all. There is no falling back on the bare
/// number: doing that accepts the reuse race this call exists to close, and the errno that
/// most invites it — `ESRCH`, a process already reaped — is the one under which the race
/// is not a risk but a certainty. A host with no `pidfd_open` (`ENOSYS` below 5.3, or a
/// sandbox answering `EINVAL`/`EPERM`) therefore gets a `kill` that refuses and names the
/// errno rather than one that signals a number it cannot vouch for. That refusal is
/// recoverable — `list` still prints the pid, so the number is a `kill(1)` away — where a
/// signal delivered to a stranger's process is not.
fn pin(pid: Pid) -> Reach {
    match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(pidfd) => Reach::Pidfd(pidfd),
        // Carried rather than discarded: nothing here can tell a reaped process from a
        // host that has no such call, so the refusal reports the errno instead of
        // describing signals it never sent.
        Err(err) => Reach::Nothing(err.into()),
    }
}

/// The published pid, where `/proc` does not rule it out, held by the process rather than
/// by the number ([`pin`]).
///
/// Shared by both modes, so the number `list` prints is the number `kill` would signal —
/// which matters most in the case `kill` refuses, since it recommends no repair there and
/// a user who wants to act asks `list` what to signal. `list` pays for a descriptor it
/// then drops unread, which is one syscall a session and the price of the two modes
/// answering out of the same code.
///
/// § 6.6 has the rest of the weighing: only a *positive* "it is not" declines the pid, and
/// what is deliberately not asked is which process holds the *socket*.
fn chosen(paths: &SessionPaths, filed: Option<Pid>) -> Option<Chosen> {
    let pid = filed?;
    // Held before it is examined and never after: these two lines are in this order for
    // [`pin`]'s reason and for no other, and swapping them gives the window back.
    let reach = pin(pid);
    (is_daemon_for(pid, paths.id()) != Some(false)).then_some(Chosen { pid, reach })
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
/// [`running_but`] opens by saying the session *is running*, and the only thing that ever
/// established that is a connection a daemon accepted. Where the probe failed instead,
/// § 6.3 makes it evidence of neither death nor life, so there is no session to describe
/// and no publish window to have been caught in the middle of: § 6.6's account of that
/// state is [`unprobeable`], which names the errno — the one thing about *this* call
/// anybody can repair. What the pidfile was doing is left unsaid there rather than added
/// to it, since a session that turns out to have stopped owes no explanation for a file
/// it was never going to be asked for.
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
/// the words the [`Reach`] it was escalated *through* earns.
///
/// The answering is established either way — the caller reaches this only from a
/// connection a daemon accepted. The rest turns on whether a signal went out. Through a
/// descriptor one did, so a session that outlived `SIGKILL`, which nothing survives, says
/// the pid signalled is not the process serving the socket. Through [`Reach::Nothing`]
/// none did: `pidfd_open` declined the process before either grace began, and the same
/// two-and-a-half seconds of answering then say nothing whatever about the pid. What is
/// reportable there is the errno that declined it, which is also the only part of the
/// state anybody can repair.
///
/// The graces are waited out under that reach all the same, and not as a formality: the
/// socket is what decides, and [`pin`]'s `ESRCH` is a daemon already on its way out, whose
/// socket falling silent inside them reaches the unlink instead of this sentence.
fn still_answering(id: &str, chosen: &Chosen) -> String {
    let pid = chosen.pid.as_raw_nonzero();
    match &chosen.reach {
        Reach::Pidfd(_) => format!(
            "session {id} is still answering after SIGTERM and SIGKILL to pid {pid}, so \
             that pid is not the process serving it; leaving it alone rather than \
             unlinking a live session's files"
        ),
        Reach::Nothing(err) => format!(
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
    use std::process::{Command, Stdio};

    use rustix::io::Errno;
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

    use super::{Chosen, Reach, names_daemon_for, pin, still_answering};

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

        let Reach::Pidfd(pidfd) = pin(pid) else {
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

    /// The refusal after both graces says what the escalation did, and a [`Reach`] that
    /// sent nothing is never described as having sent two signals.
    ///
    /// Put to the sentence where it is built rather than to a `kill`, because the state
    /// behind it cannot be arranged from a test: [`Reach::Nothing`] over a session that
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
                reach: Reach::Nothing(Errno::MFILE.into()),
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
                    reach: Reach::Pidfd(pidfd),
                },
            );
            assert!(
                signalled.contains("still answering after SIGTERM and SIGKILL to pid 999999999"),
                "a session that outlasted a signal that was sent says so, and names the \
                 number it was sent to: {signalled:?}"
            );
        }
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
