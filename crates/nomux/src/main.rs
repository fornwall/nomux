//! `nomux` — persistent PTY sessions that survive SSH disconnects.
//!
//! One binary, several modes (see `DESIGN.md` § 4):
//!
//! - `daemon` owns the PTY master, the child process and the output ring buffer.
//! - `spawn` and `attach` are one dumb byte relay between stdio and the daemon's
//!   unix socket, differing only in whether they may create the session.
//! - `list` and `kill` are the frozen, version-independent control surface.

mod agent;
mod attach;
mod conn;
mod control;
mod daemon;
mod linger;
mod nbio;
mod pty;
mod ring;
mod rundir;
mod sanitize;
#[cfg(test)]
mod scratch;
mod startup;
mod usock;

use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

/// `EX_USAGE`: malformed invocation. The one code borrowed from `sysexits.h`, and
/// the only one shared by every mode — `IMPLEMENTATION.md` § 10 has both tables and
/// says why the rest of that range is left alone.
const EXIT_USAGE: u8 = 64;
/// The session is there but this mode cannot have it: `spawn` found the id already
/// taken, or `attach` found a session it could not join. The shell's "found but not
/// executable", for the reason § 10 gives.
const EXIT_UNATTACHABLE: u8 = 126;
/// No such session — `attach` on an id nothing answers for, or a `spawn` whose daemon
/// never started. The shell's "not found", for the reason above.
const EXIT_NO_SESSION: u8 = 127;

const USAGE: &str = "\
usage: nomux <mode> [session-id] [options]

binary-protocol modes (normally driven by a matching client):
  daemon <session-id>   Own a PTY session (normally started by `spawn`)
  spawn <session-id>    Create a session and relay framed stdio; fails if it exists
  attach <session-id>   Relay framed stdio to an existing session; fails if absent

human control modes:
  list                  List live sessions and collect stale run files
  kill <session-id>     Terminate a session and unlink its run files

options:
  --label <text>        Display name for `list` (daemon and spawn only)
  --version, -V         Print version and protocol revision
  --help, -h            Print this usage
";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(mode) = args.next() else {
        return usage_error(None);
    };

    match mode.to_str() {
        Some(word @ "list") => only(args, word, || report(control::list())),
        Some(word @ ("--version" | "-V")) => only(args, word, || {
            println!(
                "nomux {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                nomux::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }),
        Some(word @ ("--help" | "-h")) => only(args, word, || {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }),
        // Private half of the relay's bounded stdout boundary. `attach` gives it the
        // worker channel as stdin and interprets this errno-shaped status; it is kept
        // out of `USAGE` because it is not a user or client mode.
        Some(word @ "__relay-stdout") => only(args, word, stdout_worker),
        Some(word @ "daemon") => with_session(word, args, true, |session, label, lock_fd| {
            report(daemon::run(session, label, lock_fd))
        }),
        Some(word @ "spawn") => with_session(word, args, false, |session, label, _| {
            report_relay(attach::run(session, attach::Intent::Create(label)))
        }),
        Some(word @ "attach") => with_session(word, args, false, |session, label, _| {
            // Refused rather than dropped on the floor: a `--label` on `attach` is a
            // caller that still believes `attach` might create the session.
            if label.is_some() {
                return usage_error(Some(
                    "`attach` takes no `--label`: a label is recorded when the session \
                     is created, which `spawn` does",
                ));
            }
            report_relay(attach::run(session, attach::Intent::Resume))
        }),
        Some(word @ "kill") => with_session(word, args, false, |session, label, _| {
            if label.is_some() {
                return usage_error(Some(
                    "`kill` takes no `--label`: labels are recorded only when a session is created",
                ));
            }
            report(control::kill(session))
        }),
        _ => usage_error(Some(&format!("unknown mode `{}`", mode.display()))),
    }
}

/// Runs the private relay worker, preserving an ordinary Linux errno in its exit code.
///
/// `EPIPE` is already a successful closed-stdout outcome inside the copy. 255 is the
/// sentinel for a failure without a representable errno; Linux errnos fit below it.
fn stdout_worker() -> ExitCode {
    match attach::copy_stdin_to_stdout() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => ExitCode::from(
            err.raw_os_error()
                .and_then(|raw| u8::try_from(raw).ok())
                .filter(|raw| *raw != 0 && *raw != u8::MAX)
                .unwrap_or(u8::MAX),
        ),
    }
}

/// Refuses arguments to a mode that takes none.
fn only(mut args: impl Iterator<Item = OsString>, word: &str, run: fn() -> ExitCode) -> ExitCode {
    if let Some(extra) = args.next() {
        return usage_error(Some(&format!(
            "`{word}` takes no arguments, got `{}`",
            extra.display()
        )));
    }
    run()
}

/// Prints `message` where there is one, then the usage, and reports `EX_USAGE`.
///
/// Every way to misuse the command line ends here, so what a usage error consists of
/// is decided once.
fn usage_error(message: Option<&str>) -> ExitCode {
    if let Some(message) = message {
        // Escaped here rather than at each of the five places one is built: what all
        // of them quote is a word from `argv`, on its way to a terminal that would
        // act on an `ESC ]0;` in it. `escape_debug` leaves printable UTF-8 alone, so
        // an argument in any language still reads as what was typed.
        eprintln!("nomux: {}\n", message.escape_debug());
    }
    eprint!("{USAGE}");
    ExitCode::from(EXIT_USAGE)
}

/// The command line the four modes that take a session id share, parsed once and handed
/// to whichever of them `main` matched.
///
/// `word` is that mode, carried only so a refusal can name it. `lock_fd_ok` is passed by
/// the daemon arm alone: everywhere else `--lock-fd` is an unknown option.
fn with_session(
    word: &str,
    args: impl Iterator<Item = OsString>,
    lock_fd_ok: bool,
    run: impl FnOnce(&str, Option<&str>, Option<i32>) -> ExitCode,
) -> ExitCode {
    let SessionArgs {
        session,
        label,
        lock_fd,
    } = match parse_session_args(args, lock_fd_ok) {
        Ok(parsed) => parsed,
        Err(message) => return usage_error(Some(&message)),
    };
    let Some(session) = session else {
        return usage_error(Some(&format!("`{word}` requires a session id")));
    };
    run(&session, label.as_deref(), lock_fd)
}

/// The shared command line of every mode that names a session.
#[derive(Debug)]
struct SessionArgs {
    session: Option<String>,
    label: Option<String>,
    /// Private startup capability passed only from `spawn` to `daemon`.
    lock_fd: Option<i32>,
}

/// Splits a session-mode command line into its id and optional label — and, only where
/// `lock_fd_ok`, the private `--lock-fd` handoff.
///
/// Deliberately minimal — no argument parser, no abbreviations, no `--` handling.
/// The only caller is the client, which builds this command line itself.
fn parse_session_args(
    mut args: impl Iterator<Item = OsString>,
    lock_fd_ok: bool,
) -> Result<SessionArgs, String> {
    let mut session = None;
    let mut label = None;
    let mut lock_fd = None;

    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| format!("argument `{}` must be valid UTF-8", arg.display()))?;
        let value = match text.split_once('=') {
            Some(("--lock-fd", value)) if lock_fd_ok => {
                parse_lock_fd(value, &mut lock_fd)?;
                continue;
            }
            Some(("--label", value)) => value.to_owned(),
            _ if lock_fd_ok && text == "--lock-fd" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing `--lock-fd` value".to_owned())?;
                let value = value
                    .to_str()
                    .ok_or_else(|| "non-UTF-8 `--lock-fd`".to_owned())?;
                parse_lock_fd(value, &mut lock_fd)?;
                continue;
            }
            _ if text == "--label" => args
                .next()
                .ok_or_else(|| "`--label` requires a value".to_owned())?
                .to_str()
                .ok_or_else(|| "label must be valid UTF-8".to_owned())?
                .to_owned(),
            _ if text.starts_with('-') => return Err(format!("unknown option `{text}`")),
            _ if session.is_none() => {
                session = Some(text.to_owned());
                continue;
            }
            _ => return Err(format!("unexpected argument `{text}`")),
        };
        if label.replace(value).is_some() {
            return Err("`--label` is given once: a second would replace the first".to_owned());
        }
    }
    Ok(SessionArgs {
        session,
        label,
        lock_fd,
    })
}

/// Parses the private descriptor passed from `spawn` to its daemon.
fn parse_lock_fd(value: &str, slot: &mut Option<i32>) -> Result<(), String> {
    let fd = value
        .parse::<i32>()
        .ok()
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or_else(|| "invalid `--lock-fd`".to_owned())?;
    if slot.replace(fd).is_some() {
        return Err("`--lock-fd` is given once".to_owned());
    }
    Ok(())
}

/// Maps a fallible operation onto an exit code, reporting failure on stderr.
///
/// `IMPLEMENTATION.md` § 10's first table, which `daemon`, `list` and `kill` are scored
/// against: a failure is a failure. What both tables share is `InvalidInput`, which every
/// mode gives `EX_USAGE`: [`rundir::SessionPaths::in_dir`] is the only place the crate
/// *constructs* one, so it means an id that could never have named a session rather than
/// an operation that failed — a distinction the client acts on, caching "unattachable"
/// per host and otherwise caching its own typo. That makes this kind a reserved word
/// here: an `EINVAL` from anywhere would decode to it and be reported as the user's
/// spelling, which is why a run file that cannot be read is `InvalidData`
/// ([`rundir::read_prefix`]) and why `Hello.term` is refused for an interior NUL before
/// it can reach `Command::env`.
fn report(result: std::io::Result<()>) -> ExitCode {
    reported(result, |_| ExitCode::FAILURE)
}

/// [`report`] for the two modes that relay, which § 10 scores on a table of their own:
/// `spawn` and `attach` distinguish a session that is not there from one they may not
/// have, because their client acts on the difference.
fn report_relay(result: std::io::Result<()>) -> ExitCode {
    reported(result, |kind| match kind {
        // A failure *during* the relay, which `attach::relay_failed` renames to this
        // kind and nothing else in the crate constructs. The one row here that says
        // nothing about the session: `nomux attach work > /var/log/big` on a filesystem
        // that fills had the session for an hour and then could not write to its own
        // stdout. Scored 126, that takes a working host out of the client's rotation as
        // unattachable; 1 says what happened, which is that this attempt failed.
        std::io::ErrorKind::ConnectionAborted => ExitCode::FAILURE,
        // `NotFound` is the session `attach` refused to invent; `TimedOut` is a daemon
        // `spawn` started that never bound — the same "not found", reached by waiting.
        // The other wait that runs out is a `connect` to a socket somebody bound and
        // stopped accepting on, which is a session and not a missing one; that this
        // line cannot tell the two apart is why both modes rename it first, through
        // `attach::may_be_running` and `attach::unattachable`, and never leave it as
        // `TimedOut`.
        std::io::ErrorKind::NotFound | std::io::ErrorKind::TimedOut => {
            ExitCode::from(EXIT_NO_SESSION)
        }
        _ => ExitCode::from(EXIT_UNATTACHABLE),
    })
}

/// The half the two share: success, the message on stderr, and § 10's one reserved kind.
/// `failed` scores everything else, which is the whole of what the two tables differ by.
fn reported(
    result: std::io::Result<()>,
    failed: impl FnOnce(std::io::ErrorKind) -> ExitCode,
) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Runtime failures carry paths from the environment and labels read from
            // disk as well as static text. Apply the same terminal boundary as argv
            // errors: a hostile ESC or newline is data, never terminal control or a
            // forged second diagnostic.
            eprintln!("nomux: {}", err.to_string().escape_debug());
            let kind = err.kind();
            if kind == std::io::ErrorKind::InvalidInput {
                ExitCode::from(EXIT_USAGE)
            } else {
                failed(kind)
            }
        }
    }
}
