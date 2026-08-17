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
/// `--version` and `--help` get a heading of their own rather than a place under
/// `options:` because they are modes here, not options: [`only`] refuses anything after
/// either, and `spawn --help` is an unknown option. Advertising them as options is what
/// made the two disagree.
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

in place of a mode, alone:
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
                nomux_protocol::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }),
        Some(word @ ("--help" | "-h")) => only(args, word, || {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }),
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
/// `word` is that mode, carried only so a refusal can name it. `private_options_ok` is
/// passed by the daemon arm alone: everywhere else the startup handoff option is unknown.
fn with_session(
    word: &str,
    args: impl Iterator<Item = OsString>,
    private_options_ok: bool,
    run: impl FnOnce(&str, Option<&str>, Option<i32>) -> ExitCode,
) -> ExitCode {
    let SessionArgs {
        session,
        label,
        lock_fd,
    } = match parse_session_args(args, private_options_ok) {
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
/// `private_options_ok`, the startup handoff option.
///
/// Deliberately minimal — no argument parser, no abbreviations, no `--` handling.
/// The only caller is the client, which builds this command line itself.
fn parse_session_args(
    mut args: impl Iterator<Item = OsString>,
    private_options_ok: bool,
) -> Result<SessionArgs, String> {
    let mut session = None;
    let mut label = None;
    let mut lock_fd = None;

    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| format!("argument `{}` must be valid UTF-8", arg.display()))?;
        let value = match text.split_once('=') {
            Some(("--lock-fd", value)) if private_options_ok => {
                parse_lock_fd(value, &mut lock_fd)?;
                continue;
            }
            Some(("--label", value)) => value.to_owned(),
            _ if private_options_ok && text == "--lock-fd" => {
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
    reported(result, ExitCode::FAILURE)
}

/// Reports the relay modes' versioned machine record and legacy exit status.
///
/// The record is a separate complete stderr line with no caller-controlled bytes. A client
/// can therefore find it among login-shell chatter without parsing the human diagnostic.
/// Command usage remains outside the record's closed set and keeps the ordinary reporter.
fn report_relay(result: Result<(), attach::RunError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(attach::RunError::Usage(err)) => reported(Err(err), ExitCode::from(EXIT_USAGE)),
        Err(attach::RunError::Classified(failure)) => {
            let class = failure.class();
            eprintln!("NOMUX-RELAY-ERROR 1 {}", class.token());
            eprintln!("nomux: {}", failure.to_string().escape_debug());
            ExitCode::from(class.exit_code())
        }
    }
}

/// The half the two share: success, the message on stderr, and § 10's one reserved kind.
/// `failed` scores everything else, which is the whole of what the two tables differ by.
fn reported(result: std::io::Result<()>, failed: ExitCode) -> ExitCode {
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
                failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_args(args: &[&str], private_options_ok: bool) -> Result<SessionArgs, String> {
        parse_session_args(
            args.iter().map(|argument| OsString::from(*argument)),
            private_options_ok,
        )
    }

    #[test]
    fn the_lock_descriptor_is_a_daemon_only_startup_handoff() {
        for spelling in [["--lock-fd", "19"].as_slice(), ["--lock-fd=19"].as_slice()] {
            let mut args = vec!["session"];
            args.extend_from_slice(spelling);
            args.extend_from_slice(&["--label=cost $5"]);
            let parsed = session_args(&args, true).expect("parse the daemon handoff");
            assert_eq!(parsed.session.as_deref(), Some("session"));
            assert_eq!(parsed.lock_fd, Some(19));
            assert_eq!(parsed.label.as_deref(), Some("cost $5"));

            assert_eq!(
                session_args(&args, false).expect_err("reject a private option on public modes"),
                format!("unknown option `{}`", spelling[0])
            );
        }
    }

    #[test]
    fn the_lock_descriptor_cannot_be_repeated_or_name_standard_stdio() {
        assert_eq!(
            session_args(&["session", "--lock-fd=19", "--lock-fd", "20"], true)
                .expect_err("reject a repeated descriptor"),
            "`--lock-fd` is given once"
        );
        // A relay hands over a descriptor it opened; `2` would be the stderr the daemon is
        // about to silence rather than a lock anybody holds.
        assert_eq!(
            session_args(&["session", "--lock-fd=2"], true)
                .expect_err("reject a standard descriptor"),
            "invalid `--lock-fd`"
        );
    }
}
