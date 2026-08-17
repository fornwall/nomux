//! `nomux` — persistent PTY sessions that survive SSH disconnects.
//!
//! `daemon` owns a session, `spawn` and `attach` relay bytes, and `list` and
//! `kill` form the version-independent control surface (`DESIGN.md` § 4).

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
use std::io::{self, Write as _};
use std::process::ExitCode;

/// `EX_USAGE`: malformed invocation (`IMPLEMENTATION.md` § 10).
const EXIT_USAGE: u8 = 64;
/// `--version` and `--help` are modes: both must appear alone.
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
            write_stdout(format_args!(
                "nomux {} (protocol {})\n",
                env!("CARGO_PKG_VERSION"),
                nomux_protocol::PROTOCOL_VERSION
            ))
        }),
        Some(word @ ("--help" | "-h")) => {
            only(args, word, || write_stdout(format_args!("{USAGE}")))
        }
        Some(word @ "daemon") => with_session(word, args, true, |session, label, lock_fd| {
            report(daemon::run(session, label, lock_fd))
        }),
        Some(word @ "spawn") => with_session(word, args, false, |session, label, _| {
            report_relay(attach::run(session, attach::Intent::Create(label)))
        }),
        Some(word @ "attach") => with_session(word, args, false, |session, label, _| {
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

fn only(mut args: impl Iterator<Item = OsString>, word: &str, run: fn() -> ExitCode) -> ExitCode {
    if let Some(extra) = args.next() {
        return usage_error(Some(&format!(
            "`{word}` takes no arguments, got `{}`",
            extra.display()
        )));
    }
    run()
}

/// Reports a command-line error and `EX_USAGE`.
fn usage_error(message: Option<&str>) -> ExitCode {
    if let Some(message) = message {
        // Arguments may contain terminal controls; printable UTF-8 remains unchanged.
        write_stderr(format_args!("nomux: {}\n\n", message.escape_debug()));
    }
    write_stderr(format_args!("{USAGE}"));
    ExitCode::from(EXIT_USAGE)
}

/// Writes output without panicking on a broken destination.
fn write_stdout(arguments: std::fmt::Arguments<'_>) -> ExitCode {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if stdout
        .write_fmt(arguments)
        .and_then(|()| stdout.flush())
        .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Best-effort diagnostics; the exit status carries the outcome if stderr fails.
fn write_stderr(arguments: std::fmt::Arguments<'_>) {
    let stderr = io::stderr();
    drop(stderr.lock().write_fmt(arguments));
}

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

#[derive(Debug)]
struct SessionArgs {
    session: Option<String>,
    label: Option<String>,
    /// Private startup capability passed only from `spawn` to `daemon`.
    lock_fd: Option<i32>,
}

/// Parses the deliberately minimal, client-generated session command line.
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

/// Reports control-mode failures. `InvalidInput` is reserved for invalid session ids
/// and maps to `EX_USAGE` (`IMPLEMENTATION.md` § 10).
fn report(result: io::Result<()>) -> ExitCode {
    reported(result, ExitCode::FAILURE)
}

/// Reports a relay's versioned machine record and legacy exit status.
fn report_relay(result: Result<(), attach::RunError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(attach::RunError::Usage(err)) => reported(Err(err), ExitCode::from(EXIT_USAGE)),
        Err(attach::RunError::Classified(failure)) => {
            let class = failure.class();
            write_stderr(format_args!("NOMUX-RELAY-ERROR 1 {}\n", class.token()));
            write_stderr(format_args!(
                "nomux: {}\n",
                failure.to_string().escape_debug()
            ));
            ExitCode::from(class.exit_code())
        }
    }
}

/// Shared reporting for ordinary and relay errors.
fn reported(result: io::Result<()>, failed: ExitCode) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Paths and labels can contain terminal controls or forged newlines.
            write_stderr(format_args!("nomux: {}\n", err.to_string().escape_debug()));
            if err.kind() == io::ErrorKind::InvalidInput {
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
        // The handoff cannot name standard I/O.
        assert_eq!(
            session_args(&["session", "--lock-fd=2"], true)
                .expect_err("reject a standard descriptor"),
            "invalid `--lock-fd`"
        );
    }
}
