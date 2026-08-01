//! `nomux` — persistent PTY sessions that survive SSH disconnects.
//!
//! One binary, three modes (see `DESIGN.md` § 4):
//!
//! - `daemon` owns the PTY master, the child process and the output ring buffer.
//! - `attach` is a dumb byte relay between stdio and the daemon's unix socket.
//! - `probe` reports the information the client needs to bootstrap this host.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

/// `EX_USAGE`: malformed invocation.
const EXIT_USAGE: u8 = 64;
/// `EX_UNAVAILABLE`: mode recognised but not yet implemented.
const EXIT_UNAVAILABLE: u8 = 69;

const USAGE: &str = "\
usage: nomux <mode> [session-id]

modes:
  daemon <session-id>   Own a PTY session (normally spawned by `attach`)
  attach <session-id>   Relay stdio to a session, spawning it if absent
  probe                 Report OS, architecture and install path

control surface (frozen across versions, see IMPLEMENTATION.md 6.6):
  list                  List sessions in the run directory
  kill <session-id>     Terminate a session and unlink its run files

  --version             Print version and protocol revision
";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(mode) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };

    match mode.to_str() {
        Some("probe") => {
            print_probe();
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            println!(
                "nomux {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                nomux_proto::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(mode @ ("daemon" | "attach" | "kill")) => run_session_mode(mode, args.next()),
        Some("list") => {
            eprintln!("nomux: `list` is not implemented yet");
            ExitCode::from(EXIT_UNAVAILABLE)
        }
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Dispatches the session-owning modes once a session id has been supplied.
fn run_session_mode(mode: &str, session: Option<OsString>) -> ExitCode {
    let Some(session) = session else {
        eprintln!("nomux: `{mode}` requires a session id\n");
        eprint!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    eprintln!(
        "nomux: `{mode}` is not implemented yet (session {})",
        session.to_string_lossy()
    );
    ExitCode::from(EXIT_UNAVAILABLE)
}

/// Emits the bootstrap line the client parses in `IMPLEMENTATION.md` § 5.1.
///
/// The architecture reported is this binary's own compile-time target, which is
/// what the client actually needs to confirm: that the uploaded artifact runs here.
fn print_probe() {
    println!(
        "NOMUX-BOOTSTRAP {} {} {}",
        env::consts::OS,
        env::consts::ARCH,
        install_dir().display()
    );
}

/// Resolves the install directory, matching the shell precedence in
/// `IMPLEMENTATION.md` § 5.
fn install_dir() -> PathBuf {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|dir| !dir.is_empty())
        .map_or_else(
            || {
                let home = env::var_os("HOME").unwrap_or_else(|| OsString::from("."));
                let mut path = PathBuf::from(home);
                path.push(".local/share");
                path
            },
            PathBuf::from,
        );
    base.join("nomux")
}
