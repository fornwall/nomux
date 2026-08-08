//! Starts a session daemon either directly or in a transient systemd user scope.
//!
//! A direct child remains in sshd's `session-*.scope` even after `setsid(2)`.  Where a
//! lingering user manager is available, `systemd-run --user --scope` first moves its own
//! process into a manager-owned scope and then `exec`s the daemon.  Scope mode is important:
//! unlike a transient service, it preserves the caller's environment and arbitrary inherited
//! descriptors, including the already-held spawn lock.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::rundir::SpawnLock;

/// Selects the startup path. `auto` is deliberately the default for an unset variable.
const LAUNCHER_ENV: &str = "NOMUX_LAUNCHER";

/// Absolute system paths only. Running a same-user program found through a writable `PATH`
/// would hand it the spawn-lock capability.
const SYSTEMD_RUN_PATHS: [&str; 2] = ["/usr/bin/systemd-run", "/bin/systemd-run"];
const LOGINCTL_PATHS: [&str; 2] = ["/usr/bin/loginctl", "/bin/loginctl"];
const DETECTION_TIMEOUT: Duration = Duration::from_secs(1);
const DETECTION_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Preference {
    Auto,
    Direct,
    Systemd,
}

/// The creator's `INVOCATION_ID` before systemd-run replaced it for the transient scope.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OriginalInvocationId {
    /// The creating SSH environment did not contain the variable.
    Absent,
    /// Its raw Unix value, which need not be UTF-8.
    Value(OsString),
}

/// Starts the daemon while `spawn_lock` continues to serialise this session id.
///
/// # Errors
///
/// Propagates command construction and process-spawn failures. A forced systemd launch also
/// fails if the trusted `systemd-run` path is unavailable; automatic selection falls back to
/// direct launch before starting anything.
pub(crate) fn spawn_daemon(
    session_id: &str,
    label: Option<&str>,
    spawn_lock: &SpawnLock,
) -> io::Result<Option<ChildStderr>> {
    let preference = preference()?;
    let systemd_run = trusted_program(&SYSTEMD_RUN_PATHS);
    let use_systemd = match preference {
        Preference::Direct => false,
        Preference::Systemd => {
            if systemd_run.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "NOMUX_LAUNCHER=systemd, but systemd-run is unavailable at a trusted system path",
                ));
            }
            true
        }
        Preference::Auto => {
            systemd_run.is_some() && user_manager_reachable() && user_linger_enabled()
        }
    };

    let lock_fd = spawn_lock.raw_fd();
    let mut command = match (use_systemd, systemd_run.as_deref()) {
        (true, Some(systemd_run)) => scope_command(systemd_run, session_id, label, lock_fd),
        (true, None) => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "systemd-run disappeared before daemon startup",
            ));
        }
        (false, _) => direct_command(session_id, label, lock_fd)?,
    };
    configure_stdio_and_lock(&mut command, lock_fd);
    command.spawn().map(|mut child| child.stderr.take())
}

fn preference() -> io::Result<Preference> {
    match env::var(LAUNCHER_ENV).as_deref() {
        Err(env::VarError::NotPresent) | Ok("" | "auto") => Ok(Preference::Auto),
        Ok("direct") => Ok(Preference::Direct),
        Ok("systemd") => Ok(Preference::Systemd),
        Ok(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{LAUNCHER_ENV} must be `auto`, `direct` or `systemd`, got {value:?}"),
        )),
        Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{LAUNCHER_ENV} must be valid UTF-8"),
        )),
    }
}

/// The old path, kept whole as the fallback and as an explicit diagnostic escape hatch.
fn direct_command(session_id: &str, label: Option<&str>, lock_fd: i32) -> io::Result<Command> {
    let mut command = Command::new("/proc/self/exe");
    command.arg0(env::current_exe()?);
    daemon_args(&mut command, session_id, label, lock_fd, false);
    Ok(command)
}

/// Builds a scope command whose final `exec` resolves the exact inode this relay is running.
///
/// `/proc/self/exe` inside systemd-run would name systemd-run. The relay stays alive while it
/// waits for publication and while it relays the new attachment, so its pid-qualified link is
/// an immutable route to the already-loaded nomux inode throughout this handoff.
fn scope_command(
    systemd_run: &Path,
    session_id: &str,
    label: Option<&str>,
    lock_fd: i32,
) -> Command {
    let exact_image = format!("/proc/{}/exe", std::process::id());
    // Unique even if a failed unit has not been collected yet. One relay creates one session,
    // so its pid does not need another nonce.
    let unit = format!("nomux-{session_id}-{}", std::process::id());
    let mut command = Command::new(systemd_run);
    command
        .arg("--user")
        .arg("--scope")
        .arg("--quiet")
        .arg("--collect")
        .arg("--unit")
        .arg(unit)
        .arg(exact_image);
    daemon_args(&mut command, session_id, label, lock_fd, true);

    command
}

fn daemon_args(
    command: &mut Command,
    session_id: &str,
    label: Option<&str>,
    lock_fd: i32,
    systemd_scope: bool,
) {
    command
        .arg("daemon")
        .arg(session_id)
        .arg("--lock-fd")
        .arg(lock_fd.to_string());
    if systemd_scope {
        // systemd-run adds the scope's invocation id to the environment it passes on. Carry
        // the SSH session's raw value (including absence) outside the environment so no
        // internal variable can collide with one the shell should inherit wholesale.
        command.arg(format!(
            "--systemd-scope={}",
            encode_invocation_id(env::var_os("INVOCATION_ID").as_deref())
        ));
    }
    if let Some(label) = label {
        // systemd-run releases disagree about whether command arguments undergo environment
        // expansion. An ASCII hex handoff contains nothing either behavior can reinterpret;
        // the daemon decodes it only when the private scope marker accompanies it.
        if systemd_scope {
            command.arg("--label").arg(encode_hex(label.as_bytes()));
        } else {
            command.arg("--label").arg(label);
        }
    }
}

fn encode_invocation_id(value: Option<&OsStr>) -> String {
    let Some(value) = value else {
        return "-".to_owned();
    };
    encode_hex(value.as_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(1usize.saturating_add(bytes.len().saturating_mul(2)));
    encoded.push('x');
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            let digit = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            };
            encoded.push(char::from(digit));
        }
    }
    encoded
}

/// Decodes the private systemd-scope argument back into the original environment value.
pub(crate) fn decode_invocation_id(value: &str) -> Result<OriginalInvocationId, &'static str> {
    if value == "-" {
        return Ok(OriginalInvocationId::Absent);
    }
    decode_hex(value)
        .map(OsString::from_vec)
        .map(OriginalInvocationId::Value)
}

/// Restores a label protected from systemd-run's version-dependent argument expansion.
pub(crate) fn decode_scope_label(value: &str) -> Result<String, &'static str> {
    let bytes = decode_hex(value).map_err(|_| "invalid systemd scope label")?;
    String::from_utf8(bytes).map_err(|_| "invalid systemd scope label")
}

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    let Some(hex) = value.strip_prefix('x') else {
        return Err("invalid `--systemd-scope` value");
    };
    if hex.len() % 2 != 0 {
        return Err("invalid `--systemd-scope` value");
    }
    let mut decoded = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let [high, low] = pair else {
            return Err("invalid `--systemd-scope` value");
        };
        let Some(high) = hex_nibble(*high) else {
            return Err("invalid `--systemd-scope` value");
        };
        let Some(low) = hex_nibble(*low) else {
            return Err("invalid `--systemd-scope` value");
        };
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn configure_stdio_and_lock(command: &mut Command, lock_fd: i32) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // The caller reads this pipe only if publication misses its deadline.
        .stderr(Stdio::piped());

    let pre_exec = move || -> io::Result<()> {
        rustix::process::setsid()?;
        // `SpawnLock` opens `CLOEXEC`. Clear it only in the forked child, across either the
        // direct exec or systemd-run's scope setup and final exec. The daemon validates the
        // descriptor against the current lock path and restores `CLOEXEC` before the shell.
        // SAFETY: `lock_fd` belongs to the lock held across `Command::spawn` by the caller.
        let lock = unsafe { BorrowedFd::borrow_raw(lock_fd) };
        rustix::io::fcntl_setfd(lock, rustix::io::FdFlags::empty())?;
        Ok(())
    };
    // SAFETY: the closure runs after fork and calls only async-signal-safe operations.
    unsafe {
        command.pre_exec(pre_exec);
    }
}

fn trusted_program(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(Path::new).find_map(|path| {
        let metadata = fs::metadata(path).ok()?;
        (metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .then(|| path.to_path_buf())
    })
}

/// Whether systemd-run can reach the standard user-manager bus from this login environment.
///
/// Linger is a persistence promise, not proof that this SSH session was given a usable
/// `XDG_RUNTIME_DIR`. Checking before the handoff lets automatic mode use the direct fallback
/// while it is still certain that no daemon was started.
fn user_manager_reachable() -> bool {
    env::var_os("XDG_RUNTIME_DIR")
        .filter(|runtime| Path::new(runtime).is_absolute())
        .is_some_and(|runtime| {
            crate::usock::connect_within(&PathBuf::from(runtime).join("bus"), DETECTION_TIMEOUT)
                .is_ok()
        })
}

/// Whether logind promises to keep this user's manager after the final logout.
///
/// A manager that happens to be running is insufficient: without linger it is stopped with the
/// final login and takes the transient scope with it. `loginctl show-user` is its documented
/// machine-readable query; failure or an unfamiliar answer conservatively means no promise.
fn user_linger_enabled() -> bool {
    let Some(loginctl) = trusted_program(&LOGINCTL_PATHS) else {
        return false;
    };
    let mut command = Command::new(loginctl);
    command
        .arg("show-user")
        .arg(rustix::process::getuid().as_raw().to_string())
        .arg("--property=Linger")
        .arg("--value")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    output_within(&mut command, DETECTION_TIMEOUT)
        .is_ok_and(|output| output.status.success() && linger_value(&output.stdout))
}

fn output_within(command: &mut Command, within: Duration) -> io::Result<Output> {
    let mut child = command.stdout(Stdio::piped()).spawn()?;
    let deadline = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(DETECTION_POLL_INTERVAL);
            }
            Ok(None) => {
                drop(child.kill());
                drop(child.try_wait());
                return Err(io::ErrorKind::TimedOut.into());
            }
            Err(err) => {
                drop(child.kill());
                return Err(err);
            }
        }
    }
}

fn linger_value(output: &[u8]) -> bool {
    let without_lf = output.strip_suffix(b"\n").unwrap_or(output);
    without_lf.strip_suffix(b"\r").unwrap_or(without_lf) == b"yes"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linger_is_only_the_exact_machine_answer() {
        assert!(linger_value(b"yes\n"));
        assert!(linger_value(b"yes\r\n"));
        assert!(linger_value(b"yes"));
        for answer in [
            b"no\n".as_slice(),
            b"yes\n\n".as_slice(),
            b" yes\n".as_slice(),
            b"",
        ] {
            assert!(!linger_value(answer), "accepted {answer:?}");
        }
    }

    #[test]
    fn a_launcher_probe_cannot_hold_startup_forever() {
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        let started = Instant::now();
        let err = output_within(&mut command, Duration::from_millis(20))
            .expect_err("the probe must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn scope_labels_are_insulated_from_argument_expansion() {
        let label = "$HOME/${USER}/$$";
        let encoded = encode_hex(label.as_bytes());
        assert_eq!(encoded, "x24484f4d452f247b555345527d2f2424");
        assert_eq!(decode_scope_label(&encoded).as_deref(), Ok(label));
    }

    #[test]
    fn scope_command_carries_the_lock_and_invocation_restore() {
        let command = scope_command(
            Path::new("/usr/bin/systemd-run"),
            "session_7",
            Some("cost $5"),
            19,
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "--user".to_owned(),
                "--scope".to_owned(),
                "--quiet".to_owned(),
                "--collect".to_owned(),
                "--unit".to_owned(),
                format!("nomux-session_7-{}", std::process::id()),
                format!("/proc/{}/exe", std::process::id()),
                "daemon".to_owned(),
                "session_7".to_owned(),
                "--lock-fd".to_owned(),
                "19".to_owned(),
                format!(
                    "--systemd-scope={}",
                    encode_invocation_id(env::var_os("INVOCATION_ID").as_deref())
                ),
                "--label".to_owned(),
                "x636f7374202435".to_owned(),
            ]
        );
    }

    #[test]
    fn direct_command_does_not_apply_systemd_escaping() {
        let command = direct_command("session", Some("cost $5"), 23).unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            ["daemon", "session", "--lock-fd", "23", "--label", "cost $5"]
        );
    }

    #[test]
    fn invocation_id_encoding_preserves_absence_and_raw_bytes() {
        assert_eq!(decode_invocation_id("-"), Ok(OriginalInvocationId::Absent));
        let raw = OsStr::from_bytes(b"id-\xff-$");
        assert_eq!(
            decode_invocation_id(&encode_invocation_id(Some(raw))),
            Ok(OriginalInvocationId::Value(raw.to_os_string()))
        );
        for invalid in ["", "yes", "x0", "xgg"] {
            assert_eq!(
                decode_invocation_id(invalid),
                Err("invalid `--systemd-scope` value")
            );
        }
    }
}
