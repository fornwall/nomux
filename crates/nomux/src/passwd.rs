//! The two fields of the password database this daemon needs: the user's name and
//! their login shell.
//!
//! Read straight out of `/etc/passwd` rather than through `getpwuid`, for the reason
//! `IMPLEMENTATION.md` § 6.1.1 gives. Both callers — shell selection and the linger
//! check's username ([`crate::linger`]) — have an environment variable to fall back
//! on, so a miss is never an error and a directory-backed user still gets a session.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::str;

/// Where the password database lives.
const PASSWD: &str = "/etc/passwd";

/// The fields of one `/etc/passwd` line that anything here cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Login name. Text, unlike the shell below, because its one use is as a
    /// filename component that [`crate::linger`] compares against `$USER` — which
    /// arrives through `env::var` and so could not carry non-UTF-8 bytes either.
    pub name: String,
    /// Login shell, absent when the field is empty — which conventionally means
    /// `/bin/sh` and is left for the caller to decide.
    pub shell: Option<PathBuf>,
}

/// Looks up the entry for the user this process runs as.
///
/// Returns `None` if the file is unreadable or holds no line for this uid.
pub(crate) fn current() -> Option<Entry> {
    let uid = rustix::process::getuid().as_raw();
    let contents = fs::read(PASSWD).ok()?;
    lookup(&contents, uid)
}

/// Finds the first entry for `uid` in the contents of a password file.
///
/// Parsed as bytes rather than decoded first. `/etc/passwd` has a field structure
/// but no encoding: one GECOS field written in Latin-1 fails a UTF-8 decode of the
/// *whole file*, quietly and for everyone, a miss being indistinguishable from "no
/// such uid".
///
/// Malformed lines are skipped rather than rejected: a database with one bad line
/// is not a reason to refuse someone a shell.
fn lookup(contents: &[u8], uid: u32) -> Option<Entry> {
    contents.split(|byte| *byte == b'\n').find_map(|line| {
        // A carriage return from a CRLF-written file would otherwise end up inside
        // the shell path, the shell being the last field on the line.
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let mut fields = line.split(|byte| *byte == b':');
        let name = fields.next()?;
        // Field 1 is the password placeholder, 3 the gid, 4 the GECOS comment and
        // 5 the home directory; only the uid and the shell are wanted.
        let _password = fields.next()?;
        // Strict, because reading a malformed uid field as zero would hand root the
        // broken line.
        if str::from_utf8(fields.next()?).ok()?.parse::<u32>().ok()? != uid {
            return None;
        }
        let shell = fields.nth(3).filter(|shell| !shell.is_empty());
        // Decoded after the uid has matched, so that a name this daemon cannot
        // represent disqualifies at most the one line carrying it.
        let name = str::from_utf8(name).ok().filter(|name| !name.is_empty())?;
        Some(Entry {
            name: name.to_owned(),
            // A shell path is whatever bytes the filesystem holds, so it is handed
            // back as those rather than through a string.
            shell: shell.map(|shell| PathBuf::from(OsStr::from_bytes(shell))),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"root:x:0:0:root:/root:/bin/bash\n\
                            daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                            noshell:x:1000:1000:No Shell:/home/noshell:\n\
                            fornwall:x:1001:1001:Fredrik,,,:/home/fornwall:/usr/bin/zsh\n";

    #[test]
    fn finds_the_name_and_shell_for_a_uid() {
        assert_eq!(
            lookup(SAMPLE, 1001),
            Some(Entry {
                name: "fornwall".to_owned(),
                shell: Some(PathBuf::from("/usr/bin/zsh")),
            })
        );
        assert_eq!(lookup(SAMPLE, 0).unwrap().name, "root");
    }

    #[test]
    fn an_empty_shell_field_is_absent_rather_than_empty() {
        assert_eq!(lookup(SAMPLE, 1000).unwrap().shell, None);
    }

    #[test]
    fn an_unknown_uid_is_a_miss() {
        assert_eq!(lookup(SAMPLE, 4242), None);
    }

    /// One unparseable line must not hide the entries around it, and a uid field
    /// that is not a number must never be read as uid 0.
    #[test]
    fn malformed_lines_are_skipped() {
        let contents = b"\n\
                         garbage\n\
                         short:x\n\
                         bad:x:notanumber:0::/:/bin/sh\n\
                         real:x:7:7::/home/real:/bin/dash\n";
        assert_eq!(lookup(contents, 0), None);
        assert_eq!(
            lookup(contents, 7),
            Some(Entry {
                name: "real".to_owned(),
                shell: Some(PathBuf::from("/bin/dash")),
            })
        );
    }

    /// The reason any of this is parsed as bytes: `ö` as the single byte 0xF6 is what
    /// an account predating the host's move to UTF-8 still carries, and decoding the
    /// file as text fails on all of it at once.
    #[test]
    fn a_latin_1_gecos_field_costs_nobody_their_shell() {
        let contents = b"bjorn:x:1000:1000:Bj\xf6rn Str\xf6m:/home/bjorn:/bin/bash\n\
                         fornwall:x:1001:1001:Fredrik,,,:/home/fornwall:/usr/bin/zsh\n";
        // Not the user whose line holds the byte, ...
        assert_eq!(
            lookup(contents, 1001).unwrap().shell,
            Some(PathBuf::from("/usr/bin/zsh"))
        );
        // ... and not that user either, whose own two fields are ASCII.
        assert_eq!(
            lookup(contents, 1000),
            Some(Entry {
                name: "bjorn".to_owned(),
                shell: Some(PathBuf::from("/bin/bash")),
            })
        );
    }

    /// A path is bytes all the way to `execv`, and the one place that would have
    /// narrowed it to UTF-8 is here.
    #[test]
    fn a_shell_path_outside_utf8_survives_as_its_bytes() {
        assert_eq!(
            lookup(b"odd:x:5:5::/home/odd:/opt/sh\xff\n", 5)
                .unwrap()
                .shell,
            Some(PathBuf::from(OsStr::from_bytes(b"/opt/sh\xff")))
        );
    }

    /// The deliberate limit of holding [`Entry::name`] as a `String`: a login name
    /// outside UTF-8 loses its own line, and only its own line.
    #[test]
    fn a_name_outside_utf8_skips_only_its_own_line() {
        let contents = b"o\xffdd:x:9:9::/home/odd:/bin/dash\n\
                         real:x:10:10::/home/real:/bin/bash\n";
        assert_eq!(lookup(contents, 9), None);
        assert_eq!(lookup(contents, 10).unwrap().name, "real");
    }

    /// Nothing enforces the newline being a terminator: a hand-edited database can
    /// end mid-line, and a CRLF one would otherwise hand back a shell path with a
    /// carriage return on the end.
    #[test]
    fn the_last_line_parses_however_it_ends() {
        for contents in [
            &b"real:x:7:7::/home/real:/bin/dash"[..],
            &b"real:x:7:7::/home/real:/bin/dash\r\n"[..],
        ] {
            assert_eq!(
                lookup(contents, 7).unwrap().shell,
                Some(PathBuf::from("/bin/dash"))
            );
        }
    }
}
