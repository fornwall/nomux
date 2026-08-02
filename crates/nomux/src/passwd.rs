//! The two fields of the password database this daemon needs: the user's name and
//! their login shell.
//!
//! Read straight out of `/etc/passwd` rather than through `getpwuid`. In a static
//! musl binary — which is what ships (`IMPLEMENTATION.md` § 8) — `getpwuid` *is*
//! this file parser, because NSS modules cannot be loaded into a static
//! executable. Doing it here keeps the lookup safe, testable and free of an FFI
//! buffer dance, at the cost of not seeing LDAP or NIS users. Both callers treat a
//! miss as "fall back", never as an error:
//!
//! - shell selection, where `$SHELL` from the SSH login is the primary source
//! - the username for the linger check ([`crate::linger`]), where `$USER` is
//!
//! so a directory-backed user still gets a working session.

use std::fs;
use std::path::PathBuf;

/// Where the password database lives.
const PASSWD: &str = "/etc/passwd";

/// The fields of one `/etc/passwd` line that anything here cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Login name.
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
    let contents = fs::read_to_string(PASSWD).ok()?;
    lookup(&contents, uid)
}

/// Finds the first entry for `uid` in the contents of a password file.
///
/// Malformed lines are skipped rather than rejected: a database with one bad line
/// is not a reason to refuse someone a shell.
fn lookup(contents: &str, uid: u32) -> Option<Entry> {
    contents.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        // Field 1 is the password placeholder, 3 the gid, 4 the GECOS comment and
        // 5 the home directory; only the uid and the shell are wanted.
        let _password = fields.next()?;
        if fields.next()?.parse::<u32>().ok()? != uid {
            return None;
        }
        let shell = fields.nth(3).filter(|shell| !shell.is_empty());
        (!name.is_empty()).then(|| Entry {
            name: name.to_owned(),
            shell: shell.map(PathBuf::from),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "root:x:0:0:root:/root:/bin/bash\n\
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
        let contents = "\n\
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
}
