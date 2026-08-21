//! The two children this binary starts, without `std::process::Command`.
//!
//! Both call sites already needed a `pre_exec` — a controlling terminal here
//! (`pty.rs`), a descriptor deliberately handed across the `exec` there (`attach.rs`) —
//! and that is the one thing that takes `Command` off its `posix_spawn` fast path and
//! down a `fork` of its own. What `Command` still carried on that path was an `OsString`
//! command line, a `BTreeMap<OsString, OsString>` environment and the machinery to render
//! both at fork time: the largest single cluster of `.text` in the shipping artifact,
//! against the 400 KiB every cold upload pays (`IMPLEMENTATION.md` § 8). This is the same
//! fork with the rendering moved into the parent.
//!
//! The rule the module exists to keep: **between `fork` and `execve` the child may make
//! only async-signal-safe calls**. Every string, every pointer array and every descriptor
//! number the child needs is built in [`Program`] and in [`spawn`]'s parent half, before
//! the fork — so the child's own path is syscalls and nothing else. It does not allocate,
//! it takes no lock, it formats no error and it touches no Rust runtime. `pre_exec` asked
//! for exactly this discipline and could not enforce it; here the child has nothing else
//! in scope to reach for.
//!
//! Deliberately not a `Command`. No `PATH` search — both callers name an absolute program,
//! and `pty::pick_shell` has what a relative one would cost. No shell, no argument
//! quoting, no pipe plumbing beyond the three descriptors a caller hands over, no `wait`
//! bookkeeping and no reaping `Drop`: [`crate::pty::Pty`] and the relay each own their
//! child's identity, and § 6.5's teardown is built on that identity outliving the process.
//! The one thing `Command` did that this must not lose is the failed `execve`: a child
//! that never became a program answers with its own `errno` down a `CLOEXEC` pipe, so a
//! `$SHELL` that has been uninstalled still reaches `daemon.rs` as an error rather than as
//! a session that started and immediately died.

use std::ffi::{CStr, CString, c_char};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use rustix::io::Errno;
use rustix::pipe::PipeFlags;
use rustix::process::{Pid, WaitOptions, waitpid};

/// Exit status of a child that never reached its program. Nothing reads it — the parent
/// learns what happened from the `errno` on [`Ready::fail`] — but a status the shell
/// convention already spends on "could not run it" is the one to leave in `/proc`.
const EXEC_FAILED: i32 = 127;

/// A program, its argument vector and the changes to the environment it inherits, held in
/// the NUL-terminated form `execve` takes.
///
/// Built in the parent and read in the child, which is the whole point: constructing one
/// allocates, and the child may not.
#[derive(Debug)]
pub(crate) struct Program {
    /// Absolute path handed to `execve`. Not searched for and not resolved.
    path: CString,
    /// `argv`, `argv[0]` included — which is not always the path (`pty.rs` runs the login
    /// shell as `-bash`, `attach.rs` runs `/proc/self/exe` under its resolved name).
    args: Vec<CString>,
    /// `KEY=VALUE` entries that replace whatever the inherited block says about that key.
    overrides: Vec<CString>,
    /// Where the child starts, when that is not where the parent is. The daemon has moved
    /// to `/` by the time it spawns a shell (§ 6.2), so this is never left to inheritance
    /// on that path.
    dir: Option<CString>,
}

impl Program {
    /// A program at `path`, to be run with `argv[0]` as `argv0`.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] where either already holds a NUL.
    pub(crate) fn new(path: &Path, argv0: &[u8]) -> io::Result<Self> {
        Ok(Self {
            path: nul_terminated(path.as_os_str().as_bytes())?,
            args: vec![nul_terminated(argv0)?],
            overrides: Vec::new(),
            dir: None,
        })
    }

    /// Appends one argument.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] where `arg` holds a NUL.
    pub(crate) fn arg(&mut self, arg: &str) -> io::Result<()> {
        self.args.push(nul_terminated(arg.as_bytes())?);
        Ok(())
    }

    /// Sets `key` in the child's environment, over whatever the inherited block or an
    /// earlier call said about it.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] where `value` holds a NUL, or `key` is empty or
    /// holds one of a NUL or an `=`. Refused rather than trusted: `frame.rs`'s
    /// `checked_term` already keeps a `TERM` with an interior NUL off the wire in both
    /// directions, so `Command::env` never saw one — and that is a guarantee two modules
    /// away from the `execve` that would be handed a truncated variable, which is not
    /// where this may be resting. An `=` in the key is refused for the same reason
    /// [`shadowed`] compares over a `KEY=` prefix: `env("A=B", "c")` would otherwise
    /// shadow `A` while the child read it as `A=B=c`.
    pub(crate) fn env(&mut self, key: &str, value: &[u8]) -> io::Result<()> {
        if key.is_empty() || key.as_bytes().contains(&b'=') {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut entry = Vec::with_capacity(key.len() + 1 + value.len());
        entry.extend_from_slice(key.as_bytes());
        entry.push(b'=');
        entry.extend_from_slice(value);
        let entry = nul_terminated(&entry)?;
        // Every earlier setting of this key and not merely the first, for [`shadowed`]'s
        // reason: `getenv` answers with the first match, so a survivor would be the value
        // the child actually reads.
        self.overrides
            .retain(|held| key_of(held.to_bytes()) != Some(key.as_bytes()));
        self.overrides.push(entry);
        Ok(())
    }

    /// Starts the child in `dir` rather than wherever the parent happens to be.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] where `dir` holds a NUL, which no path a
    /// filesystem answered for can.
    pub(crate) fn current_dir(&mut self, dir: &Path) -> io::Result<()> {
        self.dir = Some(nul_terminated(dir.as_os_str().as_bytes())?);
        Ok(())
    }

    /// The argument vector as built, `argv[0]` first.
    #[cfg(test)]
    pub(crate) fn args(&self) -> &[CString] {
        &self.args
    }
}

/// Everything the child reads, in the form it reads it: no owned string, no allocation and
/// nothing left to render. Built in the parent, and valid in the child because `fork`
/// copies the address space it lives in.
struct Ready<'a> {
    path: &'a CStr,
    /// NUL-terminated, as `execve` reads it.
    argv: &'a [*const c_char],
    /// The same, with the inherited block's own pointers in it ([`environment`]).
    envp: &'a [*const c_char],
    dir: Option<&'a CStr>,
    /// What becomes the child's stdin, stdout and stderr. Already above `STDERR_FILENO`,
    /// which is what makes the placement below safe in any order.
    stdio: [RawFd; 3],
    /// Write end of the `CLOEXEC` pipe a failed `execve` reports its `errno` down.
    fail: BorrowedFd<'a>,
}

/// Forks, prepares the child and `execve`s `program` in it, answering with the child's pid.
///
/// `stdio` becomes the child's descriptors 0, 1 and 2, in that order; the caller keeps
/// them. `setup` is the per-site work that has to happen in the child and cannot happen
/// anywhere else — `setsid` and `TIOCSCTTY` for a session's shell, clearing `CLOEXEC` on
/// the spawn lock for a daemon — and is handed the three stdio numbers as this function
/// will place them, which need not be the numbers the caller passed in. **Everything
/// `setup` does must be async-signal-safe**: it runs between the `fork` and the `execve`,
/// where a heap this process's other threads may have been holding is not this child's to
/// take.
///
/// # Errors
///
/// The `fork` itself, the descriptor and pipe setup around it, and — the reason the pipe
/// is there at all — whatever the child's own `execve` (or `chdir`, or `setup`) failed
/// with, as the `io::Error` the caller would have got from `Command::spawn`.
pub(crate) fn spawn(
    program: &Program,
    stdio: [BorrowedFd<'_>; 3],
    setup: &mut dyn FnMut([RawFd; 3]) -> Result<(), Errno>,
) -> io::Result<Pid> {
    let argv = pointers(&program.args);
    let envp = environment(&program.overrides);

    // Every one of the three raised above `STDERR_FILENO` before the fork, because the
    // child places them *onto* 0, 1 and 2: a source that was already one of those numbers
    // would be overwritten by an earlier `dup2` in the sequence, and the child would exec
    // holding the wrong end of something on the wrong descriptor. `std`'s `to_child_stdio`
    // re-duplicates for the same reason. Neither caller can reach the case today — the
    // daemon's 0/1/2 are the `/dev/null` `startup::silence_standard_descriptors` put
    // there, and the relay's are the user's own stdio — but that is a fact about two
    // callers and not about this function, and it is not one the next caller inherits.
    // Unconditional rather than conditional on the number: three `fcntl`s on the
    // session-creation path buy the absence of a branch that would be wrong exactly once.
    //
    // `CLOEXEC`, so these copies are gone by the time the program runs; the `dup2`s below
    // clear it on 0, 1 and 2 themselves, which is what leaves the child holding them.
    let [input, output, diagnostics] = stdio;
    let raised = [
        above_stdio(input)?,
        above_stdio(output)?,
        above_stdio(diagnostics)?,
    ];
    // The write end must reach the child above `STDERR_FILENO` too, or the placement above
    // would close it and the parent would read the resulting end of file as a successful
    // exec — the one failure this pipe exists to rule out, reported as success.
    let (report, bound) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)?;
    let failure = above_stdio(bound.as_fd())?;
    // The end the pipe came back on, closed rather than shadowed: a shadowed binding lives
    // to the end of this frame, and a second write end held *in the parent* is one this
    // pipe never reaches end of file behind — so the read below would wait out a
    // successful exec forever rather than take its silence for success.
    drop(bound);

    let ready = Ready {
        path: &program.path,
        argv: &argv,
        envp: &envp,
        dir: program.dir.as_deref(),
        stdio: raised.each_ref().map(AsRawFd::as_raw_fd),
        fail: failure.as_fd(),
    };

    // SAFETY: `fork` is safe to issue; what is unsafe is what the child may do afterwards,
    // and the child here is [`child`]'s syscall-only path. Both callers fork before this
    // process has a second thread — the daemon is single-threaded by construction, and the
    // relay starts its stdout worker only once it is relaying — so this child is not
    // missing a thread that held a lock it needs.
    //
    // Through `libc` rather than rustix: rustix's own `fork` lives in `rustix::runtime`,
    // behind a feature it documents as unstable and not for use outside its tree.
    let forked = unsafe { libc::fork() };
    if forked < 0 {
        return Err(io::Error::last_os_error());
    }
    if forked == 0 {
        // SAFETY: this is the forked child, and [`child`] never returns — it either
        // `execve`s or `_exit`s, so nothing below runs twice and no `Drop` in this frame
        // runs in both processes.
        unsafe { child(&ready, setup) }
    }
    // The parent's own copies of the three, which the child has now taken duplicates of
    // onto 0, 1 and 2. `ready` is not used again from here, which is what lets the write
    // end it borrows be closed below.
    drop(raised);

    let Some(pid) = Pid::from_raw(forked) else {
        // Unreachable: `fork` answers with a positive pid, zero, or -1, and the other two
        // are handled above. An error rather than a panic, this being a `panic`-free crate.
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    };
    // Before the read, and this is load-bearing: a write end still open in the parent keeps
    // the pipe from ever reaching end of file, and a successful exec would read as a child
    // that has not answered yet — which is a hang, not a misreport.
    drop(failure);

    let mut raw = [0u8; size_of::<i32>()];
    let mut filled = 0;
    while let Some(rest) = raw.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match rustix::io::read(report.as_fd(), rest) {
            // The exec happened: `CLOEXEC` closed the child's write end and this is the
            // last copy going with it.
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(Errno::INTR) => {}
            // A read that failed says nothing about the child, so it is taken as the same
            // silence a successful exec produces. Being wrong here costs the caller its own
            // liveness check — `attach::create` waits for a socket, `daemon.rs` waits for
            // output or an exit — rather than a session reported as started that is not.
            Err(_) => break,
        }
    }
    if filled == raw.len() {
        // The child `_exit`ed rather than becoming a program, so it is this call's to
        // collect: nobody else knows it existed, and `Command` left no zombie here either.
        reap(pid);
        return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(raw)));
    }
    Ok(pid)
}

/// Collects `pid` if it has already exited, and leaves it running if it has not.
///
/// For the one shape `attach.rs` starts that may not be the process it waited for:
/// `startup::detach_from_controlling_terminal` double-forks on the `spawn` path, and the
/// process this binary launched then `_exit(0)`s while its own child becomes the daemon. A
/// `std::process::Child` has no reaping `Drop`, so that intermediate used to sit `<defunct>`
/// under a relay that lives as long as the SSH session it serves — hours to days, one per
/// session, accumulating towards `RLIMIT_NPROC`. `NOHANG` is what tells the two cases apart
/// without guessing: an intermediate has already gone and is collected here, and a daemon
/// that did not need the fork is still running and is left exactly alone.
pub(crate) fn reap_if_exited(pid: Pid) {
    collect(pid, WaitOptions::NOHANG);
}

/// Collects a child that never became a program. Blocking, and immediate with it: the
/// `errno` the parent just read was the last thing that child did before `_exit`.
fn reap(pid: Pid) {
    collect(pid, WaitOptions::empty());
}

/// One `waitpid`, retried past a signal and with its outcome dropped: every caller here has
/// already learned what it needed, and `ECHILD` from a child something else collected is
/// this working.
fn collect(pid: Pid, options: WaitOptions) {
    while matches!(waitpid(Some(pid), options), Err(Errno::INTR)) {}
}

/// A `CLOEXEC` copy of `fd`, guaranteed to be above `STDERR_FILENO`.
fn above_stdio(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    rustix::io::fcntl_dupfd_cloexec(fd, libc::STDERR_FILENO + 1).map_err(Into::into)
}

/// The child half of [`spawn`]: everything between the `fork` and the `execve`, and the
/// one path in this binary where nothing but an async-signal-safe call is allowed.
///
/// # Safety
///
/// Must be reached only from the child of a `fork`, and never returns to the caller.
unsafe fn child(ready: &Ready<'_>, setup: &mut dyn FnMut([RawFd; 3]) -> Result<(), Errno>) -> ! {
    // SAFETY: the caller's own contract — this is the forked child.
    let failure = unsafe { prepare(ready, setup) };
    let raw = failure.raw_os_error().to_ne_bytes();
    // One write of four bytes, which `PIPE_BUF` makes atomic: there is no partial write to
    // resume, and no second writer to interleave with. A refused write leaves the parent
    // reading end of file and taking the exec for done, which is [`spawn`]'s documented
    // fallback and not something a retry loop here could improve on.
    while matches!(rustix::io::write(ready.fail, &raw), Err(Errno::INTR)) {}
    // SAFETY: the only correct exit for a forked child that is not going to exec, and for
    // `startup::detach_from_controlling_terminal`'s reason: `exit` would run this
    // process's `atexit` handlers and flush a second copy of whatever the parent had
    // buffered and not yet written.
    unsafe { libc::_exit(EXEC_FAILED) }
}

/// The child's syscalls, in order, answering with the `errno` of the first that failed.
///
/// Always returns: a successful `execve` never comes back here, so reaching the end is
/// itself a failure to report.
///
/// # Safety
///
/// [`child`]'s contract, one frame down.
unsafe fn prepare(
    ready: &Ready<'_>,
    setup: &mut dyn FnMut([RawFd; 3]) -> Result<(), Errno>,
) -> Errno {
    // The signal *mask*, which is the half `execve` carries into the new program: a
    // `SIGTERM` left blocked by whatever started this binary would stay blocked for the
    // login shell's whole life, and a shell that cannot be interrupted is a session the
    // user cannot leave. `Command` cleared it exactly here, so this has to as well.
    // Dispositions are the caller's business — `pty.rs` puts every one of them back to
    // `SIG_DFL`, and the daemon `attach.rs` starts installs its own in `startup.rs`.
    //
    // SAFETY: `sigemptyset` initialises the set this frame owns, which `sigprocmask` is
    // then handed along with a null pointer for the old mask it is not being asked for.
    // Both are async-signal-safe, and this child has exactly one thread to have a mask.
    unsafe {
        let mut empty = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(empty.as_mut_ptr());
        libc::sigprocmask(libc::SIG_SETMASK, empty.as_ptr(), ptr::null_mut());
    }
    // The one disposition that is this module's rather than a caller's, and for the same
    // reason `Command` reset it here: std ignores `SIGPIPE` process-wide at startup, so
    // without this every program either call site launches would inherit an ignore it
    // never chose and discover a closed pipe as an `EPIPE` in the middle of a write it did
    // not check.
    //
    // SAFETY: `signal` is async-signal-safe, `SIG_DFL` is a valid handler, and `SIGPIPE`
    // is neither invalid nor uncatchable. Unchecked for the reason `startup.rs` gives.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    if let Err(err) = setup(ready.stdio) {
        return err;
    }

    // Onto 0, 1 and 2. `dup2` clears `CLOEXEC` on the descriptor it creates, which is what
    // carries these three across the `execve` while every other descriptor this process
    // holds is left to close itself.
    let [input, output, diagnostics] = ready.stdio;
    for (source, slot) in [(input, 0u8), (output, 1), (diagnostics, 2)] {
        // SAFETY: `source` was duplicated in the parent and is open in this child; the
        // `OwnedFd` behind it outlives the `fork` in [`spawn`]'s frame.
        let source = unsafe { BorrowedFd::borrow_raw(source) };
        loop {
            // Through `rustix::stdio`, whose three spellings are the raw `dup3` syscall on
            // the `linux_raw` backend every shipped target selects. `rustix::io::dup2` is
            // the wrong shape here: it insists on owning its destination as a `&mut
            // OwnedFd`, which would mean manufacturing an `OwnedFd` over 0, 1 and 2 —
            // descriptors this process does not own and must not close.
            let placed = match slot {
                0 => rustix::stdio::dup2_stdin(source),
                1 => rustix::stdio::dup2_stdout(source),
                _ => rustix::stdio::dup2_stderr(source),
            };
            match placed {
                Ok(()) => break,
                Err(Errno::INTR) => {}
                Err(err) => return err,
            }
        }
    }

    // Last, next to the `execve` it is for. rustix takes a `&CStr` straight through without
    // copying it into a buffer of its own, so this allocates nothing — which is the whole
    // reason the path was rendered in the parent. A failure here is `pty::pick_dir`'s
    // unenterable `$HOME` arriving anyway, and it reaches the daemon as an `EACCES` from
    // `Pty::spawn` rather than as a session that started somewhere nobody asked for.
    if let Some(dir) = ready.dir
        && let Err(err) = rustix::process::chdir(dir)
    {
        return err;
    }

    // SAFETY: `path`, `argv` and `envp` were built in the parent and are NUL-terminated in
    // both dimensions; the strings they point at outlive this call, since the frame that
    // owns them cannot return while this child is in it. `libc` rather than rustix for
    // `fork`'s reason: rustix's `execve` is behind the unstable `runtime` feature.
    unsafe {
        libc::execve(
            ready.path.as_ptr(),
            ready.argv.as_ptr(),
            ready.envp.as_ptr(),
        );
    }
    last_errno()
}

/// This process's `errno`, as the value that goes down the pipe.
fn last_errno() -> Errno {
    // SAFETY: `__errno_location` answers with a pointer to this thread's `errno`, valid for
    // as long as the thread is. Async-signal-safe: it reads thread-local storage that the
    // `fork` copied along with everything else.
    Errno::from_raw_os_error(unsafe { *libc::__errno_location() })
}

/// One `execve` vector: the strings' own pointers, and the null the kernel reads as the end.
///
/// Pointing into `strings` rather than copying them. A `CString`'s bytes are a heap
/// allocation of their own that does not move when the `Vec` of handles grows or is itself
/// moved, and [`spawn`]'s frame keeps both alive across the `fork`.
fn pointers(strings: &[CString]) -> Vec<*const c_char> {
    let mut out = Vec::with_capacity(strings.len() + 1);
    out.extend(strings.iter().map(|string| string.as_ptr()));
    out.push(ptr::null());
    out
}

/// The child's `envp`: the block this process inherited, with `overrides` replacing what
/// they name and appended where they name something new.
///
/// The inherited entries are carried by *pointer*, not copied. That is what
/// `Command`'s `BTreeMap<OsString, OsString>` cost some 4 KiB of `.text` to avoid needing:
/// it took an owned copy of every variable of an SSH session's environment, in order to
/// flatten it back into exactly this pointer array at fork time. The block itself is
/// untouched and outlives the `execve` that consumes these pointers, this binary never
/// calling `setenv`, `putenv` or `std::env::set_var` — the three things that may reallocate
/// or free it (`IMPLEMENTATION.md` § 6.1.1 has why nothing is scrubbed either).
fn environment(overrides: &[CString]) -> Vec<*const c_char> {
    // Declared here rather than taken from `libc`, which exports it only with the `std`
    // feature that § 8's budget is why this crate does not enable (`usock.rs` turns the
    // same corner for sockets). The symbol itself is as old as `execve`: every libc that
    // starts a process defines it, and it is what the kernel handed this process as the
    // third argument to its own `main`.
    unsafe extern "C" {
        static environ: *const *const c_char;
    }

    let mut envp = Vec::new();
    // SAFETY: `environ` is this process's environment block, read in the parent where
    // nothing else is running, and never written by this binary — see above.
    let mut cursor = unsafe { environ };
    while !cursor.is_null() {
        // SAFETY: `cursor` walks a null-terminated array of NUL-terminated strings, and
        // the terminator is what the loop below stops at before stepping past it.
        let entry = unsafe { *cursor };
        if entry.is_null() {
            break;
        }
        // SAFETY: as above — an entry of the block is a NUL-terminated string.
        let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
        if !shadowed(bytes, overrides) {
            envp.push(entry);
        }
        // SAFETY: the null checked above says this is not the last slot.
        cursor = unsafe { cursor.add(1) };
    }
    envp.extend(overrides.iter().map(|entry| entry.as_ptr()));
    envp.push(ptr::null());
    envp
}

/// Whether an entry of the inherited block names a variable one of `overrides` also names.
///
/// Over the whole `KEY=` prefix rather than a `starts_with`, or an override of `TERM` would
/// take `TERMINAL` with it. *Every* match is dropped and not merely the first: nothing stops
/// an environment block holding a variable twice, `getenv` answers with the first of them,
/// and a survivor left in place is therefore the value the child actually reads. That
/// deduplication is the one thing `Command`'s `BTreeMap` did for free, and this line is what
/// replaces it.
fn shadowed(entry: &[u8], overrides: &[CString]) -> bool {
    let Some(key) = key_of(entry) else {
        // An entry with no `=` names nothing that can be overridden. The kernel would have
        // handed it to the child unchanged and so does this.
        return false;
    };
    overrides
        .iter()
        .any(|held| key_of(held.to_bytes()) == Some(key))
}

/// The variable an environment entry names, or `None` where it names none.
fn key_of(entry: &[u8]) -> Option<&[u8]> {
    let at = entry.iter().position(|byte| *byte == b'=')?;
    entry.get(..at)
}

/// One `execve` string, refused where the caller's bytes already hold the terminator.
///
/// `ErrorKind::InvalidInput` and no sentence behind it: nothing a peer can send reaches
/// here — `frame.rs` refuses a `TERM` with a NUL on both encode and decode, `rundir.rs`
/// refuses a session id outside `[A-Za-z0-9_-]`, `sanitize.rs` drops a label's control
/// bytes, and no path a filesystem answered for holds one — so this arm exists to be
/// unreachable, and a message for it would cost a heap allocation and a formatting path in
/// every build.
fn nul_terminated(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    /// An override replaces the variable it names and nothing that merely starts the same
    /// way — and it replaces *every* copy of it, a block being free to hold two.
    #[test]
    fn an_override_shadows_only_the_variable_it_names() {
        let overrides = [
            CString::new("TERM=xterm").expect("an override with no NUL in it"),
            CString::new("NOMUX_SESSION=work").expect("an override with no NUL in it"),
        ];

        for shadow in [b"TERM=vt100".as_slice(), b"TERM=", b"NOMUX_SESSION=other"] {
            assert!(
                shadowed(shadow, &overrides),
                "{shadow:?} names an overridden variable and must not reach the child"
            );
        }
        for kept in [
            b"TERMINAL=x".as_slice(),
            b"TERMCAP=x",
            b"NOMUX_SESSION_ID=x",
            b"PATH=/bin",
            // No `=` at all: not a variable, so not one this can be asked to override.
            b"MALFORMED",
            b"",
        ] {
            assert!(
                !shadowed(kept, &overrides),
                "{kept:?} names no overridden variable and must reach the child unchanged"
            );
        }
    }

    /// A program that cannot be `exec`ed comes back as the child's own `errno`, which is
    /// the whole reason for the pipe: `daemon.rs` answers a failed spawn with
    /// `ErrorCode::Internal` and `attach::create` with a `StartupFailure`, and both need to
    /// happen rather than a session appearing to start and vanishing.
    ///
    /// The child is collected by [`spawn`] itself, which the second half asserts: a
    /// `waitpid` that answers `ECHILD` is a process this test never has to see again.
    #[test]
    fn a_program_that_cannot_be_execed_comes_back_as_an_error_and_leaves_no_child() {
        let null = crate::startup::open_null_device().expect("open /dev/null");
        let stdio = [null.as_fd(); 3];
        let program = Program::new(Path::new("/nonexistent-nomux-program"), b"nope")
            .expect("a program path with no NUL in it");

        let err = spawn(&program, stdio, &mut |_| Ok(())).expect_err("the exec must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOENT),
            "the child's own errno must reach the parent: {err}"
        );
        assert_eq!(
            waitpid(None, WaitOptions::NOHANG).err(),
            Some(Errno::CHILD),
            "the child that never became a program was left unreaped"
        );

        // The same for a failure raised by `setup` rather than by `execve`, which travels
        // the identical path and is the one a caller's own `setsid` or `ioctl` would take.
        let program =
            Program::new(Path::new("/bin/sh"), b"sh").expect("a program path with no NUL in it");
        let err = spawn(&program, stdio, &mut |_| Err(Errno::ACCESS))
            .expect_err("a setup that failed must fail the spawn");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EACCES),
            "a setup failure must reach the parent as itself: {err}"
        );
    }

    /// The child's environment is this process's, with the overrides applied once each —
    /// and its working directory, argv and stdio are what the caller asked for.
    ///
    /// `PATH` is the one inherited variable asserted on: the suite's own runner sets it,
    /// and it is also the variable the override half replaces, so the two halves cannot
    /// both pass on an environment that was simply thrown away.
    #[test]
    fn the_child_runs_where_and_as_it_was_told_with_the_environment_it_was_given() {
        let (read, write) = rustix::pipe::pipe().expect("a pipe for the child's stdout");
        let null = crate::startup::open_null_device().expect("open /dev/null");

        let mut program =
            Program::new(Path::new("/bin/sh"), b"-sh").expect("a program path with no NUL in it");
        program.arg("-c").expect("an argument with no NUL in it");
        program
            .arg("printf '%s\\n' \"$0\" \"$PWD\" \"$NOMUX_TEST\"; env | grep -c '^PATH='")
            .expect("an argument with no NUL in it");
        program
            .env("NOMUX_TEST", b"set-once")
            .expect("an override with no NUL in it");
        // Set twice, and the second is what the child must read: `getenv` answers with the
        // first entry of the block, so a first setting left in place would win.
        program
            .env("NOMUX_TEST", b"set-twice")
            .expect("an override with no NUL in it");
        program
            .current_dir(Path::new("/tmp"))
            .expect("a directory with no NUL in it");

        let pid = spawn(
            &program,
            [null.as_fd(), write.as_fd(), null.as_fd()],
            &mut |_| Ok(()),
        )
        .expect("spawn a shell");
        // Before the read: the child's copy is not the last one until this goes.
        drop(write);

        let mut said = String::new();
        std::fs::File::from(read)
            .read_to_string(&mut said)
            .expect("read what the child printed");
        collect(pid, WaitOptions::empty());

        assert_eq!(
            said.lines().collect::<Vec<_>>(),
            ["-sh", "/tmp", "set-twice", "1"],
            "the child's argv[0], working directory, overridden variable and inherited \
             `PATH` — the last exactly once, an override having to replace rather than \
             shadow: {said:?}"
        );
    }

    /// A descriptor the caller hands over as stdin, stdout or stderr reaches the child
    /// above `STDERR_FILENO`, whatever number it had here. Without that the child's own
    /// `dup2` sequence would close a source it had not used yet.
    #[test]
    fn a_child_descriptor_is_raised_clear_of_the_numbers_it_will_be_placed_on() {
        let stdin = rustix::stdio::stdin();
        let raised = above_stdio(stdin).expect("raise stdin clear of 0, 1 and 2");
        assert!(
            raised.as_raw_fd() > libc::STDERR_FILENO,
            "a source left at {} would be clobbered by the placement onto it",
            raised.as_raw_fd()
        );
        assert!(
            rustix::io::fcntl_getfd(&raised)
                .expect("the copy's descriptor flags")
                .contains(rustix::io::FdFlags::CLOEXEC),
            "the copy must not survive the exec it exists to feed"
        );
    }

    /// A key that is not one is refused rather than rendered into an entry that would
    /// shadow the wrong variable, and so is a value carrying the terminator.
    #[test]
    fn an_environment_entry_that_could_not_be_read_back_is_refused() {
        let mut program =
            Program::new(Path::new("/bin/sh"), b"sh").expect("a program path with no NUL in it");
        for (key, value) in [
            ("", b"x".as_slice()),
            ("A=B", b"x"),
            ("A\0B", b"x"),
            ("A", b"x\0y"),
        ] {
            assert_eq!(
                program.env(key, value).map_err(|err| err.kind()),
                Err(io::ErrorKind::InvalidInput),
                "{key:?}={value:?} is not an entry a child could read back"
            );
        }
        assert!(
            program
                .args()
                .first()
                .is_some_and(|argv0| argv0.to_bytes() == b"sh"),
            "argv[0] is the name the program is run under, not the path it is loaded from"
        );
    }
}
