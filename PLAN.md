# nomux — Plan

Backlog. Rationale: [DESIGN.md](DESIGN.md). Mechanics: [IMPLEMENTATION.md](IMPLEMENTATION.md).
The `P` in `P1`–`P4` is priority, highest first: what is known to be wrong, then what
is merely awkward, then process, then depth nobody is blocked on.

## Status

Everything below this section is a feature not started, a decision deliberately
deferred, or client-side work recorded because its server-side contract is fixed
here. This section is the standing state; the deltas that produced it are what
`git log` is for.

Complete and under test on Linux, at the protocol revision
[IMPLEMENTATION.md § 2.2](IMPLEMENTATION.md#22-messages) states, and not usable on its
own: the client that speaks this protocol is a separate, unreleased project, so a
clone of this repository gives you `list`, `kill` and a daemon nothing can hold a
conversation with. What is complete is the whole server half. The daemon owns a PTY, a
child and a bounded ring buffer; clients resume by absolute byte offset across a
severed connection, replayed input is trimmed instead of re-applied, and overflow is
reported as an explicit gap. Agent forwarding proxies `ssh-agent` to the client as a
sub-channel of the same connection. `spawn` creates a session and `attach` joins one,
over one relay that knows nothing of the protocol and refuses to invent a session it
was only asked to join. A session outlives its child, so the exit status and the last
of the output are still there for a client that arrives days later. `list` and `kill`
act on the run directory alone, so any build can manage any daemon.

- **Platform** — Linux only, by construction. Everything else degrades to plain SSH
  ([DESIGN.md § 7](DESIGN.md#7-degradation)).
- **Suite** — a per-test timeout in `.config/nextest.toml` makes a hang a failure, and
  one test is `#[ignore]`d because it sits out the real 30 s first-attach reap, which
  CI covers with `--run-ignored all`. The count is whatever
  `cargo nextest list --workspace` prints. Layers and invariants:
  [IMPLEMENTATION.md § 9](IMPLEMENTATION.md#9-testing).
- **Release** — both musl targets build reproducibly and inside the size and growth
  gates `scripts/build-release.sh` enforces
  ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)). The sizes live in
  `scripts/size-baseline`, which a build writes.
- **Partly done** — P3's publishing half: a `v*` tag builds, checks and publishes a
  release, so what is left there is policy, not plumbing.
- **Not started** — the client, a separate repository, whose server-side contract is
  the last section of this file.

## P1 — known gaps

Eight. The first four are this surface's own; the last four came out of a security
review, and each is held today by something other than a check.

- **A hand-started daemon has a bind-to-publish window.** `nomux daemon <id>` run
  directly answers `connect` from its bind onward and publishes `<id>.pid` a few
  syscalls later, so a `kill` landing in between sees a live session it cannot
  identify. It refuses and waits the window out, so the outcome is an honest non-zero
  exit and never a destroyed session — § 6.6's "a live session's files are never
  unlinked" holds without a caveat. `spawn` narrows the window by holding the spawn
  lock until the path exists; nothing closes it.
- **An abort still says nothing from inside the process.** The shipping build is
  `-Cpanic=immediate-abort` with `strip = "symbols"`, so allocation failure and any
  surviving panic produce no message and no symbol to forward. The `SIGQUIT` core is
  readable against the `nomux-<target>.debug` companion every release publishes
  ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)), which names functions but not
  lines; lines mean `debug = 1` in the release profile, a change to what ships. The
  message itself is unfixable from inside — an immediate abort has nowhere to write it.
- **Nothing bounds how many sessions one host will run** — the *policy* half, the
  backstop having landed. The daemon counts ids in the run directory and refuses past
  64 ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)), a floor under a runaway.
  The cap of eight is client-side ([DESIGN.md § 5.1](DESIGN.md#51-identity)) and the
  client is unwritten, so two devices on one account give sixteen and a client bug
  gives sixty-four. What closes it is on the far side of a boundary this repository
  cannot see.
- **An id this run directory cannot hold makes its files invisible *and*
  uncollectable.** The `sun_path` refusal in
  [IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket) is environment-dependent, and
  both modes meet it by giving up: `list` drops the id it discovered from the
  filenames, `kill` is handed an id refused before anything is read, and the files stay
  where they are. The `list` half closes cheaply — report the id instead of skipping
  it, since reporting is not collecting. The `kill` half does not: "no socket address
  can be formed" is not "no live session", a symlinked short path reaching the same
  inode, so collecting by name there could unlink the files of a daemon still holding
  the user's shell. Whatever closes it has to establish liveness some other way.
- **A departure costs the daemon half a second, and departures are unlimited.**
  `Conn::flush_final` writes against a 500 ms deadline and `drop_client` reaches it on
  every ordinary departure, so one process can greet, never read, half-close and come
  back: half a second a cycle with no PTY drained and nothing reaped. The socket's
  `0600` makes that process this uid's, so it is recorded and not fixed. A budget per
  daemon closes it, as does a non-blocking final flush.
- **The signal path re-checks identity by command line, not by start time.** `kill`
  puts a candidate pid to `/proc/<pid>/cmdline`
  ([IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface)) and
  re-probes liveness before it escalates, so the window in which a reissued pid takes
  the signal — screen's CVE-2023-24626 in shape though never in privilege — is down to
  the interval between the last probe and the `kill_process` after it. Closing the rest
  is reusing `pty::stat_start_time` in `control::resolve`: a pid whose start time moved
  is not the daemon that published it, whatever its command line says.
- **`write_private` unlinks and then writes by name.** `fs::write` follows symlinks and
  asks for no `O_EXCL`, so what stands between the `remove_file` and the create is the
  directory — `0700`, this uid's, checked before any name in it is resolved
  ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)). Sound as argued, and one
  call short of not needing the argument: `O_NOFOLLOW | O_EXCL` would also cover the
  attacker-writable *parent* § 6.3 concedes. `read_prefix` already opens that way.
- **Nothing asserts the uid of an accepted connection.** `Daemon::accept` reads no
  credentials; the run directory's `0700` and the socket's `0600` are the whole of the
  authentication, deliberately ([SECURITY.md](SECURITY.md)), so the swapped run
  directory above is answered by file modes alone. Nothing in the tree reads
  `SO_PEERCRED` any more, so this is a `getsockopt` to be written — a few lines, and
  defence in depth. shpool refuses a cross-user connection outright.

## P2 — structure

- **A test can hold another test's descriptor without meaning to.** `fork` duplicates
  every open descriptor, and under `cargo test` that reaches across tests; the argument
  and the obligation that every process go through `harness::launch` belong in
  `harness::while_nothing_forks`'s doc comment, and `abandon_socket`'s for the listener
  case.
- **A raw read in the harness has to resume what a signal ended.** `SO_RCVTIMEO` makes
  `EINTR` reachable whatever `SA_RESTART` asked for; the argument belongs in
  `harness::read_uninterrupted`'s and `write_uninterrupted`'s doc comments.

## P3 — release process

Both musl targets build and land under the 400 KiB budget, which
`scripts/build-release.sh` enforces along with the growth gate and a grep of each
artifact for the builder's paths — the only reproducibility check a single machine can
make ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)). What is left is process:

- Decide when the pinned nightly moves. It is named once, in `scripts/nightly-version`,
  which the build script and CI both read, so a local build and the runner measure the
  same bytes. `scripts/size-baseline` records the compiler that measured it and a build
  whose compiler disagrees is refused, `NOMUX_UPDATE_BASELINE=1` being the one way past
  and the one that rewrites the file. Undecided is the *policy* — when to take a newer
  compiler at all, given that toolchain and baseline then move in one commit.
- Decide what the client does when a host already holds a binary whose hash it no
  longer recognises. The publishing half is done: a `v*` tag promotes the release build
  into a GitHub release carrying the shipping binaries beside `SHA256SUMS`, in the
  format `sha256sum -c` reads, and GitHub exposes its own immutable per-asset SHA-256
  as `digest` on the releases API. The unstripped companions ride along with their own
  `SHA256SUMS.debug`. Nothing in the client reads any of it, so
  [DESIGN.md § 8](DESIGN.md#8-security-model)'s "verify it after upload" is unwritten.

## P4 — test depth

- A `cargo-fuzz` target for `decode_header` and `Frame::decode`. The parser's fuzzing
  lives in `proptest` today — arbitrary bytes per frame type, plus single-byte
  mutations of real encodings — and runs on stable in the normal suite. A nightly
  `cargo-fuzz` target would explore longer, and has not earned the dependency.
- Chaos against a real full-screen program. The suite emits sixel and CSI from `sh`,
  which keeps it deterministic; driving an actual `vim` would test `vim`.
- **The wire vectors cannot be run by the implementation that most needs them.**
  `crates/nomux-proto/tests/wire.rs` is written from the § 2.2 table, not from the
  encoder, which is what makes it able to catch a changed field order — and it is
  locked inside a Rust integration test.
  [IMPLEMENTATION.md § 1](IMPLEMENTATION.md#1-layout-and-conventions) allows the client
  to reimplement the codec, which a mobile client in Swift or Kotlin will. Emitting the
  same table as a language-neutral fixture — hex per frame, checked in — would let an
  independent implementation be verified against identical bytes.
- **One arm of the publish grace has to be re-established as untested.** `kill` waits
  out a `<id>.pid` that is *missing* as well as one that is empty
  ([IMPLEMENTATION.md § 6.6](IMPLEMENTATION.md#66-frozen-control-surface)); only the
  empty arm is pinned. The old argument for why the missing arm did not need a test ran
  through a second witness that no longer exists, so it has expired. Re-run the
  mutation before treating this as open.
- **`MAX_PENDING_READ` has no test and cannot easily have one.** The kernel's unix send
  buffer is roughly 212 KiB, five times tighter than the 1 MiB cap, so on a stock host
  the cap never binds. Raising the peer's `SO_SNDBUF` to 4 MiB makes it bind — peak RSS
  5.2 MB against 12.3 MB — but a test doing that silently clamps where
  `net.core.wmem_max` is small, which is a test that cannot fail.

## Deferred by decision

Not backlog — recorded so they are not rediscovered as gaps.

- **Read-only mirrors.** Out of scope ([DESIGN.md § 2](DESIGN.md#2-scope)).
- **Ring capacity default.** `NOMUX_RING_BYTES` already makes it tunable per daemon, so
  what is unchosen is the default, and whether `Hello` should negotiate it at all.
  Against a larger one: eight sessions at 4 MiB is 32 MiB of address space reserved on
  a host whose administrator agreed to none of it — resident only as far as each
  session has produced the output to fill it, the ring being one allocation faulted in
  lazily. For a larger one: 4 MiB covers a multi-hour *idle* disconnect but not `yes`
  for ten seconds, and an ordinary twenty-minute disconnect across a build overruns it
  and loses the output the reconnect was for.
- **Compressing the output ring.** Measured at `b71db5f`, whose tables `git show` still
  holds: `lz4_flex` costs 1.5% of the 400 KiB cap and buys a median 4.6x more
  scrollback, but runs 21x slower on the PTY push path — and the hosts where 4 MiB a
  session is scarce are armv7 SBCs, where that CPU lands hardest. Raising the default
  ring capacity buys the same scrollback for nothing.
- **Server-side screen snapshot on overflow**, replacing the SIGWINCH repaint heuristic
  with a redraw that does not depend on the child cooperating. It buys determinism, not
  exactness: the snapshot matches the client's screen only where the server's model of
  the stream agrees with the client's emulator, and by default those are two different
  programs. So it trades a repaint the child may ignore for one that always happens and
  may be quietly wrong — the second, lossier server-side emulator
  [DESIGN.md § 3](DESIGN.md#3-key-properties) rejects — and it reconstructs the visible
  screen only, scrollback below the gap being gone either way. Against any engine: the
  400 KiB cap. Against `libvterm` in particular: the first C object in a tree that has
  none, which costs the property that both musl targets build from `rustup target add`
  alone ([IMPLEMENTATION.md § 8](IMPLEMENTATION.md#8-build)). Deferred until the
  heuristic proves insufficient.
- **Cross-device handover** (start on desktop, resume on mobile). It needs no new
  concurrency — takeover
  ([IMPLEMENTATION.md § 6.4](IMPLEMENTATION.md#64-multiple-clients)) is already the
  right primitive, handover being serial — but it needs three things: an input offset
  in `Hello` with a `u64::MAX` "tell me" sentinel mirroring the output side, a rule that
  clients never auto-reconnect after `Error{TAKEOVER}` (otherwise two resilient clients
  evict each other forever), and geometry-conditional replay, because scrollback
  carries absolute cursor positioning computed for the old width. The first is not on
  the wire and will not be until then: reserving eight bytes of every greeting for a
  deferred feature is the forward compatibility
  [DESIGN.md § 2](DESIGN.md#2-scope) refuses, and handover is a wire change and a bump
  regardless.
- **`daemon::run` *waiting* for the spawn lock.** It takes one without blocking and goes
  on without one where somebody holds it. Waiting would park the session's own creation
  behind the `spawn` that started it, since that spawn holds this very lock on its
  behalf until the pidfile exists
  ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)).
- **Addressing the run files through a validated directory descriptor.** There is no
  `bindat(2)`, so the sockets must resolve by name whatever the check returns
  ([IMPLEMENTATION.md § 6.3](IMPLEMENTATION.md#63-socket)).

## Client-side, not this repo

Listed because the server is useless without them, and because each has a
server-side contract already fixed here.

- `direct-streamlocal` warm path; the exec relay is the fallback.
- Bootstrap orchestration: probe, arch selection, upload, negative caching per host.
- Codec retention and the "never auto-reconnect after `TAKEOVER`" rule. N-1 is stated in
  [DESIGN.md § 6.4](DESIGN.md#64-version-skew), and its safety argument — that the client
  offers a restart while the session is *still reachable* — assumes the client runs under
  every release. App stores batch updates in the background, so a user who does not open
  the app for a month goes from release 5 to release 8 without ever running 6 or 7, and
  any session created under 5 is unreachable before the window opens. Keying retention to
  protocol revision instead, and keeping every revision ever shipped, removes the failure
  rather than bounding it: revisions are append-only integers and a codec is a few hundred
  lines, which costs an app nothing.
- Collecting binaries it has uploaded. Nothing in this repository resolves the install
  directory or ever unlinks one — so every release leaves another artifact
  in every user's home on every host they have touched, in a directory
  [DESIGN.md § 8](DESIGN.md#8-security-model) already expects file-integrity tooling to
  notice. The client knows the version each session is running, so it has what it needs
  to remove any `nomux-*` that is neither current nor holding a live session.
- Emulator reset on `gap`, and the 8-sessions-per-host cap.
- The child's exit status. It arrives in the `Exit` frame; the relay cannot read it
  without parsing frames, which is exactly what keeps the relay version-independent
  ([IMPLEMENTATION.md § 10](IMPLEMENTATION.md#10-exit-codes)). It now survives the
  disconnect that used to lose it, the session outliving its child, and carries
  `since_exit_secs` beside it — which hands the client a rendering decision it did not
  have before, since a status collected as it happened and one collected on Thursday for
  a build that finished on Tuesday are the same two numbers and not the same thing to put
  in front of a user.
- Answering agent channels from the key store, and the per-host opt-in that sets `HELLO_AGENT_FORWARD`. The daemon never enables forwarding on its own.
- Choosing the repaint policy per attach via `HELLO_REPAINT_CTRL_L`; only the client knows whether an editor or a prompt is on screen.
- Minting `--label` on `spawn`, which is the mode that creates and therefore the one that takes it, so an orphan is recognisable in `nomux list` after the client loses its state.
