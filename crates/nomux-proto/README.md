# nomux-proto

Wire protocol codec for [nomux](../../README.md): framing, frame types and stream
offsets. No I/O, no `unsafe`.

Private protocol — client and daemon are versioned in lockstep. See
[IMPLEMENTATION.md § 2](../../IMPLEMENTATION.md#2-wire-protocol).
