//! Wire protocol for nomux.
//!
//! Spoken end-to-end between the client and the session daemon; the `attach` relay
//! is transparent to it. See `IMPLEMENTATION.md` § 2 for the frame tables.
//!
//! A private protocol with no stability guarantee: [`PROTOCOL_VERSION`] exists to
//! fail fast on a mismatched peer rather than to negotiate (`IMPLEMENTATION.md` § 2).
//!
//! What belongs here is what is on the wire, and nothing else: session id validation
//! and the agent socket's one-at-a-time rule are daemon policy, not codec.
//!
//! A library target beside the binary rather than a module inside it, because an
//! integration test cannot import from a binary and most of the suite speaks this
//! codec. That also keeps `forbid(unsafe_code)` over a whole target: the signal
//! handlers, the `fork` and the raw `AF_UNIX` calls are the binary's, and a codec that
//! only reads and writes byte slices needs none of them.

#![forbid(unsafe_code)]
// The one place a doctest's warnings become errors. Neither `RUSTFLAGS` nor
// `RUSTDOCFLAGS` reaches the doctest compile, so without this the crate's gates deny
// warnings everywhere except the examples in these docs.
#![doc(test(attr(deny(warnings))))]

mod frame;

pub use frame::{
    ErrorCode, ExitKind, Frame, Hello, HelloOk, MAX_AGENT_DATA, MAX_OUTPUT_DATA, RESUME_FROM_START,
    WinSize,
};

/// Protocol revision. Bumped on any wire change, including compatible ones.
///
/// There is no history to consult but `git log`: `IMPLEMENTATION.md` § 2.2 states the
/// revision in force and nothing before it. `tests/codec.rs`'s `vectors` module holds the
/// constant, the byte vectors and the document to each other, so a bump has to move all
/// three.
pub const PROTOCOL_VERSION: u16 = 11;

/// Fixed bytes a daemon writes immediately before its first response frame.
///
/// An attach relay is transparent, so a remote login shell's startup output can precede
/// these bytes. Clients scan for the complete sequence, discard everything through it,
/// and decode a frame header from the following byte. The value is independent of the
/// protocol revision so that a client can also synchronize to a version-mismatch
/// [`Frame::Error`].
pub const SERVER_PREAMBLE: &[u8; 12] = b"\0nomux-sync\xff";

/// Fixed frame header size: a reader sizes the payload from the first four bytes it has,
/// and never has to scan for a boundary.
pub const HEADER_LEN: usize = 4;

/// Largest permitted payload. Bounds the peer's ability to force an allocation.
pub const MAX_PAYLOAD: u32 = 256 * 1024;

// A discriminant list is written down once, and everything derived from it — the
// enum, both directions of the conversion, and the `ALL` the suites sweep — is
// generated, so the four cannot drift apart. A hand-written `from_wire` ending in a
// catch-all `_ => None` leaves an end that can *send* a new frame but never
// *receives* one. `IMPLEMENTATION.md` § 2.3 applies the same closed-set rule to
// `Error.code` and `Exit.kind`.
macro_rules! wire_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident: $repr:ident,
        $($(#[$variant_meta:meta])* $variant:ident = $value:literal,)+
    ) => {
        $(#[$enum_meta])*
        #[repr($repr)]
        pub enum $name {
            $($(#[$variant_meta])* $variant = $value,)+
        }

        impl $name {
            /// Every variant, in wire order. Public because the integration tests
            /// sweep it, a test that has to be told about a new variant being one
            /// that will eventually not be told about one.
            pub const ALL: [Self; [$(Self::$variant),+].len()] = [$(Self::$variant),+];

            /// Returns the wire discriminant.
            #[must_use]
            pub const fn as_wire(self) -> $repr {
                self as $repr
            }

            /// Parses a wire discriminant, returning `None` if unrecognised.
            #[must_use]
            pub const fn from_wire(value: $repr) -> Option<Self> {
                match value {
                    $($value => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}
pub(crate) use wire_enum;

wire_enum! {
    /// Frame discriminant.
    ///
    /// Exhaustive on purpose: both endpoints are built from this repository, so an
    /// unrecognised variant is a bug rather than a forward-compatibility case.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    FrameType: u8,
    /// Client opens a session, carrying its resume offsets and window size.
    Hello = 0x01,
    /// Daemon accepts, reporting where output will resume from.
    HelloOk = 0x02,
    /// Client keystrokes, at an absolute offset in the input stream.
    Input = 0x03,
    /// Daemon confirms input it has taken ownership of, and will never re-apply.
    InputAck = 0x04,
    /// PTY output, at an absolute offset in the output stream.
    Output = 0x05,
    /// Window size change, applied via `TIOCSWINSZ`.
    Resize = 0x06,
    /// Output was discarded by ring overflow; the stream is discontinuous.
    Gap = 0x07,
    /// The terminal stream ended, with the child outcome where it is known.
    Exit = 0x08,
    /// Client leaves without terminating the session.
    Detach = 0x09,
    /// Liveness probe.
    Ping = 0x0a,
    /// Liveness response.
    Pong = 0x0b,
    /// Daemon-side failure; the connection closes after this.
    Error = 0x0c,
    /// A process connected to the session's agent socket; open one to the real agent.
    AgentOpen = 0x0d,
    /// Opaque `ssh-agent` protocol bytes for the connection being served.
    AgentData = 0x0e,
    /// The served connection is finished, in either direction.
    AgentClose = 0x0f,
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Frame discriminant.
    pub ty: FrameType,
    /// Payload length in bytes.
    ///
    /// `<= MAX_PAYLOAD` in every header [`decode_header`] returns, which is the only
    /// thing that builds one outside the tests. The promise is that function's and not
    /// this type's: both fields are `pub`, so a `Header` written out by hand carries
    /// whatever it was given.
    pub len: u32,
}

/// A malformed frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// Discriminant is not a known [`FrameType`].
    UnknownFrameType(u8),
    /// Declared length exceeds [`MAX_PAYLOAD`].
    PayloadTooLarge(u32),
    /// Payload ended before the frame's fixed fields were complete.
    Truncated,
    /// Payload continued past the end of a fixed-size frame.
    TrailingBytes,
    /// Structurally intact but semantically invalid.
    Malformed(&'static str),
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::UnknownFrameType(byte) => write!(f, "unknown frame type {byte:#04x}"),
            Self::PayloadTooLarge(len) => {
                write!(f, "payload of {len} bytes exceeds maximum of {MAX_PAYLOAD}")
            }
            Self::Truncated => f.write_str("frame payload is truncated"),
            Self::TrailingBytes => f.write_str("frame payload has trailing bytes"),
            Self::Malformed(what) => write!(f, "malformed frame: {what}"),
        }
    }
}

/// Encodes a frame header. Reached only through [`Frame::encode`], after that function
/// has computed and validated the payload length.
///
/// # Errors
///
/// [`ProtoError::PayloadTooLarge`] if `len` exceeds [`MAX_PAYLOAD`].
pub(crate) const fn encode_header(ty: FrameType, len: u32) -> Result<[u8; HEADER_LEN], ProtoError> {
    if len > MAX_PAYLOAD {
        return Err(ProtoError::PayloadTooLarge(len));
    }
    // `len <= MAX_PAYLOAD` fits in 24 bits, so the high byte is always zero.
    let [_, a, b, c] = len.to_be_bytes();
    Ok([ty.as_wire(), a, b, c])
}

/// Decodes a frame header.
///
/// # Errors
///
/// [`ProtoError::UnknownFrameType`] for an unrecognised discriminant, or
/// [`ProtoError::PayloadTooLarge`] if the declared length exceeds [`MAX_PAYLOAD`].
///
/// # Examples
///
/// § 2.1's header, in bytes: the discriminant, then the length big endian in the
/// three that follow.
///
/// ```
/// use nomux_protocol::{FrameType, Header, decode_header};
///
/// assert_eq!(
///     decode_header(&[0x05, 0x00, 0x10, 0x00])?,
///     Header { ty: FrameType::Output, len: 4096 }
/// );
/// # Ok::<(), nomux_protocol::ProtoError>(())
/// ```
pub fn decode_header(bytes: &[u8; HEADER_LEN]) -> Result<Header, ProtoError> {
    let [ty, a, b, c] = *bytes;
    let ty = FrameType::from_wire(ty).ok_or(ProtoError::UnknownFrameType(ty))?;
    let len = u32::from_be_bytes([0, a, b, c]);
    if len > MAX_PAYLOAD {
        return Err(ProtoError::PayloadTooLarge(len));
    }
    Ok(Header { ty, len })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        for ty in FrameType::ALL {
            for len in [0, 1, 255, 256, 65_535, MAX_PAYLOAD] {
                let encoded = encode_header(ty, len).unwrap();
                assert_eq!(decode_header(&encoded).unwrap(), Header { ty, len });
            }
        }
    }

    /// The encoder's half only. [`decode_header`] is `pub`, and `tests/codec.rs`'s
    /// `header_decode_is_total` closes its whole domain — every type byte crossed with
    /// the lengths either side of the cap — so asserting single points of it here would
    /// only be a slower copy. [`encode_header`] is `pub(crate)` and out of that test's
    /// reach.
    #[test]
    fn oversized_payload_is_refused_by_the_encoder() {
        assert_eq!(
            encode_header(FrameType::Output, MAX_PAYLOAD + 1),
            Err(ProtoError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
    }
}
