//! Wire protocol for nomux.
//!
//! Spoken end-to-end between the client and the session daemon; the `attach` relay
//! is transparent to it. See `IMPLEMENTATION.md` § 2 for the frame tables.
//!
//! A private protocol with no stability guarantee: [`PROTOCOL_VERSION`] exists to
//! fail fast on a mismatched peer rather than to negotiate (`IMPLEMENTATION.md` § 2).

#![forbid(unsafe_code)]

mod frame;

pub use frame::{
    ErrorCode, ExitKind, Frame, HELLO_AGENT_FORWARD, HELLO_REPAINT_CTRL_L, Hello, HelloOk, Linger,
    RESUME_FROM_START, WinSize,
};

/// Protocol revision. Bumped on any wire change, including compatible ones.
///
/// `IMPLEMENTATION.md` § 2.2 owns the history. The number is held against that
/// section by `the_frozen_numbers_are_the_ones_the_document_gives` and against the
/// handshake vectors' literal by `the_vectors_pin_every_value_of_every_closed_set`,
/// so a bump has to move the constant, the vectors and the document.
pub const PROTOCOL_VERSION: u16 = 5;

/// Fixed frame header size, so reads are a two-stage `read_exact`.
pub const HEADER_LEN: usize = 4;

/// Largest permitted payload. Bounds the peer's ability to force an allocation.
pub const MAX_PAYLOAD: u32 = 256 * 1024;

// A discriminant list is written down once, and everything derived from it — the
// enum, both directions of the conversion, and the `ALL` the suites sweep — is
// generated, so the four cannot drift apart. A hand-written `from_byte` ending in a
// catch-all `_ => None` leaves an end that can *send* a new frame but never
// *receives* one. `IMPLEMENTATION.md` § 2.3 applies the same closed-set rule to
// `Error.code`, `Exit.kind` and the linger field, hence the parameters: those sets
// differ in their repr and in what the accessors are called.
macro_rules! wire_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident: $repr:ident, $as_fn:ident / $from_fn:ident,
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
            pub const fn $as_fn(self) -> $repr {
                self as $repr
            }

            /// Parses a wire discriminant, returning `None` if unrecognised.
            #[must_use]
            pub const fn $from_fn(value: $repr) -> Option<Self> {
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
    FrameType: u8, as_byte / from_byte,
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
    /// Client has consumed output. Advisory, payload-free, and never trims the ring.
    OutputAck = 0x06,
    /// Window size change, applied via `TIOCSWINSZ`.
    Resize = 0x07,
    /// Output was discarded by ring overflow; the stream is discontinuous.
    Gap = 0x08,
    /// The child process terminated.
    Exit = 0x09,
    /// Client leaves without terminating the session.
    Detach = 0x0a,
    /// Liveness probe.
    Ping = 0x0b,
    /// Liveness response, echoing the nonce.
    Pong = 0x0c,
    /// Daemon-side failure; the connection closes after this.
    Error = 0x0d,
    /// A process connected to the session's agent socket; open a peer channel.
    AgentOpen = 0x0e,
    /// Opaque `ssh-agent` protocol bytes for one agent channel.
    AgentData = 0x0f,
    /// One agent channel is finished, in either direction.
    AgentClose = 0x10,
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Frame discriminant.
    pub ty: FrameType,
    /// Payload length in bytes, guaranteed `<= MAX_PAYLOAD`.
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

impl core::error::Error for ProtoError {}

/// Encodes a frame header.
///
/// # Errors
///
/// [`ProtoError::PayloadTooLarge`] if `len` exceeds [`MAX_PAYLOAD`].
pub const fn encode_header(ty: FrameType, len: u32) -> Result<[u8; HEADER_LEN], ProtoError> {
    if len > MAX_PAYLOAD {
        return Err(ProtoError::PayloadTooLarge(len));
    }
    // `len <= MAX_PAYLOAD` fits in 24 bits, so the high byte is always zero.
    let [_, a, b, c] = len.to_be_bytes();
    Ok([ty.as_byte(), a, b, c])
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
/// ```
/// use nomux_proto::{FrameType, Header, decode_header, encode_header};
///
/// let bytes = encode_header(FrameType::Output, 4096)?;
/// assert_eq!(bytes, [0x05, 0x00, 0x10, 0x00]);
/// assert_eq!(
///     decode_header(&bytes)?,
///     Header { ty: FrameType::Output, len: 4096 }
/// );
/// # Ok::<(), nomux_proto::ProtoError>(())
/// ```
pub fn decode_header(bytes: &[u8; HEADER_LEN]) -> Result<Header, ProtoError> {
    let [ty, a, b, c] = *bytes;
    let ty = FrameType::from_byte(ty).ok_or(ProtoError::UnknownFrameType(ty))?;
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

    #[test]
    fn oversized_payload_is_rejected() {
        assert_eq!(
            encode_header(FrameType::Output, MAX_PAYLOAD + 1),
            Err(ProtoError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
        // 0x00_04_00_01 == MAX_PAYLOAD + 1, encoded by hand since the encoder refuses.
        assert_eq!(
            decode_header(&[FrameType::Output.as_byte(), 0x04, 0x00, 0x01]),
            Err(ProtoError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
    }

    #[test]
    fn unknown_frame_type_is_rejected() {
        assert_eq!(
            decode_header(&[0x00, 0, 0, 0]),
            Err(ProtoError::UnknownFrameType(0x00))
        );
        assert_eq!(
            decode_header(&[0xff, 0, 0, 0]),
            Err(ProtoError::UnknownFrameType(0xff))
        );
    }
}
