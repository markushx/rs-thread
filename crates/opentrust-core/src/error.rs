//! Error type shared by all OpenTrust crates.

use core::fmt;

/// Result alias using [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors returned by OpenTrust operations.
///
/// Loosely mirrors the subset of OpenThread's `otError` that the protocol
/// layers need, so behaviour can be compared in differential tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Error {
    /// Input could not be parsed (truncated, malformed, out-of-range field).
    Parse,
    /// Not enough buffer space (output buffer, message pool, table).
    NoBufs,
    /// An argument is invalid.
    InvalidArgs,
    /// The operation is not allowed in the current state.
    InvalidState,
    /// The requested item does not exist.
    NotFound,
    /// The item already exists / the operation is already in progress.
    Already,
    /// The resource is busy.
    Busy,
    /// Security check failed (MIC mismatch, replayed frame counter, ...).
    Security,
    /// The message was dropped (e.g. filtered or duplicate).
    Drop,
    /// No response was received in time.
    ResponseTimeout,
    /// The operation is not implemented.
    NotImplemented,
    /// The operation was aborted.
    Abort,
    /// A platform/driver operation failed.
    Platform,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Parse => "parse error",
            Error::NoBufs => "no buffers",
            Error::InvalidArgs => "invalid arguments",
            Error::InvalidState => "invalid state",
            Error::NotFound => "not found",
            Error::Already => "already",
            Error::Busy => "busy",
            Error::Security => "security check failed",
            Error::Drop => "dropped",
            Error::ResponseTimeout => "response timeout",
            Error::NotImplemented => "not implemented",
            Error::Abort => "aborted",
            Error::Platform => "platform error",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}
