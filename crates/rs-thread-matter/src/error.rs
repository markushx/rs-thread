//! Error mapping between the stacks.

use rs_matter::error::{Error, ErrorCode};

/// Map an rs-thread error to the closest rs-matter error code.
pub fn map_err(e: rs_thread_core::Error) -> Error {
    use rs_thread_core::Error as E;
    let code = match e {
        E::NoBufs => ErrorCode::ResourceExhausted,
        E::InvalidArgs => ErrorCode::InvalidArgument,
        E::InvalidState => ErrorCode::InvalidState,
        E::NotFound => ErrorCode::NotFound,
        E::Already => ErrorCode::AlreadyExists,
        E::Busy => ErrorCode::Busy,
        E::ResponseTimeout => ErrorCode::RxTimeout,
        E::Parse => ErrorCode::InvalidData,
        E::NotImplemented => ErrorCode::InvalidAction,
        _ => ErrorCode::Invalid,
    };
    Error::new(code)
}
