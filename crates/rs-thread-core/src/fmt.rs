//! Logging macros that forward to `defmt` or `log`, or compile to nothing.
//!
//! Exported at the crate root: `rs_thread_core::info!(...)` etc.
//! Enable at most one of the `defmt` / `log` features. With `log`, the macros
//! go through a re-export (`$crate::__log`), so calling crates need no `log`
//! dependency. With `defmt`, calling crates must depend on `defmt` and
//! forward the feature, because defmt's macros expand to `::defmt` paths in
//! the caller.
//! Only use the format-string subset common to both (`{}`, `{:?}`).
//! Without a backend the arguments are only borrowed (no trait bounds), so
//! callers get no unused-variable warnings.

#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("features `defmt` and `log` are mutually exclusive");

/// Log at `trace` level via the enabled logging backend.
#[cfg(feature = "defmt")]
#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => { ::defmt::trace!($($t)*) };
}

/// Log at `trace` level via the enabled logging backend.
#[cfg(feature = "log")]
#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => { $crate::__log::trace!($($t)*) };
}

/// Log at `trace` level via the enabled logging backend.
#[cfg(not(any(feature = "defmt", feature = "log")))]
#[macro_export]
macro_rules! trace {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        let _ = $s;
        $(let _ = &$x;)*
    }};
}

/// Log at `debug` level via the enabled logging backend.
#[cfg(feature = "defmt")]
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => { ::defmt::debug!($($t)*) };
}

/// Log at `debug` level via the enabled logging backend.
#[cfg(feature = "log")]
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => { $crate::__log::debug!($($t)*) };
}

/// Log at `debug` level via the enabled logging backend.
#[cfg(not(any(feature = "defmt", feature = "log")))]
#[macro_export]
macro_rules! debug {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        let _ = $s;
        $(let _ = &$x;)*
    }};
}

/// Log at `info` level via the enabled logging backend.
#[cfg(feature = "defmt")]
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { ::defmt::info!($($t)*) };
}

/// Log at `info` level via the enabled logging backend.
#[cfg(feature = "log")]
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { $crate::__log::info!($($t)*) };
}

/// Log at `info` level via the enabled logging backend.
#[cfg(not(any(feature = "defmt", feature = "log")))]
#[macro_export]
macro_rules! info {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        let _ = $s;
        $(let _ = &$x;)*
    }};
}

/// Log at `warn` level via the enabled logging backend.
#[cfg(feature = "defmt")]
#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => { ::defmt::warn!($($t)*) };
}

/// Log at `warn` level via the enabled logging backend.
#[cfg(feature = "log")]
#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => { $crate::__log::warn!($($t)*) };
}

/// Log at `warn` level via the enabled logging backend.
#[cfg(not(any(feature = "defmt", feature = "log")))]
#[macro_export]
macro_rules! warn {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        let _ = $s;
        $(let _ = &$x;)*
    }};
}

/// Log at `error` level via the enabled logging backend.
#[cfg(feature = "defmt")]
#[macro_export]
macro_rules! error {
    ($($t:tt)*) => { ::defmt::error!($($t)*) };
}

/// Log at `error` level via the enabled logging backend.
#[cfg(feature = "log")]
#[macro_export]
macro_rules! error {
    ($($t:tt)*) => { $crate::__log::error!($($t)*) };
}

/// Log at `error` level via the enabled logging backend.
#[cfg(not(any(feature = "defmt", feature = "log")))]
#[macro_export]
macro_rules! error {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        let _ = $s;
        $(let _ = &$x;)*
    }};
}
