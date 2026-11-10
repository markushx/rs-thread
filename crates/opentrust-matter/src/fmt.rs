//! Logging shim: `log` or `defmt` by feature, silent otherwise.
#![allow(unused_macros, unused_imports)]

macro_rules! log_warn {
    ($($arg:tt)*) => {{
        #[cfg(feature = "log")]
        ::log::warn!($($arg)*);
        #[cfg(all(feature = "defmt", not(feature = "log")))]
        ::defmt::warn!($($arg)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        { let _ = format_args!($($arg)*); }
    }};
}

macro_rules! log_debug {
    ($($arg:tt)*) => {{
        #[cfg(feature = "log")]
        ::log::debug!($($arg)*);
        #[cfg(all(feature = "defmt", not(feature = "log")))]
        ::defmt::debug!($($arg)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        { let _ = format_args!($($arg)*); }
    }};
}

macro_rules! log_info {
    ($($arg:tt)*) => {{
        #[cfg(feature = "log")]
        ::log::info!($($arg)*);
        #[cfg(all(feature = "defmt", not(feature = "log")))]
        ::defmt::info!($($arg)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        { let _ = format_args!($($arg)*); }
    }};
}

pub(crate) use {log_debug, log_info, log_warn};
