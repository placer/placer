//! Macros used by this crate

/// Create a new error (of a given enum variant) with a formatted message
macro_rules! err {
    ($variant:ident, $msg:expr) => {
        crate::error::Error::$variant { description: $msg.to_owned() }
    };
    ($variant:ident, $fmt:expr, $($arg:tt)+) => {
        crate::error::Error::$variant { description: format!($fmt, $($arg)+) }
    };
}

/// Create and return an error enum variant with a formatted message
macro_rules! fail {
    ($variant:ident, $msg:expr) => {
        return Err(err!($variant, $msg).into());
    };
    ($variant:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(err!($variant, $fmt, $($arg)+).into());
    };
}
