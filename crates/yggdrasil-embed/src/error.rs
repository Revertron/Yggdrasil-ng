//! Error type with stable numeric codes shared by all language bindings.

use std::fmt;
use std::io;

pub const ERR_INVALID_ARGUMENT: i32 = 1;
pub const ERR_CONFIG: i32 = 2;
pub const ERR_CONNECTION_REFUSED: i32 = 3;
pub const ERR_TIMED_OUT: i32 = 4;
pub const ERR_ADDR_IN_USE: i32 = 5;
pub const ERR_CLOSED: i32 = 6;
pub const ERR_WOULD_BLOCK: i32 = 7;
pub const ERR_IO: i32 = 8;
pub const ERR_PANIC: i32 = 9;
pub const ERR_NOT_FOUND: i32 = 10;

#[derive(Debug, Clone)]
pub struct Error {
    pub code: i32,
    pub message: String,
}

impl Error {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ERR_INVALID_ARGUMENT, message)
    }

    /// Closest `std::io::ErrorKind` for the code.
    pub fn kind(&self) -> io::ErrorKind {
        use io::ErrorKind::*;
        match self.code {
            ERR_INVALID_ARGUMENT | ERR_CONFIG => InvalidInput,
            ERR_CONNECTION_REFUSED => ConnectionRefused,
            ERR_TIMED_OUT => TimedOut,
            ERR_ADDR_IN_USE => AddrInUse,
            ERR_CLOSED => NotConnected,
            ERR_WOULD_BLOCK => WouldBlock,
            ERR_NOT_FOUND => NotFound,
            _ => Other,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        use io::ErrorKind::*;
        let code = match e.kind() {
            InvalidInput | InvalidData => ERR_INVALID_ARGUMENT,
            ConnectionRefused => ERR_CONNECTION_REFUSED,
            TimedOut => ERR_TIMED_OUT,
            AddrInUse => ERR_ADDR_IN_USE,
            NotConnected | BrokenPipe | ConnectionReset | ConnectionAborted => ERR_CLOSED,
            WouldBlock => ERR_WOULD_BLOCK,
            NotFound => ERR_NOT_FOUND,
            _ => ERR_IO,
        };
        Self::new(code, e.to_string())
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(e.kind(), e.message)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
