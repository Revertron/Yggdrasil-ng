//! Error codes, the thread-local last error, and the panic guard every
//! exported function runs in.

use std::cell::RefCell;
use std::ffi::{CString, c_char};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub const YGG_OK: i32 = 0;
pub const YGG_ERR_INVALID_ARGUMENT: i32 = 1;
pub const YGG_ERR_CONFIG: i32 = 2;
pub const YGG_ERR_CONNECTION_REFUSED: i32 = 3;
pub const YGG_ERR_TIMED_OUT: i32 = 4;
pub const YGG_ERR_ADDR_IN_USE: i32 = 5;
pub const YGG_ERR_CLOSED: i32 = 6;
pub const YGG_ERR_WOULD_BLOCK: i32 = 7;
pub const YGG_ERR_IO: i32 = 8;
pub const YGG_ERR_PANIC: i32 = 9;
pub const YGG_ERR_NOT_FOUND: i32 = 10;

#[derive(Debug)]
pub struct Error {
    pub code: i32,
    pub message: String,
}

impl Error {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(YGG_ERR_INVALID_ARGUMENT, message)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        use io::ErrorKind::*;
        let code = match e.kind() {
            InvalidInput | InvalidData => YGG_ERR_INVALID_ARGUMENT,
            ConnectionRefused => YGG_ERR_CONNECTION_REFUSED,
            TimedOut => YGG_ERR_TIMED_OUT,
            AddrInUse => YGG_ERR_ADDR_IN_USE,
            NotConnected | BrokenPipe | ConnectionReset | ConnectionAborted => YGG_ERR_CLOSED,
            WouldBlock => YGG_ERR_WOULD_BLOCK,
            NotFound => YGG_ERR_NOT_FOUND,
            _ => YGG_ERR_IO,
        };
        Self::new(code, e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> = RefCell::new((YGG_OK, CString::default()));
}

fn set_last_error(code: i32, message: &str) {
    let message = CString::new(message.replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = (code, message));
}

/// Run an exported function body: record its error (or panic) as the
/// thread's last error and return `on_error` in that case.
pub fn guard<T>(on_error: T, f: impl FnOnce() -> Result<T>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => {
            set_last_error(YGG_OK, "");
            value
        }
        Ok(Err(e)) => {
            set_last_error(e.code, &e.message);
            on_error
        }
        Err(panic) => {
            let message = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_string());
            set_last_error(YGG_ERR_PANIC, &format!("internal error: {message}"));
            on_error
        }
    }
}

/// Code of the last error on the calling thread (`YGG_OK` after a success).
#[unsafe(no_mangle)]
pub extern "C" fn ygg_last_error() -> i32 {
    LAST_ERROR.with(|e| e.borrow().0)
}

/// Message of the last error on the calling thread. Valid until the next
/// `ygg_*` call on this thread; never NULL.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_last_error_message() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}
