//! Error codes, the thread-local last error, and the panic guard every
//! exported function runs in.

use std::cell::RefCell;
use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub use yggdrasil_embed::{Error, Result};

pub const YGG_OK: i32 = 0;
pub const YGG_ERR_INVALID_ARGUMENT: i32 = yggdrasil_embed::ERR_INVALID_ARGUMENT;
pub const YGG_ERR_CONFIG: i32 = yggdrasil_embed::ERR_CONFIG;
pub const YGG_ERR_CONNECTION_REFUSED: i32 = yggdrasil_embed::ERR_CONNECTION_REFUSED;
pub const YGG_ERR_TIMED_OUT: i32 = yggdrasil_embed::ERR_TIMED_OUT;
pub const YGG_ERR_ADDR_IN_USE: i32 = yggdrasil_embed::ERR_ADDR_IN_USE;
pub const YGG_ERR_CLOSED: i32 = yggdrasil_embed::ERR_CLOSED;
pub const YGG_ERR_WOULD_BLOCK: i32 = yggdrasil_embed::ERR_WOULD_BLOCK;
pub const YGG_ERR_IO: i32 = yggdrasil_embed::ERR_IO;
pub const YGG_ERR_PANIC: i32 = yggdrasil_embed::ERR_PANIC;
pub const YGG_ERR_NOT_FOUND: i32 = yggdrasil_embed::ERR_NOT_FOUND;

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
