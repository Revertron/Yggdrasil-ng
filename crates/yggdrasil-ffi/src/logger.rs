//! Forwards the library's log output to a C callback.

use std::ffi::{CStr, CString, c_char, c_void};
use std::io;

use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

use crate::error::{Error, Result, YGG_ERR_CONFIG};

pub const YGG_LOG_ERROR: i32 = 1;
pub const YGG_LOG_WARN: i32 = 2;
pub const YGG_LOG_INFO: i32 = 3;
pub const YGG_LOG_DEBUG: i32 = 4;
pub const YGG_LOG_TRACE: i32 = 5;

pub type LogFn = extern "C" fn(userdata: *mut c_void, level: i32, message: *const c_char);

#[derive(Clone, Copy)]
struct Callback {
    f: LogFn,
    userdata: *mut c_void,
}

// SAFETY: the API contract requires the callback and userdata to be usable
// from any thread.
unsafe impl Send for Callback {}
unsafe impl Sync for Callback {}

impl<'a> MakeWriter<'a> for Callback {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter { cb: *self, level: YGG_LOG_INFO, buf: Vec::new() }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        let level = match *meta.level() {
            Level::ERROR => YGG_LOG_ERROR,
            Level::WARN => YGG_LOG_WARN,
            Level::INFO => YGG_LOG_INFO,
            Level::DEBUG => YGG_LOG_DEBUG,
            Level::TRACE => YGG_LOG_TRACE,
        };
        LineWriter { cb: *self, level, buf: Vec::new() }
    }
}

/// Collects one formatted event and hands it to the callback when dropped.
pub struct LineWriter {
    cb: Callback,
    level: i32,
    buf: Vec<u8>,
}

impl io::Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        while self.buf.last().is_some_and(|b| *b == b'\n') {
            self.buf.pop();
        }
        if self.buf.is_empty() {
            return;
        }
        self.buf.retain(|b| *b != 0);
        if let Ok(msg) = CString::new(std::mem::take(&mut self.buf)) {
            (self.cb.f)(self.cb.userdata, self.level, msg.as_ptr());
        }
    }
}

pub fn install(f: LogFn, userdata: *mut c_void, filter: *const c_char) -> Result<()> {
    let filter = if filter.is_null() {
        "info".to_string()
    } else {
        // SAFETY: the caller passes a NUL-terminated string.
        unsafe { CStr::from_ptr(filter) }.to_string_lossy().into_owned()
    };
    let filter = EnvFilter::try_new(&filter).map_err(|e| Error::new(YGG_ERR_CONFIG, e.to_string()))?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(Callback { f, userdata })
        .with_ansi(false)
        .without_time()
        .with_level(false)
        .with_target(true)
        .try_init()
        .map_err(|e| Error::new(YGG_ERR_CONFIG, format!("logger already installed: {e}")))
}
