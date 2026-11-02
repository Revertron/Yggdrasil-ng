//! Routes the node's log output to a callback (C function, Python callable,
//! Kotlin interface, ...).

use std::io;
use std::sync::Arc;

use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

use crate::error::{ERR_CONFIG, Error, Result};

pub const LOG_ERROR: i32 = 1;
pub const LOG_WARN: i32 = 2;
pub const LOG_INFO: i32 = 3;
pub const LOG_DEBUG: i32 = 4;
pub const LOG_TRACE: i32 = 5;

type Sink = Arc<dyn Fn(i32, &str) + Send + Sync>;

#[derive(Clone)]
struct SinkWriter(Sink);

impl<'a> MakeWriter<'a> for SinkWriter {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter { sink: self.0.clone(), level: LOG_INFO, buf: Vec::new() }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        let level = match *meta.level() {
            Level::ERROR => LOG_ERROR,
            Level::WARN => LOG_WARN,
            Level::INFO => LOG_INFO,
            Level::DEBUG => LOG_DEBUG,
            Level::TRACE => LOG_TRACE,
        };
        LineWriter { sink: self.0.clone(), level, buf: Vec::new() }
    }
}

/// Collects one formatted event and hands it to the sink when dropped.
pub struct LineWriter {
    sink: Sink,
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
        let text = String::from_utf8_lossy(&self.buf);
        let text = text.trim_end_matches('\n');
        if !text.is_empty() {
            (self.sink)(self.level, text);
        }
    }
}

/// Send log events to `sink(level, message)`. `filter` uses tracing
/// EnvFilter syntax ("info", "warn,yggdrasil::links=debug"). Can be installed
/// once per process; the sink is called from library threads.
pub fn set_logger(sink: impl Fn(i32, &str) + Send + Sync + 'static, filter: &str) -> Result<()> {
    let filter = EnvFilter::try_new(filter).map_err(|e| Error::new(ERR_CONFIG, e.to_string()))?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(SinkWriter(Arc::new(sink)))
        .with_ansi(false)
        .without_time()
        .with_level(false)
        .with_target(true)
        .try_init()
        .map_err(|e| Error::new(ERR_CONFIG, format!("logger already installed: {e}")))
}
