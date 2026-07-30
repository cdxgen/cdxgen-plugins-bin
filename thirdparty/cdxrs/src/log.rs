//! NDJSON logging to stderr.
//!
//! Every log record is a single-line JSON object written to stderr so that
//! stdout is reserved exclusively for command output (BOM data, info results).

use serde_json::{Value, json};

/// Log level for a record.
#[derive(Debug, Clone, Copy)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Write a single NDJSON log record to stderr.
pub fn log(level: Level, msg: &str, extra: Option<&Value>) {
    let mut record = json!({
        "level": level.as_str(),
        "msg": msg,
    });
    if let Some(e) = extra
        && let Some(obj) = record.as_object_mut()
        && let Some(eobj) = e.as_object()
    {
        for (k, v) in eobj {
            obj.insert(k.clone(), v.clone());
        }
    }
    eprintln!("{record}");
}

pub fn debug(msg: &str) {
    log(Level::Debug, msg, None);
}

pub fn info(msg: &str) {
    log(Level::Info, msg, None);
}

pub fn warn(msg: &str) {
    log(Level::Warn, msg, None);
}

pub fn error(msg: &str) {
    log(Level::Error, msg, None);
}
