use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::logs::{LogEntry, LogLevel};

pub struct ProcessHandle {
    child: Option<Child>,
    pub log_rx: mpsc::Receiver<LogEntry>,
    pub thought_rx: mpsc::Receiver<String>,
    pub trace_rx: mpsc::Receiver<String>,
    pub thought_log_path: Option<PathBuf>,
}

impl ProcessHandle {
    pub fn spawn(
        cmd: &str,
        args: &[String],
        thought_log: &str,
        trace_log: &str,
    ) -> Result<Self, String> {
        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("CDXGEN_THINK_MODE", "true")
            .env("CDXGEN_THOUGHT_LOG", thought_log)
            .env("CDXGEN_TRACE_MODE", "true")
            .env("CDXGEN_TRACE_LOG", trace_log)
            // Progress belongs to this UI, not to the child. cdxgen already
            // disables its live region on a pipe; saying so explicitly keeps
            // cursor-control sequences out of the captured log either way.
            .env("CDXGEN_NO_PROGRESS", "true")
            .env(
                "FETCH_LICENSE",
                std::env::var("FETCH_LICENSE").unwrap_or_default(),
            );

        let mut child = command
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", cmd, e))?;

        let stdout = child.stdout.take().ok_or("No stdout")?;
        let stderr = child.stderr.take().ok_or("No stderr")?;

        let (log_tx, log_rx) = mpsc::channel::<LogEntry>();
        let (thought_tx, thought_rx) = mpsc::channel::<String>();
        let (trace_tx, trace_rx) = mpsc::channel::<String>();

        // stdout reader thread
        let tx1 = log_tx.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(text) => {
                        if tx1.send(parse_line(&text)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // stderr reader thread
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                match line {
                    Ok(text) => {
                        if log_tx.send(parse_line(&text)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // thought log file reader thread
        let thought_path = PathBuf::from(thought_log.to_string());
        let thought_path_clone = thought_path.clone();
        thread::spawn(move || {
            let mut last_size = 0u64;
            loop {
                thread::sleep(Duration::from_millis(500));
                if let Ok(meta) = std::fs::metadata(&thought_path_clone) {
                    let current_size = meta.len();
                    // A shrink means a fresh log file (new cdxgen run): restart
                    // from the top on the next poll.
                    if current_size < last_size {
                        last_size = 0;
                    } else if current_size > last_size
                        && let Ok(content) = std::fs::read_to_string(&thought_path_clone)
                    {
                        let new_content = &content[last_size as usize..];
                        if !new_content.is_empty()
                            && thought_tx.send(new_content.to_string()).is_err()
                        {
                            break;
                        }
                        last_size = current_size;
                    }
                }
            }
        });

        // trace log file reader thread
        let trace_path = PathBuf::from(trace_log.to_string());
        let trace_path_clone = trace_path.clone();
        thread::spawn(move || {
            let mut last_size = 0u64;
            loop {
                thread::sleep(Duration::from_millis(250));
                if let Ok(meta) = std::fs::metadata(&trace_path_clone) {
                    let current_size = meta.len();
                    if current_size < last_size {
                        last_size = 0;
                    } else if current_size > last_size
                        && let Ok(content) = std::fs::read_to_string(&trace_path_clone)
                    {
                        let new_content = &content[last_size as usize..];
                        if !new_content.is_empty()
                            && trace_tx.send(new_content.to_string()).is_err()
                        {
                            break;
                        }
                        last_size = current_size;
                    }
                }
            }
        });

        Ok(Self {
            child: Some(child),
            log_rx,
            thought_rx,
            trace_rx,
            thought_log_path: Some(thought_path),
        })
    }

    pub fn try_wait(&mut self) -> Option<i32> {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.code().unwrap_or(-1);
                    self.child = None;
                    Some(code)
                }
                Ok(None) => None,
                Err(_) => {
                    self.child = None;
                    Some(-1)
                }
            }
        } else {
            Some(0)
        }
    }

    pub fn read_thought_log(&self) -> Option<String> {
        self.thought_log_path
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok())
    }

    pub fn kill(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            self.child = None;
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Classify one line of child output.
///
/// The stream a line arrived on carries no severity: cdxgen v13 writes every
/// human-readable diagnostic to stderr so that stdout carries only the BOM
/// payload, so treating stderr as a warning would paint the whole log yellow.
fn parse_line(line: &str) -> LogEntry {
    let ansi_stripped = {
        let bytes = strip_ansi_escapes::strip(line);
        String::from_utf8_lossy(&bytes).into_owned()
    };

    let l = ansi_stripped.to_lowercase();
    let level = if l.contains("error") || l.contains("fail") {
        LogLevel::Error
    } else if l.contains("warn") {
        LogLevel::Warn
    } else {
        LogLevel::Info
    };

    LogEntry {
        level,
        text: ansi_stripped,
        thought_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stderr_lines_are_not_all_warnings() {
        // Every v13 diagnostic arrives on stderr, including ordinary progress.
        let entry = parse_line("✔ Generating BOM  5770 components  3.4s");
        assert_eq!(entry.level, LogLevel::Info);
    }

    #[test]
    fn test_error_and_warning_are_classified_by_content() {
        assert_eq!(parse_line("ERROR: could not parse").level, LogLevel::Error);
        assert_eq!(parse_line("Warning: deprecated").level, LogLevel::Warn);
    }

    #[test]
    fn test_ansi_is_stripped() {
        let entry = parse_line("\x1b[32m✔ done\x1b[39m");
        assert_eq!(entry.text, "✔ done");
    }
}
