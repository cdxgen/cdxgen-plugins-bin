use std::io::{BufRead, BufReader, Read};
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
    pub thought_log_path: Option<PathBuf>,
}

impl ProcessHandle {
    pub fn spawn(cmd: &str, args: &[String], thought_log: &str) -> Result<Self, String> {
        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("CDXGEN_THINK_MODE", "true")
            .env("CDXGEN_THOUGHT_LOG", thought_log)
            .env("CDXGEN_DEBUG_MODE", "verbose");

        let mut child = command.spawn().map_err(|e| format!("Failed to spawn {}: {}", cmd, e))?;

        let stdout = child.stdout.take().ok_or("No stdout")?;
        let stderr = child.stderr.take().ok_or("No stderr")?;

        let (log_tx, log_rx) = mpsc::channel::<LogEntry>();
        let (thought_tx, thought_rx) = mpsc::channel::<String>();

        // stdout reader thread
        let tx1 = log_tx.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(text) => {
                        if tx1.send(parse_line(&text, false)).is_err() {
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
                        if log_tx.send(parse_line(&text, true)).is_err() {
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
                    if current_size > last_size {
                        if let Ok(content) = std::fs::read_to_string(&thought_path_clone) {
                            let new_content = &content[last_size as usize..];
                            if !new_content.is_empty() {
                                if thought_tx.send(new_content.to_string()).is_err() {
                                    break;
                                }
                            }
                        }
                        last_size = current_size;
                    } else if current_size < last_size {
                        last_size = 0;
                    }
                }
            }
        });

        Ok(Self {
            child: Some(child),
            log_rx,
            thought_rx,
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
        if let Some(ref path) = self.thought_log_path {
            std::fs::read_to_string(path).ok()
        } else {
            None
        }
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

fn parse_line(line: &str, is_stderr: bool) -> LogEntry {
    let ansi_stripped = {
        let bytes = strip_ansi_escapes::strip(line);
        String::from_utf8_lossy(&bytes).into_owned()
    };

    let level = if is_stderr {
        let l = ansi_stripped.to_lowercase();
        if l.contains("error") || l.contains("fail") { LogLevel::Error }
        else if l.contains("warn") { LogLevel::Warn }
        else { LogLevel::Info }
    } else {
        let l = ansi_stripped.to_lowercase();
        if l.contains("error") || l.contains("fail") { LogLevel::Error }
        else if l.contains("warn") { LogLevel::Warn }
        else { LogLevel::Info }
    };

    LogEntry {
        timestamp: std::time::Instant::now(),
        level,
        text: ansi_stripped,
        thought_id: None,
    }
}
