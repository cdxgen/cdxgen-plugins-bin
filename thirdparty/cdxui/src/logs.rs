use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
    Thought,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub text: String,
    pub thought_id: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ThoughtBlock {
    pub id: usize,
    pub entry_count: usize,
}

pub struct LogStore {
    entries: VecDeque<LogEntry>,
    max_entries: usize,
    thought_blocks: Vec<ThoughtBlock>,
    next_thought_id: usize,
    open_thought: Option<usize>,
}

impl LogStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries,
            thought_blocks: Vec::new(),
            next_thought_id: 0,
            open_thought: None,
        }
    }

    pub fn push_line(&mut self, raw_line: &str) {
        let line = raw_line.trim_end_matches(&['\n', '\r'][..]);
        if line.is_empty() {
            return;
        }

        let ansi_stripped = strip_ansi(line);
        let (level, text) = classify_line(&ansi_stripped);

        let is_close_think = ansi_stripped.contains("</think>");
        let is_open_think = ansi_stripped.contains("<think>") || ansi_stripped.contains("<think");

        let thought_id = if is_open_think {
            let id = self.next_thought_id;
            self.next_thought_id += 1;
            self.open_thought = Some(id);
            if is_close_think {
                self.open_thought = None;
            }
            self.thought_blocks.push(ThoughtBlock {
                id,
                entry_count: 1,
            });
            Some(id)
        } else if let Some(id) = self.open_thought {
            if let Some(block) = self.thought_blocks.iter_mut().find(|b| b.id == id) {
                block.entry_count += 1;
            }
            if is_close_think {
                self.open_thought = None;
            }
            Some(id)
        } else {
            None
        };

        self.entries.push_back(LogEntry {
            level,
            text,
            thought_id,
        });

        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
            if let Some(first) = self.entries.front() {
                if let Some(tid) = first.thought_id {
                    self.thought_blocks.iter_mut().find(|b| b.id == tid).map(|b| {
                        b.entry_count = b.entry_count.saturating_sub(1);
                    });
                }
            }
        }
    }

    pub fn entries(&self) -> &VecDeque<LogEntry> {
        &self.entries
    }
}

fn classify_line(line: &str) -> (LogLevel, String) {
    let trimmed = line.trim();

    if trimmed.contains("<think>") || trimmed.starts_with("<think") {
        let text = trimmed
            .replace("<think>", "")
            .replace("<think", "")
            .trim()
            .to_string();
        return (LogLevel::Thought, text);
    }

    if trimmed.ends_with("</think>") {
        let text = trimmed.replace("</think>", "").trim().to_string();
        return (LogLevel::Thought, text);
    }

    let lower = trimmed.to_lowercase();
    if lower.contains("error") || lower.contains("fail") || lower.contains(" panic") {
        return (LogLevel::Error, line.to_string());
    }
    if lower.contains("warn") || lower.starts_with("warning") {
        return (LogLevel::Warn, line.to_string());
    }
    if lower.contains("debug") || lower.starts_with("[debug]") {
        return (LogLevel::Debug, line.to_string());
    }

    (LogLevel::Info, line.to_string())
}

fn strip_ansi(input: &str) -> String {
    let bytes = strip_ansi_escapes::strip(input);
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_thought_open() {
        let (level, _text) = classify_line("<think>Let me analyze this project");
        assert_eq!(level, LogLevel::Thought);
    }

    #[test]
    fn test_classify_thought_close() {
        let (level, _text) = classify_line("Analysis complete</think>");
        assert_eq!(level, LogLevel::Thought);
    }

    #[test]
    fn test_classify_error() {
        let (level, _text) = classify_line("ERROR: Failed to parse file");
        assert_eq!(level, LogLevel::Error);
    }

    #[test]
    fn test_classify_warn() {
        let (level, _text) = classify_line("Warning: deprecated API");
        assert_eq!(level, LogLevel::Warn);
    }

    #[test]
    fn test_classify_info() {
        let (level, _text) = classify_line("Collecting packages...");
        assert_eq!(level, LogLevel::Info);
    }
}
