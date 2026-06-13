use std::collections::VecDeque;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
    Thought,
    ProcessExit(i32),
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: Instant,
    pub level: LogLevel,
    pub text: String,
    pub thought_id: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ThoughtBlock {
    pub id: usize,
    pub title: String,
    pub collapsed: bool,
    pub entry_count: usize,
}

pub struct LogStore {
    entries: VecDeque<LogEntry>,
    max_entries: usize,
    thought_blocks: Vec<ThoughtBlock>,
    next_thought_id: usize,
    open_thought: Option<usize>,
    pub auto_scroll: bool,
}

impl LogStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries,
            thought_blocks: Vec::new(),
            next_thought_id: 0,
            open_thought: None,
            auto_scroll: true,
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
                title: text.clone(),
                collapsed: false,
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
            timestamp: Instant::now(),
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

    pub fn thought_blocks(&self) -> &[ThoughtBlock] {
        &self.thought_blocks
    }

    pub fn toggle_thought(&mut self, id: usize) {
        if let Some(block) = self.thought_blocks.iter_mut().find(|b| b.id == id) {
            block.collapsed = !block.collapsed;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
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

    #[test]
    fn test_thought_block_tracking() {
        let mut store = LogStore::new(1000);
        store.push_line("<think>Analyzing project");
        assert_eq!(store.thought_blocks().len(), 1);
        assert_eq!(store.thought_blocks()[0].entry_count, 1);

        store.push_line("Found 42 components");
        assert_eq!(store.thought_blocks()[0].entry_count, 2);

        store.push_line("Done</think>");
        assert!(store.open_thought.is_none());
    }

    #[test]
    fn test_toggle_thought() {
        let mut store = LogStore::new(1000);
        store.push_line("<think>Test thought");
        store.push_line("Line 2</think>");
        assert!(!store.thought_blocks()[0].collapsed);
        store.toggle_thought(0);
        assert!(store.thought_blocks()[0].collapsed);
    }
}
