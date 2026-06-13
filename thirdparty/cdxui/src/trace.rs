use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TraceEvent {
    #[serde(rename = "type")]
    pub event_type: Option<String>,

    pub cmd: Option<String>,
    pub host: Option<String>,
    pub url: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub operation: Option<String>,
    pub status: Option<String>,
    pub duration: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Idle,
    Http,
    Command,
    FileRead,
    FileWrite,
    Network,
}

#[derive(Debug, Clone)]
pub struct TraceState {
    pub current_activity: Activity,
    pub activity_label: String,
    pub frame: u64,
    pub command_count: usize,
    pub http_count: usize,
    pub file_count: usize,
}

impl TraceState {
    pub fn new() -> Self {
        Self {
            current_activity: Activity::Idle,
            activity_label: String::new(),
            frame: 0,
            command_count: 0,
            http_count: 0,
            file_count: 0,
        }
    }

    pub fn process_line(&mut self, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        if let Ok(event) = serde_json::from_str::<TraceEvent>(line.trim()) {
            let event_type = event.event_type.as_deref().unwrap_or("");

            match event_type {
                "http" | "fetch" | "download" => {
                    self.current_activity = Activity::Http;
                    self.http_count += 1;
                    self.activity_label = event.url.as_deref()
                        .map(|u| {
                            if u.len() > 50 { format!("🌐 {}", &u[..47]) } else { format!("🌐 {}", u) }
                        })
                        .unwrap_or_else(|| "🌐 HTTP".to_string());
                }
                "command" | "spawn" | "exec" => {
                    self.current_activity = Activity::Command;
                    self.command_count += 1;
                    self.activity_label = event.cmd.as_deref()
                        .map(|c| {
                            let cmd_name = c.split_whitespace().next().unwrap_or(c);
                            if cmd_name.len() > 30 { format!("⚙ {}", &cmd_name[..27]) } else { format!("⚙ {}", cmd_name) }
                        })
                        .unwrap_or_else(|| "⚙ exec".to_string());
                }
                "file_read" | "read" => {
                    self.current_activity = Activity::FileRead;
                    self.file_count += 1;
                }
                "file_write" | "write" | "output" => {
                    self.current_activity = Activity::FileWrite;
                    self.file_count += 1;
                }
                "network" | "connect" | "dns" => {
                    self.current_activity = Activity::Network;
                }
                _ => {}
            }
        }
    }

    pub fn tick(&mut self) {
        self.frame += 1;
        if self.frame % 120 == 0 {
            self.current_activity = Activity::Idle;
            self.activity_label.clear();
        }
    }

    pub fn spinner(&self) -> &'static str {
        const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        FRAMES[self.frame as usize % FRAMES.len()]
    }

    pub fn status_icon(&self) -> &'static str {
        match self.current_activity {
            Activity::Idle => self.spinner(),
            Activity::Http => {
                const FLASH: &[&str] = &["🌐", "🌍", "🌏", "🌎"];
                FLASH[self.frame as usize % FLASH.len()]
            }
            Activity::Command => "⚙",
            Activity::FileRead => "📖",
            Activity::FileWrite => "✏",
            Activity::Network => {
                const NET: &[&str] = &["⬇", "⬆", "↕"];
                NET[self.frame as usize % NET.len()]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_http() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"http","url":"https://registry.npmjs.org/express","method":"GET"}"#);
        assert_eq!(ts.current_activity, Activity::Http);
        assert_eq!(ts.http_count, 1);
        assert!(ts.activity_label.contains("🌐"));
    }

    #[test]
    fn test_trace_command() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"command","cmd":"pip install requests","host":"localhost"}"#);
        assert_eq!(ts.current_activity, Activity::Command);
        assert_eq!(ts.command_count, 1);
    }

    #[test]
    fn test_trace_file() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"file_read","path":"/etc/os-release"}"#);
        assert_eq!(ts.current_activity, Activity::FileRead);
        assert_eq!(ts.file_count, 1);
    }

    #[test]
    fn test_trace_empty() {
        let mut ts = TraceState::new();
        ts.process_line("");
        assert_eq!(ts.current_activity, Activity::Idle);
    }

    #[test]
    fn test_trace_invalid_json() {
        let mut ts = TraceState::new();
        ts.process_line("not json");
        assert_eq!(ts.current_activity, Activity::Idle);
    }

    #[test]
    fn test_tick_idle_reset() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"http","url":"https://example.com"}"#);
        assert_eq!(ts.current_activity, Activity::Http);
        for _ in 0..120 {
            ts.tick();
        }
        assert_eq!(ts.current_activity, Activity::Idle);
    }

    #[test]
    fn test_spinner_cycles() {
        let mut ts = TraceState::new();
        assert_eq!(ts.spinner(), "⠋");
        ts.tick();
        assert_eq!(ts.spinner(), "⠙");
    }
}
