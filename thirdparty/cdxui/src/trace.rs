use serde::Deserialize;

/// One record from cdxgen's structured trace stream.
///
/// cdxgen v13 emits `command` for spawns and a split `protocol`/`host`/`pathname`
/// for HTTP rather than a single `url`. The `cmd` and `url` aliases keep older
/// cdxgen releases working against this build.
#[derive(Debug, Clone, Deserialize)]
pub struct TraceEvent {
    #[serde(rename = "type")]
    pub event_type: Option<String>,

    #[serde(alias = "cmd")]
    pub command: Option<String>,
    pub url: Option<String>,
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub pathname: Option<String>,

    // Phase records: the live-region model cdxgen renders on a terminal.
    pub phase: Option<String>,
    pub state: Option<String>,
    pub detail: Option<String>,
    pub note: Option<String>,
    pub done: Option<u64>,
    pub total: Option<u64>,
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: Option<u64>,

    // Activity records: the secure-mode ledger.
    pub kind: Option<String>,
    pub status: Option<String>,
    pub target: Option<String>,
}

impl TraceEvent {
    /// Reconstruct a displayable URL from whichever fields the producer sent.
    fn display_url(&self) -> Option<String> {
        if let Some(url) = self.url.as_deref() {
            return Some(url.to_string());
        }
        let host = self.host.as_deref()?;
        let scheme = self
            .protocol
            .as_deref()
            .map_or("https", |p| p.trim_end_matches(':'));
        let path = self.pathname.as_deref().unwrap_or("");
        Some(format!("{}://{}{}", scheme, host, path))
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseState {
    Running,
    Succeeded,
    Failed,
    Skipped,
}

impl PhaseState {
    fn parse(state: &str) -> Self {
        match state {
            "succeeded" => PhaseState::Succeeded,
            "failed" => PhaseState::Failed,
            "skipped" => PhaseState::Skipped,
            _ => PhaseState::Running,
        }
    }

    pub fn is_running(self) -> bool {
        matches!(self, PhaseState::Running)
    }

    /// Glyph mirroring the one cdxgen commits to its own terminal output.
    pub fn glyph(self) -> &'static str {
        match self {
            PhaseState::Running => "•",
            PhaseState::Succeeded => "✔",
            PhaseState::Failed => "✖",
            PhaseState::Skipped => "→",
        }
    }
}

/// A cdxgen phase, tracked from `started` through to its terminal state.
#[derive(Debug, Clone)]
pub struct Phase {
    pub name: String,
    pub state: PhaseState,
    pub detail: Option<String>,
    pub note: Option<String>,
    pub done: u64,
    pub total: u64,
    pub elapsed_ms: u64,
}

impl Phase {
    /// Fractional completion, when the phase reports a determinate total.
    pub fn ratio(&self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        Some((self.done as f64 / self.total as f64).clamp(0.0, 1.0))
    }
}

#[derive(Debug, Clone)]
pub struct TraceState {
    pub current_activity: Activity,
    pub activity_label: String,
    pub frame: u64,
    pub command_count: usize,
    pub http_count: usize,
    pub file_count: usize,
    /// Phases in the order cdxgen started them.
    pub phases: Vec<Phase>,
}

impl Default for TraceState {
    fn default() -> Self {
        Self::new()
    }
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
            phases: Vec::new(),
        }
    }

    pub fn process_line(&mut self, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        let Ok(event) = serde_json::from_str::<TraceEvent>(line.trim()) else {
            return;
        };
        let event_type = event.event_type.as_deref().unwrap_or("");

        match event_type {
            "phase" => self.apply_phase(&event),
            "http" | "fetch" | "download" => {
                self.current_activity = Activity::Http;
                self.http_count += 1;
                self.activity_label = match event.display_url() {
                    Some(url) => format!("🌐 {}", truncate(&url, 50)),
                    None => "🌐 HTTP".to_string(),
                };
            }
            "command" | "spawn" | "exec" | "cargo" => {
                self.current_activity = Activity::Command;
                self.command_count += 1;
                self.activity_label = match event.command.as_deref() {
                    Some(c) => {
                        let name = c.split_whitespace().next().unwrap_or(c);
                        format!("⚙ {}", truncate(name, 30))
                    }
                    None => "⚙ exec".to_string(),
                };
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
            "activity" => self.apply_activity(&event),
            _ => {}
        }
    }

    /// Fold a phase record into the phase list, updating the entry in place so
    /// a phase reporting progress does not accumulate one row per update.
    fn apply_phase(&mut self, event: &TraceEvent) {
        let Some(name) = event.phase.as_deref() else {
            return;
        };
        let state = PhaseState::parse(event.state.as_deref().unwrap_or("started"));
        let position = self.phases.iter().position(|p| p.name == name);
        let phase = match position {
            Some(index) => &mut self.phases[index],
            None => {
                self.phases.push(Phase {
                    name: name.to_string(),
                    state,
                    detail: None,
                    note: None,
                    done: 0,
                    total: 0,
                    elapsed_ms: 0,
                });
                self.phases.last_mut().expect("row was just pushed")
            }
        };
        phase.state = state;
        phase.done = event.done.unwrap_or(phase.done);
        phase.total = event.total.unwrap_or(phase.total);
        phase.elapsed_ms = event.elapsed_ms.unwrap_or(phase.elapsed_ms);
        if event.detail.is_some() {
            phase.detail = event.detail.clone();
        }
        if event.note.is_some() {
            phase.note = event.note.clone();
        }

        if state.is_running() {
            self.activity_label = match phase.detail.as_deref() {
                Some(detail) => format!("{} — {}", name, truncate(detail, 40)),
                None => name.to_string(),
            };
        }
    }

    /// Surface a blocked or failed secure-mode activity. Completed ones are
    /// routine and would only flicker the status bar.
    fn apply_activity(&mut self, event: &TraceEvent) {
        let status = event.status.as_deref().unwrap_or("");
        if !matches!(status, "blocked" | "denied" | "failed") {
            return;
        }
        let kind = event.kind.as_deref().unwrap_or("activity");
        if kind == "network" {
            self.current_activity = Activity::Network;
        }
        self.activity_label = match event.target.as_deref() {
            Some(target) => format!("⛔ {} {}", kind, truncate(target, 40)),
            None => format!("⛔ {} {}", kind, status),
        };
    }

    /// The phase currently running, if any.
    pub fn active_phase(&self) -> Option<&Phase> {
        self.phases.iter().find(|p| p.state.is_running())
    }

    pub fn tick(&mut self) {
        self.frame += 1;
        // Only decay to idle while no phase is running: a long phase that emits
        // no other events is still active, and blanking its label would
        // misreport cdxgen as doing nothing.
        if self.frame.is_multiple_of(120) && self.active_phase().is_none() {
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

/// Truncate on a character boundary. Slicing by byte offset would panic on the
/// non-ASCII paths and package names that appear in real scans.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_http_v13_fields() {
        let mut ts = TraceState::new();
        ts.process_line(
            r#"{"type":"http","protocol":"https:","host":"registry.npmjs.org","pathname":"/express"}"#,
        );
        assert_eq!(ts.current_activity, Activity::Http);
        assert_eq!(ts.http_count, 1);
        assert!(ts.activity_label.contains("registry.npmjs.org/express"));
    }

    #[test]
    fn test_trace_http_legacy_url() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"http","url":"https://example.com/a"}"#);
        assert!(ts.activity_label.contains("example.com/a"));
    }

    #[test]
    fn test_trace_command_v13_field() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"spawn","command":"npm install","cwd":"/tmp"}"#);
        assert_eq!(ts.current_activity, Activity::Command);
        assert_eq!(ts.command_count, 1);
        assert!(ts.activity_label.contains("npm"));
    }

    #[test]
    fn test_trace_command_legacy_cmd() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"command","cmd":"pip install requests"}"#);
        assert!(ts.activity_label.contains("pip"));
    }

    #[test]
    fn test_phase_lifecycle_updates_in_place() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"phase","phase":"Generating BOM","state":"started"}"#);
        assert_eq!(ts.phases.len(), 1);
        assert!(ts.active_phase().is_some());

        ts.process_line(
            r#"{"type":"phase","phase":"Generating BOM","state":"progress","done":3,"total":10}"#,
        );
        assert_eq!(ts.phases.len(), 1);
        assert_eq!(ts.phases[0].ratio(), Some(0.3));

        ts.process_line(
            r#"{"type":"phase","phase":"Generating BOM","state":"succeeded","note":"5770 components","elapsedMs":3013}"#,
        );
        assert_eq!(ts.phases.len(), 1);
        assert_eq!(ts.phases[0].state, PhaseState::Succeeded);
        assert_eq!(ts.phases[0].note.as_deref(), Some("5770 components"));
        assert_eq!(ts.phases[0].elapsed_ms, 3013);
        assert!(ts.active_phase().is_none());
    }

    #[test]
    fn test_phases_keep_start_order() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"phase","phase":"Preparing environment","state":"started"}"#);
        ts.process_line(r#"{"type":"phase","phase":"Preparing environment","state":"succeeded"}"#);
        ts.process_line(r#"{"type":"phase","phase":"Generating BOM","state":"started"}"#);
        let names: Vec<&str> = ts.phases.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["Preparing environment", "Generating BOM"]);
    }

    #[test]
    fn test_activity_blocked_is_surfaced() {
        let mut ts = TraceState::new();
        ts.process_line(
            r#"{"type":"activity","kind":"network","status":"blocked","target":"https://evil.test/"}"#,
        );
        assert!(ts.activity_label.contains("⛔"));
        assert_eq!(ts.current_activity, Activity::Network);
    }

    #[test]
    fn test_activity_completed_is_ignored() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"activity","kind":"network","status":"completed"}"#);
        assert!(ts.activity_label.is_empty());
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
    fn test_tick_keeps_running_phase() {
        let mut ts = TraceState::new();
        ts.process_line(r#"{"type":"phase","phase":"Generating BOM","state":"started"}"#);
        for _ in 0..240 {
            ts.tick();
        }
        assert_eq!(ts.activity_label, "Generating BOM");
    }

    #[test]
    fn test_truncate_multibyte() {
        assert_eq!(truncate("ünïcödé", 100), "ünïcödé");
        assert!(truncate("ünïcödé", 4).chars().count() <= 4);
    }

    #[test]
    fn test_spinner_cycles() {
        let mut ts = TraceState::new();
        assert_eq!(ts.spinner(), "⠋");
        ts.tick();
        assert_eq!(ts.spinner(), "⠙");
    }
}
