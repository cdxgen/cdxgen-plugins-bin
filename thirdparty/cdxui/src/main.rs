mod app;
mod args;
mod bom;
mod logs;
mod process;
mod trace;
mod ui;

use crate::app::{App, InputMode, Tab};
use crate::args::{Args, parse_cdxgen_args};
use crate::bom::store::BomStore;
use crate::logs::LogStore;
use crate::process::ProcessHandle;
use crate::trace::TraceState;
use crate::ui::theme::Theme;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::{Backend, CrosstermBackend};
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let theme = match args.theme.as_str() {
        "light" => Theme::light(),
        _ => Theme::dark(),
    };

    let mut store = BomStore::new();
    let mut log_store = LogStore::new(50000);
    let mut process: Option<ProcessHandle> = None;
    let mut saved_output_path: Option<std::path::PathBuf> = None;
    let mut app;
    let mut start_tab = Tab::Summary;
    let thought_log_path = format!("/tmp/cdxui-thought-{}.log", std::process::id());
    let trace_log_path = format!("/tmp/cdxui-trace-{}.jsonl", std::process::id());

    if args.generate {
        let cdxgen_cmd = std::env::var("CDXGEN_CMD").unwrap_or_else(|_| "cdxgen".to_string());
        let parts: Vec<&str> = cdxgen_cmd.split_whitespace().collect();
        let (cmd, pre_args) = parts.split_first().map(|(c, rest)| (*c, rest)).unwrap_or(("cdxgen", &[][..]));

        let mut cdxgen_args: Vec<String> = pre_args.iter().map(|s| s.to_string()).collect();
        cdxgen_args.extend(parse_cdxgen_args());

        let bom_output = extract_output_path(&cdxgen_args).unwrap_or_else(|| args.output.to_string_lossy().to_string());

        if !cdxgen_args.iter().any(|a| a == "-o" || a == "--output") {
            cdxgen_args.push("-o".to_string());
            cdxgen_args.push(bom_output.clone());
        }

        eprintln!("Spawning: {} {}", cmd, cdxgen_args.join(" "));
        match ProcessHandle::spawn(cmd, &cdxgen_args, &thought_log_path, &trace_log_path) {
            Ok(ph) => {
                process = Some(ph);
                start_tab = Tab::Logs;
            }
            Err(e) => {
                eprintln!("Failed to spawn cdxgen: {}", e);
            }
        }

        // Store the output path for post-generation BOM loading
        let pb = std::path::PathBuf::from(&bom_output);
        saved_output_path = Some(pb);
    } else if let Some(ref path) = args.path {
        if !path.exists() {
            eprintln!("Error: path '{}' does not exist", path.display());
            std::process::exit(1);
        }
        match store.load_path(path) {
            Ok(count) => {
                eprintln!("Loaded {} BOM file(s) from {}", count, path.display());
            }
            Err(e) => {
                eprintln!("Error loading BOM: {}", e);
                std::process::exit(1);
            }
        }
    }

    let mut trace_state = TraceState::new();
    app = App::new(store, args.path.clone().into_iter().collect());
    app.generating = process.is_some();
    app.current_tab = start_tab;
    if let Some(out_path) = saved_output_path {
        app.output_path = Some(out_path);
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app, &mut log_store, &mut process, &mut trace_state, &theme);

    if let Some(mut proc) = process {
        proc.kill();
    }
    let _ = std::fs::remove_file(&thought_log_path);
    let _ = std::fs::remove_file(&trace_log_path);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

fn run_app<B: Backend>(
    terminal: &mut ratatui::Terminal<B>,
    app: &mut App,
    log_store: &mut LogStore,
    process: &mut Option<ProcessHandle>,
    trace_state: &mut TraceState,
    theme: &Theme,
) -> io::Result<()> {
    let page_size = 20usize;
    loop {
        drain_logs(app, log_store, process);
        drain_traces(trace_state, process);
        trace_state.tick();
        check_auto_switch(app, log_store);
        terminal.draw(|frame| ui::render(frame, app, log_store, trace_state, theme))?;

        if app.should_quit {
            return Ok(());
        }

        if !event::poll(std::time::Duration::from_millis(8))? {
            continue;
        }

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.scroll_offset > 0 { app.scroll_offset -= 1; }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.scroll_offset = app.scroll_offset.saturating_add(1);
                        }
                        _ => {}
                    }
                } else {
                    handle_key_event(app, key.code, page_size);
                }
            }
            Event::Mouse(mouse) => {
                handle_mouse_event(app, mouse);
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

fn drain_logs(app: &mut App, log_store: &mut LogStore, process: &mut Option<ProcessHandle>) {
    if let Some(ref mut proc) = process {
        while let Ok(entry) = proc.log_rx.try_recv() {
            log_store.push_line(&entry.text);
        }
        while let Ok(delta) = proc.thought_rx.try_recv() {
            app.thought_text.push_str(&delta);
        }
        if let Some(code) = proc.try_wait() {
            log_store.push_line(&format!("── Process exited with code {} ──", code));
            if let Some(full_thoughts) = proc.read_thought_log() {
                app.thought_text = full_thoughts;
            }
            app.generating = false;
            app.generation_done = true;
            app.switch_timer = Some(std::time::Instant::now());

            if let Some(ref out_path) = app.output_path {
                if out_path.exists() {
                    match app.store.load_path(out_path) {
                        Ok(count) => {
                            let msg = format!("Loaded {} BOM file(s) from {}", count, out_path.display());
                            log_store.push_line(&msg);
                        }
                        Err(e) => {
                            log_store.push_line(&format!("Error loading BOM: {}", e));
                        }
                    }
                }
            }
            process.take();
        }
    }
    app.last_item_count = log_store.len();
}

fn drain_traces(trace_state: &mut TraceState, process: &mut Option<ProcessHandle>) {
    if let Some(ref mut proc) = process {
        while let Ok(delta) = proc.trace_rx.try_recv() {
            for line in delta.lines() {
                trace_state.process_line(line);
            }
        }
    }
}

fn check_auto_switch(app: &mut App, _log_store: &LogStore) {
    if let Some(timer) = app.switch_timer {
        if timer.elapsed().as_secs() >= 2 {
            app.current_tab = Tab::Summary;
            app.switch_timer = None;
        }
    }
}

fn extract_output_path(args: &[String]) -> Option<String> {
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "-o" || args[i] == "--output" {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn handle_key_event(app: &mut App, code: KeyCode, page_size: usize) {
    match app.input_mode {
        InputMode::Normal => match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,

            KeyCode::Esc => app.clear_search(),
            KeyCode::Char('/') => app.set_search(),

            KeyCode::Tab => { let next = app.current_tab.next(); app.switch_tab(next); }
            KeyCode::BackTab => { let prev = app.current_tab.prev(); app.switch_tab(prev); }

            KeyCode::Char('0') => app.switch_tab(Tab::Logs),
            KeyCode::Char('1') => app.switch_tab(Tab::Summary),
            KeyCode::Char('2') => app.switch_tab(Tab::Components),
            KeyCode::Char('3') => app.switch_tab(Tab::Crypto),
            KeyCode::Char('4') => app.switch_tab(Tab::Services),
            KeyCode::Char('5') => app.switch_tab(Tab::Formulation),
            KeyCode::Char('6') => app.switch_tab(Tab::Dependencies),

            KeyCode::Up | KeyCode::Char('k') => { app.move_selection_up(); scroll_to_selection(app, 15); }
            KeyCode::Down | KeyCode::Char('j') => { app.move_selection_down(); scroll_to_selection(app, 15); }

            KeyCode::Char(' ') | KeyCode::PageDown => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    app.toggle_dep_expand(); app.last_item_count = 0;
                } else { for _ in 0..page_size { app.move_selection_down(); } scroll_to_selection(app, 15); }
            }
            KeyCode::Char('b') | KeyCode::PageUp => { for _ in 0..page_size { app.move_selection_up(); } scroll_to_selection(app, 15); }

            KeyCode::Home | KeyCode::Char('g') => { app.table_selected = 0; app.scroll_offset = 0; }
            KeyCode::End | KeyCode::Char('G') => {
                let len = app.current_list_len();
                if len > 0 { app.table_selected = len.saturating_sub(1); app.scroll_offset = app.table_selected.saturating_sub(14) as u16; }
            }

            KeyCode::Enter => {
                if app.current_tab == Tab::Dependencies {
                    app.toggle_detail();
                    app.detail_scroll = 0;
                } else if app.current_tab == Tab::Summary {
                    app.toggle_dep_expand();
                    app.last_item_count = 0;
                } else {
                    app.toggle_detail();
                    app.detail_scroll = 0;
                }
            }
            KeyCode::Right => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    let r = get_selected_ref(app); if !app.dep_expanded.contains(&r) { app.dep_expanded.insert(r); app.last_item_count = 0; }
                }
            }
            KeyCode::Left => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    let r = get_selected_ref(app); app.dep_expanded.remove(&r); app.last_item_count = 0;
                }
            }
            KeyCode::Char('s') => app.cycle_sort(),
            KeyCode::Char('h') => app.show_help = !app.show_help,
            KeyCode::Char('f') => app.enter_type_filter(),
            KeyCode::Char('+') | KeyCode::Char('=') => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) { app.expand_all_deps(); app.last_item_count = 0; }
            }
            KeyCode::Char('-') | KeyCode::Char('_') => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) { app.collapse_all_deps(); app.last_item_count = 0; }
            }
            _ => {}
        },

        InputMode::Search => match code {
            KeyCode::Esc => app.clear_search(),
            KeyCode::Enter => { app.apply_search(); app.input_mode = InputMode::Normal; }
            KeyCode::Char(c) => { app.search_input.push(c); app.apply_search(); }
            KeyCode::Backspace => { app.search_input.pop(); app.apply_search(); }
            _ => {}
        },

        InputMode::TypeFilter => match code {
            KeyCode::Esc => app.exit_type_filter(false),
            KeyCode::Enter => app.exit_type_filter(true),
            KeyCode::Up | KeyCode::Char('k') => {
                let types = app.store.component_type_counts();
                if app.type_filter_selected > 0 { app.type_filter_selected -= 1; }
                else if !types.is_empty() { app.type_filter_selected = types.len().saturating_sub(1); }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let types = app.store.component_type_counts();
                if !types.is_empty() && app.type_filter_selected + 1 < types.len() { app.type_filter_selected += 1; }
                else { app.type_filter_selected = 0; }
            }
            _ => {}
        },
    }
}

fn handle_mouse_event(app: &mut App, mouse: crossterm::event::MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => {
            if app.scroll_offset > 0 {
                app.scroll_offset = app.scroll_offset.saturating_sub(3);
            }
        }
        MouseEventKind::ScrollDown => {
            app.scroll_offset = app.scroll_offset.saturating_add(3);
        }
        _ => {}
    }
}

fn scroll_to_selection(app: &mut App, visible: u16) {
    let sel = app.table_selected as u16;
    let v = visible.max(1);
    if sel < app.scroll_offset { app.scroll_offset = sel; }
    else if sel >= app.scroll_offset.saturating_add(v) { app.scroll_offset = sel.saturating_sub(v.saturating_sub(1)); }
}

fn get_selected_ref(app: &App) -> String {
    app.dep_tree_refs.get(app.table_selected).cloned().unwrap_or_default()
}
