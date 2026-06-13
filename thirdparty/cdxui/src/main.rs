mod app;
mod args;
mod bom;
mod ui;

use crate::app::{App, InputMode, Tab};
use crate::args::Args;
use crate::bom::store::BomStore;
use crate::ui::theme::Theme;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::{Backend, CrosstermBackend};
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if !args.path.exists() {
        eprintln!("Error: path '{}' does not exist", args.path.display());
        std::process::exit(1);
    }

    let mut store = BomStore::new();
    match store.load_path(&args.path) {
        Ok(count) => {
            eprintln!("Loaded {} BOM file(s) from {}", count, args.path.display());
        }
        Err(e) => {
            eprintln!("Error loading BOM: {}", e);
            std::process::exit(1);
        }
    }

    let theme = match args.theme.as_str() {
        "light" => Theme::light(),
        _ => Theme::dark(),
    };

    let mut app = App::new(store, vec![args.path.clone()]);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app, &theme);

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
    theme: &Theme,
) -> io::Result<()> {
    let page_size = 20usize;
    loop {
        terminal.draw(|frame| ui::render(frame, app, theme))?;

        if app.should_quit {
            return Ok(());
        }

        if !event::poll(std::time::Duration::from_millis(8))? {
            continue;
        }

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                handle_key_event(app, key.code, page_size);
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

fn handle_key_event(app: &mut App, code: KeyCode, page_size: usize) {
    match app.input_mode {
        InputMode::Normal => match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,

            KeyCode::Esc => app.clear_search(),

            KeyCode::Char('/') => app.set_search(),

            KeyCode::Tab => {
                let next = app.current_tab.next();
                app.switch_tab(next);
            }
            KeyCode::BackTab => {
                let prev = app.current_tab.prev();
                app.switch_tab(prev);
            }

            KeyCode::Char('1') => app.switch_tab(Tab::Summary),
            KeyCode::Char('2') => app.switch_tab(Tab::Components),
            KeyCode::Char('3') => app.switch_tab(Tab::Crypto),
            KeyCode::Char('4') => app.switch_tab(Tab::Services),
            KeyCode::Char('5') => app.switch_tab(Tab::Formulation),
            KeyCode::Char('6') => app.switch_tab(Tab::Dependencies),

            KeyCode::Up | KeyCode::Char('k') => {
                app.move_selection_up();
                scroll_to_selection(app, 15);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.move_selection_down();
                scroll_to_selection(app, 15);
            }

            KeyCode::Char(' ') | KeyCode::PageDown => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    app.toggle_dep_expand();
                    app.last_item_count = 0;
                } else {
                    for _ in 0..page_size { app.move_selection_down(); }
                    scroll_to_selection(app, 15);
                }
            }
            KeyCode::Char('b') | KeyCode::PageUp => {
                for _ in 0..page_size { app.move_selection_up(); }
                scroll_to_selection(app, 15);
            }

            KeyCode::Home | KeyCode::Char('g') => {
                app.table_selected = 0;
                app.scroll_offset = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                let len = app.current_list_len();
                if len > 0 {
                    app.table_selected = len.saturating_sub(1);
                    app.scroll_offset = app.table_selected.saturating_sub(14) as u16;
                }
            }

            KeyCode::Enter => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    app.toggle_dep_expand();
                    app.last_item_count = 0;
                } else {
                    app.toggle_detail();
                    app.detail_scroll = 0;
                }
            }
            KeyCode::Right => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    let r = get_selected_ref(app);
                    if !app.dep_expanded.contains(&r) {
                        app.dep_expanded.insert(r);
                        app.last_item_count = 0;
                    }
                }
            }
            KeyCode::Left => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    let r = get_selected_ref(app);
                    app.dep_expanded.remove(&r);
                    app.last_item_count = 0;
                }
            }
            KeyCode::Char('s') => app.cycle_sort(),
            KeyCode::Char('h') => app.show_help = !app.show_help,
            KeyCode::Char('f') => app.enter_type_filter(),
            KeyCode::Char('+') | KeyCode::Char('=') => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    app.expand_all_deps();
                    app.last_item_count = 0;
                }
            }
            KeyCode::Char('-') | KeyCode::Char('_') => {
                if matches!(app.current_tab, Tab::Dependencies | Tab::Summary) {
                    app.collapse_all_deps();
                    app.last_item_count = 0;
                }
            }
            _ => {}
        },

        InputMode::Search => match code {
            KeyCode::Esc => app.clear_search(),
            KeyCode::Enter => {
                app.apply_search();
                app.input_mode = InputMode::Normal;
            }
            KeyCode::Char(c) => {
                app.search_input.push(c);
                app.apply_search();
            }
            KeyCode::Backspace => {
                app.search_input.pop();
                app.apply_search();
            }
            _ => {}
        },

        InputMode::TypeFilter => match code {
            KeyCode::Esc => app.exit_type_filter(false),
            KeyCode::Enter => app.exit_type_filter(true),
            KeyCode::Up | KeyCode::Char('k') => {
                let types = app.store.component_type_counts();
                if app.type_filter_selected > 0 {
                    app.type_filter_selected -= 1;
                } else if !types.is_empty() {
                    app.type_filter_selected = types.len().saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let types = app.store.component_type_counts();
                if !types.is_empty() && app.type_filter_selected + 1 < types.len() {
                    app.type_filter_selected += 1;
                } else {
                    app.type_filter_selected = 0;
                }
            }
            _ => {}
        },
    }
}

fn scroll_to_selection(app: &mut App, visible: u16) {
    let sel = app.table_selected as u16;
    let visible = visible.max(1);
    if sel < app.scroll_offset {
        app.scroll_offset = sel;
    } else if sel >= app.scroll_offset.saturating_add(visible) {
        app.scroll_offset = sel.saturating_sub(visible.saturating_sub(1));
    }
}

fn get_selected_ref(app: &App) -> String {
    let store = &app.store;
    let all = store.all_dependencies();
    if let Some(d) = all.get(app.table_selected) {
        return d.ref_field.clone();
    }
    let roots = store.dependency_roots();
    if let Some(r) = roots.get(app.table_selected) {
        return r.clone();
    }
    String::new()
}
