pub mod detail;
pub mod theme;

use crate::app::{App, InputMode, Tab};
use crate::bom::store::SortField;
use crate::bom::store::SortOrder;
use crate::bom::store::VulnSortField;
use crate::ui::theme::Theme;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, ListItem, Paragraph, Row, Table, TableState, Tabs, Wrap},
};

const SERVICE_COLUMNS: [&str; 5] = ["Name", "Endpoints", "Auth", "Description", "BOM Ref"];
const VULN_COLUMNS: [&str; 7] = ["⚑", "ID", "Severity", "CVSS", "Reach", "Package", "Fix"];
const VULN_HEADER_FIELDS: [VulnSortField; 7] = [
    VulnSortField::Priority,
    VulnSortField::Id,
    VulnSortField::Severity,
    VulnSortField::Score,
    VulnSortField::Reach,
    VulnSortField::Package,
    VulnSortField::Fix,
];

pub fn render(
    frame: &mut Frame,
    app: &mut App,
    log_store: &crate::logs::LogStore,
    trace_state: &crate::trace::TraceState,
    theme: &Theme,
) {
    let area = frame.area();
    app.panel_areas.clear();
    let tab_bg = theme.tab_bg[Theme::tab_index(app.current_tab)];

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    let tabs_area = main_layout[0];
    let search_area = main_layout[1];
    let content_area = main_layout[2];
    let status_area = main_layout[3];

    render_tabs(frame, app, theme, tabs_area);
    render_search_bar(frame, app, theme, search_area);

    if app.detail_open && !matches!(app.current_tab, Tab::Summary | Tab::Formulation | Tab::Logs) {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(content_area);
        render_main_content(frame, app, log_store, trace_state, theme, split[0], tab_bg);
        detail::render_detail_panel(frame, app, theme, split[1]);
    } else {
        render_main_content(
            frame,
            app,
            log_store,
            trace_state,
            theme,
            content_area,
            tab_bg,
        );
    }

    render_status_bar(frame, app, trace_state, theme, status_area);
}

fn render_tabs(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let mut titles: Vec<Line> = Vec::new();
    let mut x = area.x + 2; // border offset
    app.tab_positions.clear();

    for tab in &Tab::ALL {
        let label = app.tab_label(*tab);
        let display = format!(" {} ", label);
        let width = unicode_width::UnicodeWidthStr::width(display.as_str()) as u16;
        app.tab_positions.push((*tab, x, x + width));
        x += width + 1; // gap between tabs

        if *tab == app.current_tab {
            titles.push(Line::from(vec![Span::styled(
                display,
                theme.tab_active_style(),
            )]));
        } else {
            titles.push(Line::from(vec![Span::styled(
                display,
                theme.tab_inactive_style(),
            )]));
        }
    }

    let tabs = Tabs::new(titles)
        .block(Block::default().style(Style::default().bg(theme.bg)))
        .highlight_style(theme.tab_active_style())
        .select(
            Tab::ALL
                .iter()
                .position(|t| *t == app.current_tab)
                .unwrap_or(0),
        );

    frame.render_widget(tabs, area);
}

fn render_search_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let (text, style) = match app.input_mode {
        InputMode::Search => {
            let _cursor_pos = app.search_input.len();
            let display = if app.search_input.is_empty() {
                " ".to_string()
            } else {
                app.search_input.clone()
            };
            (
                format!("/{}", display),
                Style::default().fg(theme.accent).bg(theme.search_bg),
            )
        }
        InputMode::TypeFilter => {
            let types = app.store.component_type_counts();
            let type_str = types
                .get(app.type_filter_selected)
                .map(|(t, c)| format!("{} ({})", t, c))
                .unwrap_or_default();
            (
                format!("f: {}  (↑↓ select, Enter confirm, Esc cancel)", type_str),
                Style::default().fg(theme.crypto_accent).bg(theme.search_bg),
            )
        }
        InputMode::Normal => {
            if app.current_filter_active() {
                let type_info = app
                    .component_type_filter
                    .as_ref()
                    .map(|t| format!(" type: {}", t))
                    .unwrap_or_default();
                (
                    format!(
                        "search: \"{}\"{} ({} matches, / search, f type, Esc clear)",
                        app.search_input,
                        type_info,
                        app.current_list_len()
                    ),
                    Style::default().fg(theme.search_fg).bg(theme.search_bg),
                )
            } else {
                (
                    "/:search f:filter s:sort Enter:detail Tab:next q:quit".to_string(),
                    Style::default().fg(theme.status_fg).bg(theme.bg),
                )
            }
        }
    };

    let paragraph = Paragraph::new(text)
        .block(Block::default().style(Style::default().bg(style.bg.unwrap_or(theme.bg))))
        .style(style);
    frame.render_widget(paragraph, area);
}

fn render_main_content(
    frame: &mut Frame,
    app: &mut App,
    log_store: &crate::logs::LogStore,
    trace_state: &crate::trace::TraceState,
    theme: &Theme,
    area: Rect,
    tab_bg: ratatui::style::Color,
) {
    if !matches!(app.current_tab, Tab::Logs) {
        app.panel_areas.push((crate::app::PanelFocus::Main, area));
    }
    match app.current_tab {
        Tab::Logs => render_logs(frame, app, log_store, trace_state, theme, area, tab_bg),
        Tab::Summary => render_summary(frame, app, theme, area, tab_bg),
        Tab::Components => render_component_table(frame, app, theme, area, false, tab_bg),
        Tab::Crypto => render_component_table(frame, app, theme, area, true, tab_bg),
        Tab::Services => render_service_table(frame, app, theme, area, tab_bg),
        Tab::Formulation => render_formulation(frame, app, theme, area, tab_bg),
        Tab::Dependencies => render_dependencies(frame, app, theme, area, tab_bg),
        Tab::Vulnerabilities => render_vulnerabilities(frame, app, theme, area, tab_bg),
    }
}

fn render_logs(
    frame: &mut Frame,
    app: &mut App,
    log_store: &crate::logs::LogStore,
    trace_state: &crate::trace::TraceState,
    theme: &Theme,
    area: Rect,
    _tab_bg: ratatui::style::Color,
) {
    let in_gen = app.generating || app.generation_done;
    let has_thoughts = in_gen && !app.thought_text.is_empty();

    // The phase rows sit above everything else during a run: they are the
    // answer to "what is cdxgen doing right now".
    let area = if in_gen && !trace_state.phases.is_empty() {
        let height = (trace_state.phases.len() as u16 + 2).min(area.height.saturating_sub(3));
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(height), Constraint::Min(3)])
            .split(area);
        render_phases_panel(frame, trace_state, theme, split[0]);
        split[1]
    } else {
        area
    };

    let expanded = has_thoughts && !app.thoughts_collapsed;
    let collapsed = has_thoughts && app.thoughts_collapsed;

    let constraints: Vec<Constraint> = if expanded {
        vec![Constraint::Percentage(40), Constraint::Percentage(60)]
    } else if collapsed {
        vec![Constraint::Length(3), Constraint::Min(3)]
    } else {
        vec![Constraint::Percentage(100)]
    };

    let panels = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    app.panel_areas
        .retain(|(p, _)| *p != crate::app::PanelFocus::Main);

    if expanded || collapsed {
        app.panel_areas
            .push((crate::app::PanelFocus::Thoughts, panels[0]));
        app.panel_areas
            .push((crate::app::PanelFocus::Stdout, panels[1]));
        if collapsed {
            render_thoughts_collapsed(frame, app, theme, panels[0]);
        } else {
            render_thoughts_panel(frame, app, theme, panels[0]);
        }
        render_stdout_panel(frame, app, log_store, theme, panels[1]);
    } else {
        app.panel_areas
            .push((crate::app::PanelFocus::Stdout, panels[0]));
        render_stdout_panel(frame, app, log_store, theme, panels[0]);
    }
}

/// Render cdxgen's phase model: one row per phase, in start order, with a bar
/// for the phases that report a determinate total.
///
/// cdxgen suppresses its own live region when its output is a pipe, so these
/// rows are the progress display for a run driven by this UI.
fn render_phases_panel(
    frame: &mut Frame,
    trace_state: &crate::trace::TraceState,
    theme: &Theme,
    area: Rect,
) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let rows: Vec<Line> = trace_state
        .phases
        .iter()
        .map(|phase| {
            let (glyph, color) = match phase.state {
                crate::trace::PhaseState::Running => (trace_state.spinner(), theme.accent),
                crate::trace::PhaseState::Succeeded => (phase.state.glyph(), Color::Green),
                crate::trace::PhaseState::Failed => (phase.state.glyph(), theme.error),
                crate::trace::PhaseState::Skipped => (phase.state.glyph(), theme.warn),
            };

            let mut spans = vec![
                Span::styled(format!(" {} ", glyph), Style::default().fg(color)),
                Span::styled(phase.name.clone(), Style::default().fg(theme.fg)),
            ];

            if let Some(ratio) = phase.ratio() {
                let width = inner_width
                    .saturating_sub(phase.name.len() + 24)
                    .clamp(6, 20);
                let filled = (ratio * width as f64).round() as usize;
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    format!(
                        "{}{}",
                        "█".repeat(filled),
                        "░".repeat(width.saturating_sub(filled))
                    ),
                    Style::default().fg(theme.accent),
                ));
                spans.push(Span::styled(
                    format!(" {}/{}", phase.done, phase.total),
                    Style::default()
                        .fg(theme.status_fg)
                        .add_modifier(Modifier::DIM),
                ));
            }

            // A finished phase shows its outcome note; a running one shows the
            // detail cdxgen is currently reporting.
            let trailing = match phase.state {
                crate::trace::PhaseState::Running => phase.detail.as_deref(),
                _ => phase.note.as_deref(),
            };
            if let Some(text) = trailing {
                spans.push(Span::styled(
                    format!("  {}", truncate_str(text, 40)),
                    Style::default().fg(theme.crypto_accent),
                ));
            }
            if phase.elapsed_ms > 0 && !phase.state.is_running() {
                spans.push(Span::styled(
                    format!("  {:.1}s", phase.elapsed_ms as f64 / 1000.0),
                    Style::default()
                        .fg(theme.status_fg)
                        .add_modifier(Modifier::DIM),
                ));
            }
            Line::from(spans)
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Progress ")
        .border_style(Style::default().fg(theme.accent));

    frame.render_widget(Paragraph::new(Text::from(rows)).block(block), area);
}

fn render_thoughts_panel(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let text = &app.thought_text;

    let lines: Vec<Line> = text
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            let stripped = trimmed
                .replace("<think>", "")
                .replace("</think>", "")
                .replace("<think", "")
                .trim()
                .to_string();
            if stripped.is_empty() {
                Line::from("")
            } else {
                let style = if trimmed.starts_with("<think") || trimmed.ends_with("</think>") {
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.crypto_accent)
                };
                Line::from(vec![Span::styled(
                    if stripped.len() > area.width.saturating_sub(4) as usize {
                        format!("{}…", &stripped[..area.width.saturating_sub(7) as usize])
                    } else {
                        stripped
                    },
                    style,
                )])
            }
        })
        .collect();

    let title = if app.generating {
        " 💭 Thoughts (live) "
    } else {
        " 💭 Thoughts "
    };
    let p = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .scroll((app.thought_scroll, 0));
    frame.render_widget(p, area);
}

fn render_thoughts_collapsed(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let line_count = app.thought_text.lines().count();
    let title = format!(" 💭 Thoughts ({} lines, collapsed) ", line_count);
    let hint = if area.width > 40 {
        " [click to expand] "
    } else {
        ""
    };
    let content = format!("{}{}", title, hint);
    let p = Paragraph::new(Line::from(vec![Span::styled(
        content,
        Style::default()
            .fg(theme.crypto_accent)
            .add_modifier(Modifier::DIM),
    )]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default().bg(theme.bg)),
    );
    frame.render_widget(p, area);
}

fn render_stdout_panel(
    frame: &mut Frame,
    app: &mut App,
    log_store: &crate::logs::LogStore,
    theme: &Theme,
    area: Rect,
) {
    let entries = log_store.entries();

    let mut items: Vec<ListItem> = Vec::new();
    for entry in entries.iter() {
        let level_style = match entry.level {
            crate::logs::LogLevel::Error => Style::default().fg(theme.error),
            crate::logs::LogLevel::Warn => Style::default().fg(theme.warn),
            _ => Style::default().fg(theme.fg),
        };
        let icon = match entry.level {
            crate::logs::LogLevel::Error => "✗",
            crate::logs::LogLevel::Warn => "⚠",
            _ => " ",
        };
        let text = entry.text.clone();
        items.push(ListItem::new(Line::from(vec![Span::styled(
            format!(" {} {}", icon, text),
            level_style,
        )])));
    }

    app.log_item_count = items.len();
    let total = items.len();
    let title = if app.generating {
        format!(" Stdout ({} lines, generating…) ", total)
    } else {
        format!(" Stdout ({} lines) ", total)
    };

    let visible = area.height.saturating_sub(3) as usize;
    app.visible_rows = area.height.saturating_sub(3);
    let start = (app.stdout_scroll as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .highlight_style(theme.selected_style());
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_summary(
    frame: &mut Frame,
    app: &mut App,
    theme: &Theme,
    area: Rect,
    _tab_bg: ratatui::style::Color,
) {
    let store = &app.store;

    let annotations: Vec<&crate::bom::schema::Annotation> = store
        .bom_files
        .iter()
        .filter_map(|bf| bf.bom.annotations.as_ref())
        .flatten()
        .collect();

    let has_annotations = !annotations.is_empty();
    let has_vulns = store.total_vulnerabilities > 0;

    let constraints: Vec<Constraint> = {
        let mut c = vec![];
        if has_annotations {
            c.push(Constraint::Length(5));
        }
        c.push(Constraint::Length(3)); // stats bar
        c.push(Constraint::Length(10)); // types + licenses
        if has_vulns {
            c.push(Constraint::Length(3)); // prioritized callout
            c.push(Constraint::Min(16)); // security dashboard grid
        }
        c.push(Constraint::Min(10)); // dep tree
        c.push(Constraint::Min(6)); // metadata
        c
    };

    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    let mut idx = 0;

    if has_annotations {
        render_annotation_text(frame, &annotations, theme, vert[idx]);
        idx += 1;
    }

    render_stats_bar(frame, app, theme, vert[idx]);
    idx += 1;

    let mid = vert[idx];
    idx += 1;
    let mid_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(mid);
    render_license_chart(frame, app, theme, mid_split[0]);
    render_type_breakdown(frame, app, theme, mid_split[1]);

    if has_vulns {
        render_security_callout(frame, app, theme, vert[idx]);
        idx += 1;
        render_security_dashboard(frame, app, theme, vert[idx]);
        idx += 1;
    }

    render_mini_dep_tree(frame, app, theme, vert[idx]);
    idx += 1;

    render_metadata_panel(frame, app, theme, vert[idx]);
}

fn render_annotation_text(
    frame: &mut Frame,
    annotations: &[&crate::bom::schema::Annotation],
    theme: &Theme,
    area: Rect,
) {
    let text = annotations
        .first()
        .and_then(|a| a.text.as_deref())
        .unwrap_or_default();
    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Annotations ({}) ", annotations.len()))
                .style(Style::default().bg(theme.bg)),
        )
        .style(Style::default().fg(theme.warn))
        .wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn render_license_chart(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for row in &store.components {
        let lic = row.license_display();
        if lic != "-" {
            *counts.entry(lic).or_insert(0) += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top = sorted.iter().take(8).collect::<Vec<_>>();
    let max = top.first().map(|(_, c)| *c).unwrap_or(1).max(1);

    let header = Row::new(
        ["License", "Count", "Distribution"]
            .iter()
            .map(|c| Cell::from(Span::styled(*c, theme.header_style()))),
    );

    let rows: Vec<Row> = top
        .iter()
        .enumerate()
        .map(|(i, (lic, count))| {
            let bar_len = (*count * 20 / max).max(1);
            let bar = "█".repeat(bar_len);
            let is_alt = i % 2 == 1;
            let s = if is_alt {
                Style::default()
                    .fg(theme.table_row_fg)
                    .bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };
            Row::new(vec![
                Cell::from(Span::styled(lic.clone(), s)),
                Cell::from(Span::styled(format!("{}", count), s)),
                Cell::from(Span::styled(
                    format!("{} {}", bar, count),
                    s.fg(theme.accent),
                )),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(55),
            Constraint::Percentage(12),
            Constraint::Percentage(33),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" License Distribution ({} unique) ", sorted.len()))
            .style(Style::default().bg(theme.bg)),
    )
    .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_mini_dep_tree(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    app.dep_tree_area = Some(area);
    let store = &app.store;
    let roots = store.dependency_roots();
    let mut items: Vec<ListItem> = Vec::new();
    app.dep_tree_refs.clear();

    if roots.is_empty() {
        let all = store.all_dependencies();
        if all.is_empty() {
            items.push(ListItem::new(Line::from(vec![Span::styled(
                "No dependencies",
                Style::default().fg(theme.warn),
            )])));
            app.dep_tree_refs.push(String::new());
        } else {
            for d in all.iter().take(15) {
                let name = store.resolve_bom_ref(&d.ref_field);
                let has_children = d.depends_on.as_ref().is_some_and(|c| !c.is_empty());
                let is_expanded = app.dep_expanded.contains(&d.ref_field);
                let icon = if has_children {
                    if is_expanded { "▾" } else { "▸" }
                } else {
                    " "
                };
                items.push(ListItem::new(Line::from(vec![Span::styled(
                    format!("{} {}", icon, name),
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                )])));
                app.dep_tree_refs.push(d.ref_field.clone());
                if is_expanded && let Some(ref children) = d.depends_on {
                    for child in children {
                        let cname = store.resolve_bom_ref(child);
                        items.push(ListItem::new(format!("  └── {}", cname)));
                        app.dep_tree_refs.push(child.clone());
                    }
                }
            }
        }
    } else {
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let ctx = DepCtx {
            store,
            theme,
            expanded: &app.dep_expanded,
        };
        for root in &roots {
            build_dep_list(
                &mut items,
                &mut app.dep_tree_refs,
                &ctx,
                root,
                "",
                &mut visited,
            );
        }
    }

    let total = items.len();
    app.mini_dep_tree_count = total;
    let title = format!(" Dependency Roots ({}, {} visible) ", roots.len(), total);

    let visible = area.height.saturating_sub(3) as usize;
    app.visible_rows = area.height.saturating_sub(3);
    let start = (app.scroll_offset as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .highlight_style(theme.selected_style());
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_type_breakdown(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let type_counts = store.component_type_counts();
    let max_rows = 5usize;
    let shown = type_counts.iter().take(max_rows);
    let remaining = type_counts.len().saturating_sub(max_rows);

    let header = Row::new(
        ["Component Type", "Count"]
            .iter()
            .map(|c| Cell::from(Span::styled(*c, theme.header_style()))),
    );

    let mut rows: Vec<Row> = shown
        .enumerate()
        .map(|(i, (ct, count))| {
            let is_alt = i % 2 == 1;
            let s = if is_alt {
                Style::default()
                    .fg(theme.table_row_fg)
                    .bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };
            let type_s = if ct == "cryptographic-asset" {
                s.fg(theme.crypto_accent)
            } else {
                s
            };
            Row::new(vec![
                Cell::from(Span::styled(ct.clone(), type_s)),
                Cell::from(Span::styled(
                    format!("{}", count),
                    s.add_modifier(Modifier::BOLD),
                )),
            ])
        })
        .collect();

    if remaining > 0 {
        rows.push(Row::new(vec![
            Cell::from(Span::styled(
                format!("… +{} more", remaining),
                Style::default().fg(theme.warn),
            )),
            Cell::from(Span::raw("")),
        ]));
    }

    let table = Table::new(
        rows,
        [Constraint::Percentage(70), Constraint::Percentage(30)],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Component Types ({}) ",
                store
                    .component_type_counts()
                    .iter()
                    .map(|(_, c)| c)
                    .sum::<usize>()
            ))
            .style(Style::default().bg(theme.bg)),
    )
    .column_spacing(2);
    frame.render_widget(table, area);
}

// ---------------------------------------------------------------------------
// Security dashboard (Summary tab) — reads ONLY from store.security_summary.
// ---------------------------------------------------------------------------

fn render_security_callout(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let s = &app.store.security_summary;
    let pct = (s.vulnerable_components * 100)
        .checked_div(s.total_components)
        .unwrap_or(0);
    let spans = vec![
        Span::styled(
            format!(" ⚑ {} prioritized ", s.prioritized_vulns),
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "·",
            Style::default()
                .fg(theme.detail_fg)
                .add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!(" ⚡ {} reachable ", s.reachable_vulns),
            Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "·",
            Style::default()
                .fg(theme.detail_fg)
                .add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!(" 🔥 {} exploitable ", s.exploitable_vulns),
            Style::default()
                .fg(Color::Rgb(255, 120, 80))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "·",
            Style::default()
                .fg(theme.detail_fg)
                .add_modifier(Modifier::DIM),
        ),
        Span::styled(
            format!(
                " {} vulns across {} of {} components ({}%) ",
                s.total_vulns, s.vulnerable_components, s.total_components, pct
            ),
            Style::default().fg(theme.accent),
        ),
    ];
    let p = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Security Posture ")
            .style(Style::default().bg(theme.bg)),
    );
    frame.render_widget(p, area);
}

fn render_security_dashboard(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // exposure gauge
            Constraint::Length(8), // severity distribution
            Constraint::Min(7),    // reachability breakdown
        ])
        .split(cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(9), // top by count
            Constraint::Min(8), // top by reach/exploit
        ])
        .split(cols[1]);

    render_exposure_gauge(frame, app, theme, left[0]);
    render_severity_distribution(frame, app, theme, left[1]);
    render_reachability_breakdown(frame, app, theme, left[2]);
    render_top_packages_by_count(frame, app, theme, right[0]);
    render_top_packages_by_reach(frame, app, theme, right[1]);
}

fn render_exposure_gauge(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let s = &app.store.security_summary;
    let total = s.total_components.max(1);
    let vuln = s.vulnerable_components.min(total);
    let safe = total - vuln;
    let pct = vuln * 100 / total;

    let bar_width = area.width.saturating_sub(4) as usize;
    let mut vuln_len = vuln * bar_width / total;
    if vuln > 0 && vuln_len == 0 {
        vuln_len = 1;
    }
    if vuln_len > bar_width {
        vuln_len = bar_width;
    }
    let safe_len = bar_width.saturating_sub(vuln_len);

    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(" ", Style::default().bg(theme.bg)));
    if vuln_len > 0 {
        spans.push(Span::styled(
            "█".repeat(vuln_len),
            Style::default().fg(theme.error).bg(theme.bg),
        ));
    }
    if safe_len > 0 {
        spans.push(Span::styled(
            "█".repeat(safe_len),
            Style::default().fg(Color::Rgb(90, 160, 90)).bg(theme.bg),
        ));
    }

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(spans));
    lines.push(Line::from(vec![
        Span::styled(
            format!("  {} vulnerable", vuln),
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("   {} unaffected", safe),
            Style::default().fg(Color::Rgb(90, 160, 90)),
        ),
        Span::styled(
            format!("   {}% affected", pct),
            Style::default().fg(theme.accent),
        ),
    ]));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Component Exposure ")
            .style(Style::default().bg(theme.bg)),
    );
    frame.render_widget(p, area);
}

fn render_severity_distribution(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let s = &app.store.security_summary;
    // Ordered, label-paired counts (highest severity first) come from the
    // store so the mapping is testable and cannot invert.
    let rows_data: Vec<(String, usize, Color)> = s
        .severity_display()
        .iter()
        .map(|(l, c)| (l.to_string(), *c, theme.severity_color(l)))
        .collect();
    render_bar_list(
        frame,
        " Severity Distribution ",
        &rows_data,
        area,
        theme,
        true,
    );
}

fn render_reachability_breakdown(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let s = &app.store.security_summary;
    let any_reach = s.reachable_vulns;
    let not_reachable = s.total_vulns.saturating_sub(any_reach);
    let rows_data: Vec<(String, usize, Color)> = vec![
        (
            "⚡ Reachable".to_string(),
            s.reachable_vulns.saturating_sub(s.endpoint_reachable_vulns),
            theme.warn,
        ),
        (
            "→ Endpoint".to_string(),
            s.endpoint_reachable_vulns,
            theme.crypto_accent,
        ),
        (
            "🔥 Reach+Exploit".to_string(),
            s.reachable_exploitable_vulns,
            theme.error,
        ),
        (
            "○ Not reachable".to_string(),
            not_reachable,
            Color::Rgb(120, 120, 120),
        ),
    ];
    render_bar_list(
        frame,
        " Reachability Breakdown ",
        &rows_data,
        area,
        theme,
        true,
    );
}

fn render_top_packages_by_count(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let s = &app.store.security_summary;
    let rows_data: Vec<(String, usize, Color)> = s
        .top_by_count
        .iter()
        .map(|(name, sum)| {
            let col = theme.severity_color_for_rank(sum.max_severity_rank);
            (name.clone(), sum.count, col)
        })
        .collect();
    let title = format!(" Top Packages by CVE Count ({}) ", s.top_by_count.len());
    render_bar_list(frame, &title, &rows_data, area, theme, true);
}

fn render_top_packages_by_reach(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let s = &app.store.security_summary;
    let rows_data: Vec<(String, usize, Color)> = s
        .top_by_reach_exploit
        .iter()
        .map(|(name, sum)| {
            let col = if sum.exploitable {
                theme.error
            } else {
                theme.warn
            };
            (name.clone(), sum.count, col)
        })
        .collect();
    let title = if s.top_by_reach_exploit.is_empty() {
        " Top Reachable/Exploitable Packages ".to_string()
    } else {
        " ⚡ Fix These First (reachable/exploitable) ".to_string()
    };
    if rows_data.is_empty() {
        let p = Paragraph::new("No reachable/exploitable vulnerabilities")
            .style(Style::default().fg(theme.warn).add_modifier(Modifier::DIM))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .style(Style::default().bg(theme.bg)),
            );
        frame.render_widget(p, area);
        return;
    }
    render_bar_list(frame, &title, &rows_data, area, theme, true);
}

/// Generic horizontal bar list: label | proportional bar | count.
fn render_bar_list(
    frame: &mut Frame,
    title: &str,
    rows_data: &[(String, usize, Color)],
    area: Rect,
    theme: &Theme,
    _show_bar: bool,
) {
    let max = rows_data
        .iter()
        .map(|(_, c, _)| *c)
        .max()
        .unwrap_or(1)
        .max(1);
    let header = Row::new(
        ["Package", "Bar", "Count"]
            .iter()
            .map(|c| Cell::from(Span::styled(*c, theme.header_style()))),
    );

    let rows: Vec<Row> = rows_data
        .iter()
        .enumerate()
        .map(|(i, (label, count, color))| {
            let bar_len = (*count * 16 / max).max(if *count > 0 { 1 } else { 0 });
            let bar = "█".repeat(bar_len);
            let is_alt = i % 2 == 1;
            let s = if is_alt {
                Style::default()
                    .fg(theme.table_row_fg)
                    .bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };
            Row::new(vec![
                Cell::from(Span::styled(truncate_str(label, 28), s)),
                Cell::from(Span::styled(bar.to_string(), s.fg(*color))),
                Cell::from(Span::styled(
                    format!("{}", count),
                    s.fg(*color).add_modifier(Modifier::BOLD),
                )),
            ])
        })
        .collect();

    if rows.is_empty() {
        let p = Paragraph::new("No data")
            .style(Style::default().fg(theme.warn).add_modifier(Modifier::DIM))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .style(Style::default().bg(theme.bg)),
            );
        frame.render_widget(p, area);
        return;
    }

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(50),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(Style::default().bg(theme.bg)),
    )
    .column_spacing(1);
    frame.render_widget(table, area);
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .take(max.saturating_sub(1))
            .last()
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}…", &s[..end])
    }
}

fn render_stats_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let items = [
        ("Components", store.total_components, theme.accent),
        ("Services", store.total_services, theme.accent),
        ("Crypto", store.total_crypto, theme.crypto_accent),
        ("Formulas", store.total_formulas, theme.accent),
        ("Deps", store.total_dependencies, theme.accent),
    ];

    let spans: Vec<Span> = items
        .iter()
        .flat_map(|(label, count, color)| {
            vec![
                Span::styled(
                    format!(" {}:{} ", label, count),
                    Style::default().fg(*color),
                ),
                Span::raw("│"),
            ]
        })
        .collect();

    let vuln = store.total_vulnerabilities;
    let mut all_spans = spans;
    if vuln > 0 {
        all_spans.push(Span::styled(
            format!(" Vulns:{} ", vuln),
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        ));
    }
    let ann_count: usize = store
        .bom_files
        .iter()
        .filter_map(|bf| bf.bom.annotations.as_ref())
        .map(|a| a.len())
        .sum();
    if ann_count > 0 {
        all_spans.push(Span::styled(
            format!(" Annotations:{} ", ann_count),
            Style::default().fg(theme.warn),
        ));
    }
    all_spans.push(Span::styled(
        format!(" Files:{} ", store.file_count()),
        Style::default().fg(theme.fg),
    ));

    let p = Paragraph::new(Line::from(all_spans))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Stats ")
                .style(Style::default().bg(theme.bg)),
        )
        .alignment(Alignment::Center);
    frame.render_widget(p, area);
}

fn render_metadata_panel(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let mut rows: Vec<Row> = Vec::new();

    for (fi, bf) in store.bom_files.iter().enumerate() {
        if store.bom_files.len() > 1 {
            rows.push(Row::new(vec![
                Cell::from(Span::styled(
                    format!("── File {}", fi + 1),
                    theme.header_style(),
                )),
                Cell::from(Span::raw("")),
            ]));
        }
        for (label, val) in [
            ("Format", bf.bom.bom_format.as_deref().unwrap_or("-")),
            ("Spec", bf.bom.spec_version.as_deref().unwrap_or("-")),
            ("Serial", bf.bom.serial_number.as_deref().unwrap_or("-")),
        ] {
            rows.push(Row::new(vec![
                Cell::from(Span::styled(
                    label.to_string(),
                    Style::default().fg(theme.detail_fg),
                )),
                Cell::from(Span::raw(val.to_string())),
            ]));
        }
        if let Some(ref meta) = bf.bom.metadata {
            if let Some(ref ts) = meta.timestamp {
                rows.push(Row::new(vec![
                    Cell::from(Span::styled(
                        "Timestamp",
                        Style::default().fg(theme.detail_fg),
                    )),
                    Cell::from(Span::raw(ts.clone())),
                ]));
            }
            if let Some(ref root) = meta.component {
                rows.push(Row::new(vec![
                    Cell::from(Span::styled(
                        "Root Component",
                        Style::default().fg(theme.detail_fg),
                    )),
                    Cell::from(Span::styled(
                        format!(
                            "{} {} [{}]",
                            root.name.as_deref().unwrap_or("-"),
                            root.version.as_deref().unwrap_or(""),
                            root.component_type
                        ),
                        Style::default().fg(theme.accent),
                    )),
                ]));
            }
            if let Some(ref lc) = meta.lifecycles {
                let phases: Vec<&str> = lc.iter().filter_map(|l| l.phase.as_deref()).collect();
                if !phases.is_empty() {
                    rows.push(Row::new(vec![
                        Cell::from(Span::styled(
                            "Lifecycle",
                            Style::default().fg(theme.detail_fg),
                        )),
                        Cell::from(Span::styled(
                            phases.join(", "),
                            Style::default().fg(theme.warn),
                        )),
                    ]));
                }
            }
            if let Some(ref tools) = meta.tools
                && let Some(ref tc) = tools.components
            {
                for t in tc {
                    rows.push(Row::new(vec![
                        Cell::from(Span::styled("Tool", Style::default().fg(theme.detail_fg))),
                        Cell::from(Span::raw(format!(
                            "{} {}",
                            t.name.as_deref().unwrap_or("-"),
                            t.version.as_deref().unwrap_or("")
                        ))),
                    ]));
                }
            }
            if let Some(ref props) = meta.properties {
                for p in props.iter().take(10) {
                    let n = p.name.as_deref().unwrap_or("-");
                    let v = p.value.as_deref().unwrap_or("-");
                    let vd = split_newlines_display(v);
                    rows.push(Row::new(vec![
                        Cell::from(Span::styled(
                            n.to_string(),
                            Style::default().fg(theme.crypto_accent),
                        )),
                        Cell::from(Span::raw(vd)),
                    ]));
                }
                if props.len() > 10 {
                    rows.push(Row::new(vec![
                        Cell::from(Span::raw("")),
                        Cell::from(Span::styled(
                            format!("… and {} more", props.len() - 10),
                            Style::default().fg(theme.warn),
                        )),
                    ]));
                }
            }
        }
    }

    let table = Table::new(
        rows,
        [Constraint::Percentage(20), Constraint::Percentage(80)],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Metadata ")
            .style(Style::default().bg(theme.bg)),
    )
    .column_spacing(2);

    frame.render_widget(table, area);
}

fn render_component_table(
    frame: &mut Frame,
    app: &mut App,
    theme: &Theme,
    area: Rect,
    crypto_only: bool,
    _tab_bg: ratatui::style::Color,
) {
    let store = &app.store;
    let has_vulns = store.total_vulnerabilities > 0;

    // Build columns dynamically so a plain SBOM (no vulns) renders exactly as
    // before, while a VDR adds a compact CVE column after Name.
    let columns: Vec<(&str, Option<SortField>, u16)> = if has_vulns {
        vec![
            ("Type", Some(SortField::Type), 15),
            ("Name", Some(SortField::Name), 22),
            ("CVE", Some(SortField::VulnCount), 7),
            ("Version", Some(SortField::Version), 11),
            ("Purl", Some(SortField::Purl), 25),
            ("License", Some(SortField::License), 20),
        ]
    } else {
        vec![
            ("Type", Some(SortField::Type), 15),
            ("Name", Some(SortField::Name), 25),
            ("Version", Some(SortField::Version), 12),
            ("Purl", Some(SortField::Purl), 28),
            ("License", Some(SortField::License), 20),
        ]
    };

    let header_cells: Vec<Cell> = columns
        .iter()
        .map(|(label, field, _)| {
            let text = match field {
                Some(f) if Some(*label) == store.sort_field_to_str() => {
                    let arrow = match store.sort_order {
                        SortOrder::Ascending => " ▲",
                        SortOrder::Descending => " ▼",
                    };
                    format!("{}{}", label, arrow)
                }
                _ => label.to_string(),
            };
            Cell::from(Span::styled(text, theme.header_style()))
        })
        .collect();

    let header = Row::new(header_cells).height(1);

    let indices: Vec<usize> = if crypto_only {
        store.crypto_assets.clone()
    } else {
        store.filtered_component_indices.clone()
    };

    let title = if crypto_only {
        format!(
            " Cryptographic Assets ({} of {}) ",
            store.total_crypto, store.total_components
        )
    } else {
        format!(
            " Components ({}/{}) ",
            store.filtered_components_count(),
            store.total_components
        )
    };

    let widths: Vec<Constraint> = columns
        .iter()
        .map(|(_, _, pct)| Constraint::Percentage(*pct))
        .collect();

    app.component_header_y = area.y + 1;
    app.component_header_positions.clear();
    let inner_width = area.width.saturating_sub(2);
    let mut x = area.x + 1;
    for col in &columns {
        if let Some(f) = col.1 {
            let col_width = (inner_width as u32 * col.2 as u32 / 100) as u16;
            app.component_header_positions.push((f, x, x + col_width));
            x += col_width + 1;
        }
    }

    let total_items = indices.len();
    if total_items == 0 {
        app.visible_rows = area.height.saturating_sub(4);
        let empty = Paragraph::new("No components found matching the current filter.")
            .style(Style::default().fg(theme.warn))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(empty, area);
        return;
    }

    let visible_rows = area.height.saturating_sub(4) as usize;
    app.visible_rows = area.height.saturating_sub(4);
    let scroll_start = (app.scroll_offset as usize).min(total_items.saturating_sub(1));
    let scroll_end = (scroll_start + visible_rows).min(total_items);
    let visible_indices = &indices[scroll_start..scroll_end];

    let rows: Vec<Row> = visible_indices
        .iter()
        .enumerate()
        .map(|(i, &comp_idx)| {
            let row = &store.components[comp_idx];
            let global_idx = scroll_start + i;
            let is_selected = global_idx == app.table_selected;
            let is_alt = global_idx % 2 == 1;
            let in_selection = app
                .selected_rows()
                .is_some_and(|(s, e)| global_idx >= s && global_idx <= e);

            let base_style = if is_selected {
                theme.selected_style()
            } else if in_selection {
                theme.range_selected_style()
            } else if is_alt {
                Style::default()
                    .fg(theme.table_row_fg)
                    .bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };

            let type_style = if row.component.component_type == "cryptographic-asset" {
                base_style.fg(theme.crypto_accent)
            } else {
                base_style
            };

            let mut cells: Vec<Cell> = vec![
                Cell::from(Span::styled(row.type_display().to_string(), type_style)),
                Cell::from(Span::styled(row.name_display().to_string(), base_style)),
            ];

            if has_vulns {
                let purl_key = row
                    .component
                    .purl
                    .as_deref()
                    .or(row.component.bom_ref.as_deref())
                    .unwrap_or("");
                let cve_cell = match store.vuln_summary_for(purl_key) {
                    None => Cell::from(Span::styled(
                        "—",
                        Style::default()
                            .fg(theme.table_row_fg)
                            .add_modifier(Modifier::DIM),
                    )),
                    Some(sum) => {
                        let col = theme.severity_color_for_rank(sum.max_severity_rank);
                        let mut marker = String::new();
                        if sum.prioritized {
                            marker.push('⚑');
                        }
                        if sum.reachable {
                            marker.push('⚡');
                        }
                        if !marker.is_empty() {
                            marker.push(' ');
                        }
                        let text = format!("{}{}", marker, sum.count);
                        Cell::from(Span::styled(
                            text,
                            base_style.fg(col).add_modifier(Modifier::BOLD),
                        ))
                    }
                };
                cells.push(cve_cell);
            }

            cells.push(Cell::from(Span::styled(
                row.version_display().to_string(),
                base_style,
            )));
            cells.push(Cell::from(Span::styled(
                row.purl_display().to_string(),
                base_style,
            )));
            cells.push(Cell::from(Span::styled(row.license_display(), base_style)));

            Row::new(cells)
        })
        .collect();

    let table = Table::new(rows, &widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .column_spacing(1);

    let mut table_state = TableState::default();
    if total_items > 0 {
        let relative_selected = app.table_selected.saturating_sub(scroll_start);
        table_state.select(Some(relative_selected.min(visible_rows.saturating_sub(1))));
    }

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_service_table(
    frame: &mut Frame,
    app: &mut App,
    theme: &Theme,
    area: Rect,
    _tab_bg: ratatui::style::Color,
) {
    let store = &app.store;

    let header_cells: Vec<Cell> = SERVICE_COLUMNS
        .iter()
        .map(|c| Cell::from(Span::styled(*c, theme.header_style())))
        .collect();

    let header = Row::new(header_cells).height(1);

    let indices = &store.filtered_service_indices;
    let total_items = indices.len();

    let title = format!(
        " Services ({}/{}) ",
        store.filtered_services_count(),
        store.total_services
    );

    if total_items == 0 {
        app.visible_rows = area.height.saturating_sub(4);
        let empty = Paragraph::new("No services found matching the current filter.")
            .style(Style::default().fg(theme.warn))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(empty, area);
        return;
    }

    let visible_rows = area.height.saturating_sub(4) as usize;
    app.visible_rows = area.height.saturating_sub(4);
    let scroll_start = (app.scroll_offset as usize).min(total_items.saturating_sub(1));
    let scroll_end = (scroll_start + visible_rows).min(total_items);
    let visible_indices = &indices[scroll_start..scroll_end];

    let rows: Vec<Row> = visible_indices
        .iter()
        .enumerate()
        .map(|(i, &svc_idx)| {
            let row = &store.services[svc_idx];
            let global_idx = scroll_start + i;
            let is_selected = global_idx == app.table_selected;
            let is_alt = global_idx % 2 == 1;
            let in_selection = app
                .selected_rows()
                .is_some_and(|(s, e)| global_idx >= s && global_idx <= e);

            let base_style = if is_selected {
                theme.selected_style()
            } else if in_selection {
                theme.range_selected_style()
            } else if is_alt {
                Style::default()
                    .fg(theme.table_row_fg)
                    .bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };

            let cells = vec![
                Cell::from(Span::styled(row.name_display().to_string(), base_style)),
                Cell::from(Span::styled(row.endpoints_display(), base_style)),
                Cell::from(Span::styled(row.authenticated_display(), base_style)),
                Cell::from(Span::styled(
                    row.description_display().to_string(),
                    base_style,
                )),
                Cell::from(Span::styled(row.bom_ref_display().to_string(), base_style)),
            ];

            Row::new(cells)
        })
        .collect();

    let widths = [
        Constraint::Percentage(18),
        Constraint::Percentage(28),
        Constraint::Percentage(6),
        Constraint::Percentage(25),
        Constraint::Percentage(23),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .column_spacing(1);

    let mut table_state = TableState::default();
    if total_items > 0 {
        let relative_selected = app.table_selected.saturating_sub(scroll_start);
        table_state.select(Some(relative_selected.min(visible_rows.saturating_sub(1))));
    }

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_formulation(
    frame: &mut Frame,
    app: &mut App,
    theme: &Theme,
    area: Rect,
    _tab_bg: ratatui::style::Color,
) {
    let store = &app.store;
    let mut items: Vec<ListItem> = Vec::new();

    for bom_file in &store.bom_files {
        if let Some(ref formulas) = bom_file.bom.formulation {
            for formula in formulas {
                let name = formula.name.as_deref().unwrap_or("-");
                items.push(ListItem::new(Line::from(vec![Span::styled(
                    format!("▸ {}", name),
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                )])));
                if let Some(ref desc) = formula.description {
                    items.push(ListItem::new(format!("  {}", desc)));
                }
                if let Some(ref comps) = formula.components {
                    items.push(ListItem::new(format!("  Components: {}", comps.len())));
                }
                if let Some(ref workflows) = formula.workflows {
                    for wf in workflows {
                        let wf_name = wf.name.as_deref().unwrap_or("-");
                        items.push(ListItem::new(Line::from(vec![Span::styled(
                            format!("  ▹ {}", wf_name),
                            Style::default().fg(theme.crypto_accent),
                        )])));
                        if let Some(ref wf_desc) = wf.description {
                            items.push(ListItem::new(format!("    {}", wf_desc)));
                        }
                        if let Some(ref tasks) = wf.tasks {
                            for task in tasks {
                                let t_name = task.name.as_deref().unwrap_or("-");
                                items.push(ListItem::new(Line::from(vec![Span::styled(
                                    format!("    ▪ {}", t_name),
                                    Style::default().fg(theme.fg),
                                )])));
                                if let Some(ref t_desc) = task.description {
                                    items.push(ListItem::new(format!("      {}", t_desc)));
                                }
                                if let Some(ref steps) = task.steps {
                                    for step in steps {
                                        let s_name = step.name.as_deref().unwrap_or("-");
                                        items.push(ListItem::new(format!("      • {}", s_name)));
                                        if let Some(ref desc) = step.description {
                                            items.push(ListItem::new(format!("        {}", desc)));
                                        }
                                        if let Some(ref commands) = step.commands {
                                            for cmd in commands.iter().take(3) {
                                                let ex = cmd.executed.as_deref().unwrap_or("-");
                                                items.push(ListItem::new(format!(
                                                    "        $ {}",
                                                    ex
                                                )));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(ref task_deps) = wf.task_dependencies
                            && !task_deps.is_empty()
                        {
                            let deps_str: Vec<&str> = task_deps
                                .iter()
                                .filter_map(|td| td.ref_field.as_deref())
                                .collect();
                            items.push(ListItem::new(format!(
                                "    Task deps: {}",
                                deps_str.join(", ")
                            )));
                        }
                    }
                }
            }
        }
    }

    if items.is_empty() {
        items.push(ListItem::new(Line::from(vec![Span::styled(
            "No formulation data. Use --include-formulation with cdxgen.",
            Style::default().fg(theme.warn),
        )])));
    }

    let total = items.len();
    let title = format!(
        " Formulation ({} items, #{} selected) ",
        total,
        if total > 0 { app.table_selected + 1 } else { 0 }
    );

    let visible = area.height.saturating_sub(3) as usize;
    app.visible_rows = area.height.saturating_sub(3);
    let start = (app.scroll_offset as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .highlight_style(theme.selected_style());

    frame.render_stateful_widget(list, area, &mut list_state);
}

#[allow(clippy::too_many_arguments)]
fn render_vulnerabilities(
    frame: &mut Frame,
    app: &mut App,
    theme: &Theme,
    area: Rect,
    _tab_bg: ratatui::style::Color,
) {
    let store = &app.store;

    let header_cells: Vec<Cell> = VULN_COLUMNS
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let field = VULN_HEADER_FIELDS[i];
            let arrow = if store.vuln_sort_field == field {
                match store.vuln_sort_order {
                    SortOrder::Ascending => " ▲",
                    SortOrder::Descending => " ▼",
                }
            } else {
                ""
            };
            Cell::from(Span::styled(
                format!("{}{}", c, arrow),
                theme.header_style(),
            ))
        })
        .collect();
    let header = Row::new(header_cells).height(1);

    let indices = store.filtered_vulnerability_indices.clone();
    let total_items = indices.len();

    let title = format!(
        " Vulnerabilities ({}/{}) · filter: {} · s:sort f:filter ",
        total_items,
        store.total_vulnerabilities,
        store.vuln_filter.label(),
    );

    let widths = [
        Constraint::Length(2),
        Constraint::Percentage(18),
        Constraint::Percentage(10),
        Constraint::Percentage(8),
        Constraint::Percentage(14),
        Constraint::Percentage(28),
        Constraint::Percentage(20),
    ];

    app.vuln_header_y = area.y + 1;
    app.vuln_header_positions.clear();
    // Mirror the actual `widths` above: the flag column is a fixed Length(2),
    // the rest are percentages of the inner width. Column spacing is 1.
    let inner_width = area.width.saturating_sub(2);
    let col_widths: [u16; 7] = [
        2,
        (inner_width as u32 * 18 / 100) as u16,
        (inner_width as u32 * 10 / 100) as u16,
        (inner_width as u32 * 8 / 100) as u16,
        (inner_width as u32 * 14 / 100) as u16,
        (inner_width as u32 * 28 / 100) as u16,
        (inner_width as u32 * 20 / 100) as u16,
    ];
    let mut x = area.x + 1;
    for (field, w) in VULN_HEADER_FIELDS.iter().zip(col_widths.iter()) {
        app.vuln_header_positions.push((*field, x, x + w));
        x += w + 1;
    }

    if total_items == 0 {
        app.visible_rows = area.height.saturating_sub(4);
        let empty = Paragraph::new("No vulnerabilities match the current filter.")
            .style(Style::default().fg(theme.warn))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(empty, area);
        return;
    }

    let visible_rows = area.height.saturating_sub(4) as usize;
    app.visible_rows = area.height.saturating_sub(4);
    let scroll_start = (app.scroll_offset as usize).min(total_items.saturating_sub(1));
    let scroll_end = (scroll_start + visible_rows).min(total_items);
    let visible_indices = &indices[scroll_start..scroll_end];

    let rows: Vec<Row> = visible_indices
        .iter()
        .enumerate()
        .map(|(i, &vuln_idx)| {
            let row = &store.vulnerabilities[vuln_idx];
            let global_idx = scroll_start + i;
            let is_selected = global_idx == app.table_selected;
            let is_alt = global_idx % 2 == 1;
            let in_selection = app
                .selected_rows()
                .is_some_and(|(s, e)| global_idx >= s && global_idx <= e);

            let base_style = if is_selected {
                theme.selected_style()
            } else if in_selection {
                theme.range_selected_style()
            } else if is_alt {
                Style::default()
                    .fg(theme.table_row_fg)
                    .bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };

            let sev = row.severity();
            let sev_color = theme.severity_color(sev);

            // ⚑ prioritized marker
            let prio_cell = if row.is_prioritized() {
                Cell::from(Span::styled(
                    "⚑",
                    Style::default()
                        .fg(theme.error)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Cell::from(Span::styled(" ", base_style))
            };

            // reach label (with call-site count when available)
            let locs = row.used_in_locations();
            let loc_suffix = locs.map(|n| format!(" ({})", n)).unwrap_or_default();
            let (reach_text, reach_style) = if row.is_endpoint_reachable() {
                (
                    format!("→ Endpoint{}", loc_suffix),
                    Style::default().fg(theme.crypto_accent),
                )
            } else if row.is_reachable() {
                (
                    format!("⚡ Reachable{}", loc_suffix),
                    Style::default().fg(theme.warn),
                )
            } else {
                (
                    "—".to_string(),
                    Style::default()
                        .fg(theme.table_row_fg)
                        .add_modifier(Modifier::DIM),
                )
            };

            let cells = vec![
                prio_cell,
                Cell::from(Span::styled(row.id_display().to_string(), base_style)),
                Cell::from(Span::styled(
                    sev.to_string(),
                    base_style.fg(sev_color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    format!("{:.1}", row.max_score()),
                    base_style.fg(sev_color),
                )),
                Cell::from(Span::styled(reach_text, reach_style)),
                Cell::from(Span::styled(row.package_name(), base_style)),
                Cell::from(Span::styled(row.fix_version(), base_style.fg(theme.accent))),
            ];
            Row::new(cells)
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .column_spacing(1);

    let mut table_state = TableState::default();
    if total_items > 0 {
        let relative_selected = app.table_selected.saturating_sub(scroll_start);
        table_state.select(Some(relative_selected.min(visible_rows.saturating_sub(1))));
    }

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_dependencies(
    frame: &mut Frame,
    app: &mut App,
    theme: &Theme,
    area: Rect,
    _tab_bg: ratatui::style::Color,
) {
    app.dep_tree_area = Some(area);
    let store = &app.store;
    let mut items: Vec<ListItem> = Vec::new();

    let roots = store.dependency_roots();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let expanded = &app.dep_expanded;
    app.dep_tree_refs.clear();

    if !roots.is_empty() {
        let ctx = DepCtx {
            store,
            theme,
            expanded,
        };
        for root in &roots {
            build_dep_list(
                &mut items,
                &mut app.dep_tree_refs,
                &ctx,
                root,
                "",
                &mut visited,
            );
        }
    } else {
        let all_deps = store.all_dependencies();
        for d in all_deps {
            let name = store.resolve_bom_ref(&d.ref_field);
            let has_children = d.depends_on.as_ref().is_some_and(|c| !c.is_empty());
            let is_expanded = expanded.contains(&d.ref_field);
            let icon = if has_children {
                if is_expanded { "▾ " } else { "▸ " }
            } else {
                "  "
            };
            let mut spans: Vec<Span<'static>> = vec![Span::styled(
                format!("{}{}", icon, name),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            )];
            spans.extend(vuln_badge_spans(store, theme, &d.ref_field));
            items.push(ListItem::new(Line::from(spans)));
            app.dep_tree_refs.push(d.ref_field.clone());
            if is_expanded && let Some(ref depends_on) = d.depends_on {
                for (i, child) in depends_on.iter().enumerate() {
                    let prefix = if i == depends_on.len() - 1 {
                        "  └── "
                    } else {
                        "  ├── "
                    };
                    let cname = store.resolve_bom_ref(child);
                    items.push(ListItem::new(format!("{}{}", prefix, cname)));
                    app.dep_tree_refs.push(child.clone());
                }
            }
        }
    }

    let total = items.len();
    app.dep_tree_count = total;

    let all_node_count = store.all_dependencies().len();
    let expanded_count = expanded.len();
    let title = if total > 0 {
        format!(
            " Dependencies ({} visible, {} total, {} expanded, #{} selected) ",
            total,
            all_node_count,
            expanded_count,
            app.table_selected + 1
        )
    } else {
        " Dependencies (empty) ".to_string()
    };

    let visible = area.height.saturating_sub(3) as usize;
    app.visible_rows = area.height.saturating_sub(3);
    let start = (app.scroll_offset as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.bg)),
        )
        .highlight_style(theme.selected_style());

    frame.render_stateful_widget(list, area, &mut list_state);
}

/// Inline risk badge `[!N]` (severity-colored, ⚡ if reachable) for a dep node,
/// read from the prebuilt vuln map. Empty when the node has no vulns.
fn vuln_badge_spans(store: &BomStore, theme: &Theme, ref_field: &str) -> Vec<Span<'static>> {
    match store.vuln_summary_for(ref_field) {
        Some(sum) if sum.count > 0 => {
            let col = theme.severity_color_for_rank(sum.max_severity_rank);
            let mut text = String::from(" [!");
            if sum.reachable {
                text.push('⚡');
            }
            text.push_str(&sum.count.to_string());
            text.push(']');
            vec![Span::styled(
                text,
                Style::default().fg(col).add_modifier(Modifier::BOLD),
            )]
        }
        _ => Vec::new(),
    }
}

/// Read-only context shared across the recursive dependency-tree walk.
struct DepCtx<'a> {
    store: &'a BomStore,
    theme: &'a Theme,
    expanded: &'a std::collections::HashSet<String>,
}

fn build_dep_list(
    items: &mut Vec<ListItem>,
    refs: &mut Vec<String>,
    ctx: &DepCtx,
    ref_field: &str,
    prefix: &str,
    visited: &mut std::collections::HashSet<String>,
) {
    let DepCtx {
        store,
        theme,
        expanded,
    } = *ctx;
    if visited.contains(ref_field) {
        let name = store.resolve_bom_ref(ref_field);
        items.push(ListItem::new(Line::from(vec![
            Span::raw(format!("{}{}", prefix, name)),
            Span::styled(" (cycle)", Style::default().fg(theme.warn)),
        ])));
        refs.push(ref_field.to_string());
        return;
    }
    visited.insert(ref_field.to_string());

    let name = store.resolve_bom_ref(ref_field);
    let children = store.dependency_children(ref_field);
    let has_children = !children.is_empty();
    let is_expanded = expanded.contains(ref_field);

    let icon = if has_children {
        if is_expanded { "▾ " } else { "▸ " }
    } else {
        "  "
    };
    let mut spans: Vec<Span<'static>> = vec![Span::styled(
        format!("{}{}{}", prefix, icon, name),
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )];
    spans.extend(vuln_badge_spans(store, theme, ref_field));
    items.push(ListItem::new(Line::from(spans)));
    refs.push(ref_field.to_string());

    if is_expanded {
        for (i, child) in children.iter().enumerate() {
            let is_last = i == children.len() - 1;
            let child_prefix = if is_last {
                format!("{}  └── ", prefix)
            } else {
                format!("{}  ├── ", prefix)
            };
            build_dep_list(items, refs, ctx, child, &child_prefix, visited);
        }
    }
}

fn render_status_bar(
    frame: &mut Frame,
    app: &App,
    trace_state: &crate::trace::TraceState,
    theme: &Theme,
    area: Rect,
) {
    let mut spans = Vec::new();

    if app.generating {
        let icon = trace_state.status_icon();
        let activity = &trace_state.activity_label;
        let spinner_style = Style::default().fg(theme.accent);
        spans.push(Span::styled(format!(" {} ", icon), spinner_style));
        // The running phase is the coarse "where are we" signal, so it precedes
        // the fine-grained activity label.
        if let Some(phase) = trace_state.active_phase() {
            let mut label = phase.name.clone();
            if let Some(ratio) = phase.ratio() {
                label.push_str(&format!(" {:.0}%", ratio * 100.0));
            }
            spans.push(Span::styled(
                format!("{} ", label),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("│ "));
        }
        if !activity.is_empty() {
            spans.push(Span::styled(
                format!(" {} ", activity),
                Style::default().fg(theme.crypto_accent),
            ));
            spans.push(Span::raw("│ "));
        } else {
            spans.push(Span::styled(
                format!(" {} ", trace_state.spinner()),
                Style::default().fg(theme.accent),
            ));
            spans.push(Span::raw("│ "));
        }
    }

    let tab_info = format!(
        "Tab {}/{} {}",
        Tab::ALL
            .iter()
            .position(|t| *t == app.current_tab)
            .map(|i| i + 1)
            .unwrap_or(1),
        Tab::ALL.len(),
        app.current_tab.label()
    );
    spans.push(Span::styled(tab_info, Style::default().fg(theme.status_fg)));
    spans.push(Span::raw(" │ "));
    spans.push(Span::styled(
        "↑↓:nav /:search s:sort f:filter Enter:detail Tab:next q:quit".to_string(),
        Style::default()
            .fg(theme.status_fg)
            .add_modifier(Modifier::DIM),
    ));

    let status = Paragraph::new(Line::from(spans))
        .style(Style::default().bg(theme.status_bg))
        .alignment(Alignment::Left);

    frame.render_widget(status, area);
}

fn split_newlines_display(value: &str) -> String {
    if value.contains("\\n") {
        let parts: Vec<&str> = value
            .split("\\n")
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        parts.join(", ")
    } else {
        value.to_string()
    }
}

use crate::bom::store::BomStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_newlines_display() {
        assert_eq!(
            split_newlines_display("composer\\ngem\\nnpm"),
            "composer, gem, npm"
        );
        assert_eq!(split_newlines_display("single"), "single");
        assert_eq!(split_newlines_display("a\\nb\\nc"), "a, b, c");
        assert_eq!(split_newlines_display(""), "");
    }

    fn render_every_tab_for_fixture(rel_path: &str) {
        // Headless render of every tab against a real VDR fixture — guards
        // against widget/layout panics (e.g. bar overflow) at wide + narrow
        // widths, in both themes.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel_path);
        if !path.exists() {
            return; // fixtures optional in stripped checkouts
        }
        let mut store = BomStore::new();
        store.load_path(&path).unwrap();
        assert!(store.total_vulnerabilities > 0, "{} has no vulns", rel_path);

        let log_store = crate::logs::LogStore::new(100);
        let trace_state = crate::trace::TraceState::new();

        for theme in [
            crate::ui::theme::Theme::dark(),
            crate::ui::theme::Theme::light(),
        ] {
            for &tab in Tab::ALL.iter() {
                // exercise every vuln quick filter too
                for filter in [
                    crate::bom::store::VulnFilter::All,
                    crate::bom::store::VulnFilter::Prioritized,
                    crate::bom::store::VulnFilter::Reachable,
                    crate::bom::store::VulnFilter::Exploitable,
                    crate::bom::store::VulnFilter::CriticalHigh,
                ] {
                    let mut app = crate::app::App::new(crate::bom::store::BomStore::new());
                    app.store = store.clone();
                    app.current_tab = tab;
                    if tab == Tab::Vulnerabilities {
                        app.store.set_vuln_filter(filter);
                        app.detail_open = true;
                        app.table_selected = 0;
                    } else if filter != crate::bom::store::VulnFilter::All {
                        continue; // filter only matters on the vuln tab
                    }
                    if matches!(tab, Tab::Components | Tab::Dependencies) {
                        app.detail_open = true;
                    }
                    for (w, h) in [(120u16, 40u16), (40, 12)] {
                        let backend = ratatui::backend::TestBackend::new(w, h);
                        let mut terminal = ratatui::Terminal::new(backend).unwrap();
                        terminal
                            .draw(|f| render(f, &mut app, &log_store, &trace_state, &theme))
                            .unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn test_render_phases_panel_during_generation() {
        // The progress rows are the whole point of driving cdxgen from here, so
        // they render at a narrow width and with a determinate bar without
        // overflowing their area.
        let mut trace_state = crate::trace::TraceState::new();
        for line in [
            r#"{"type":"phase","phase":"Preparing environment","state":"started"}"#,
            r#"{"type":"phase","phase":"Preparing environment","state":"succeeded","elapsedMs":25}"#,
            r#"{"type":"phase","phase":"Generating BOM","state":"started"}"#,
            r#"{"type":"phase","phase":"Generating BOM","state":"progress","done":7,"total":9,"detail":"npm workspaces"}"#,
        ] {
            trace_state.process_line(line);
        }
        assert_eq!(trace_state.phases.len(), 2);

        let log_store = crate::logs::LogStore::new(100);
        let theme = crate::ui::theme::Theme::dark();
        for (w, h) in [(120u16, 40u16), (40, 12), (20, 6)] {
            let mut app = crate::app::App::new(crate::bom::store::BomStore::new());
            app.current_tab = Tab::Logs;
            app.generating = true;
            app.thought_text = "Let's scan the project.".to_string();
            let backend = ratatui::backend::TestBackend::new(w, h);
            let mut terminal = ratatui::Terminal::new(backend).unwrap();
            terminal
                .draw(|f| render(f, &mut app, &log_store, &trace_state, &theme))
                .unwrap();
        }
    }

    #[test]
    fn test_render_all_tabs_no_panic_crapi() {
        render_every_tab_for_fixture("test/data/crapi/crapi-sbom-universal.vex.json");
    }

    #[test]
    fn test_render_all_tabs_no_panic_java() {
        render_every_tab_for_fixture("test/data/sbom-java.vex.json");
    }

    #[test]
    fn test_render_all_tabs_no_panic_universal() {
        render_every_tab_for_fixture("test/data/sbom-universal.vex.json");
    }

    #[test]
    fn test_render_all_tabs_no_panic_reachable() {
        // Reachability-rich fixture (juice-shop) exercises the "Used in N
        // locations" provenance parsing + reachability dashboard widgets.
        render_every_tab_for_fixture("test/data/juice-shop.vdr.json");
    }

    #[test]
    fn test_render_all_tabs_plain_sbom_no_vulns() {
        // Degraded path: a plain SBOM (no vulnerabilities[]) must render every
        // tab without panicking and with no CVE column / dashboard.
        let mut store = crate::bom::store::BomStore::new();
        let tmp = std::env::temp_dir().join("cdxui_plain_test_bom.json");
        std::fs::write(&tmp, r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"a","version":"1.0","purl":"pkg:npm/a@1.0"}]}"#).unwrap();
        store.load_path(&tmp).unwrap();
        assert_eq!(store.total_vulnerabilities, 0);
        let _ = std::fs::remove_file(&tmp);

        let theme = crate::ui::theme::Theme::dark();
        let log_store = crate::logs::LogStore::new(100);
        let trace_state = crate::trace::TraceState::new();

        for &tab in Tab::ALL.iter() {
            let mut app = crate::app::App::new(crate::bom::store::BomStore::new());
            app.store = store.clone();
            app.current_tab = tab;
            let backend = ratatui::backend::TestBackend::new(100, 30);
            let mut terminal = ratatui::Terminal::new(backend).unwrap();
            terminal
                .draw(|f| render(f, &mut app, &log_store, &trace_state, &theme))
                .unwrap();
        }
    }
}
