pub mod detail;
pub mod theme;

use crate::app::{App, InputMode, Tab};
use crate::bom::store::SortOrder;
use crate::ui::theme::Theme;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, ListItem, Paragraph, Row, Table, TableState, Tabs},
    Frame,
};

const COMPONENT_COLUMNS: [&str; 5] = ["Type", "Name", "Version", "Purl", "License"];
const SERVICE_COLUMNS: [&str; 5] = ["Name", "Endpoints", "Auth", "Description", "BOM Ref"];

pub fn render(frame: &mut Frame, app: &mut App, log_store: &crate::logs::LogStore, trace_state: &crate::trace::TraceState, theme: &Theme) {
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
        render_main_content(frame, app, log_store, theme, split[0], tab_bg);
        detail::render_detail_panel(frame, app, theme, split[1]);
    } else {
        render_main_content(frame, app, log_store, theme, content_area, tab_bg);
    }

    render_status_bar(frame, app, trace_state, theme, status_area);
}

fn render_tabs(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let mut titles: Vec<Line> = Vec::new();
    let mut x = area.x + 1;
    app.tab_positions.clear();

    for tab in &Tab::ALL {
        let label = app.tab_label(*tab);
        let display = format!(" {} ", label);
        let width = display.len() as u16;
        app.tab_positions.push((*tab, x, x + width));
        x += width;

        if *tab == app.current_tab {
            titles.push(Line::from(vec![Span::styled(display, theme.tab_active_style())]));
        } else {
            titles.push(Line::from(vec![Span::styled(display, theme.tab_inactive_style())]));
        }
    }

    let tabs = Tabs::new(titles)
        .block(Block::default().style(Style::default().bg(theme.bg)))
        .highlight_style(theme.tab_active_style())
        .select(Tab::ALL.iter().position(|t| *t == app.current_tab).unwrap_or(0));

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
                Style::default()
                    .fg(theme.accent)
                    .bg(theme.search_bg),
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
                Style::default()
                    .fg(theme.crypto_accent)
                    .bg(theme.search_bg),
            )
        }
        InputMode::Normal => {
            if app.current_filter_active() {
                let type_info = app.component_type_filter.as_ref()
                    .map(|t| format!(" type: {}", t))
                    .unwrap_or_default();
                (
                    format!(
                        "search: \"{}\"{} ({} matches, / search, f type, Esc clear)",
                        app.search_input, type_info,
                        app.current_match_count()
                    ),
                    Style::default()
                        .fg(theme.search_fg)
                        .bg(theme.search_bg),
                )
            } else {
                (
                    "/:search f:filter s:sort Enter:detail Tab:next q:quit".to_string(),
                    Style::default()
                        .fg(theme.status_fg)
                        .bg(theme.bg),
                )
            }
        }
    };

    let paragraph = Paragraph::new(text)
        .block(Block::default().style(Style::default().bg(style.bg.unwrap_or(theme.bg))))
        .style(style);
    frame.render_widget(paragraph, area);
}

impl App {
    fn current_filter_active(&self) -> bool {
        !self.search_input.is_empty() || self.component_type_filter.is_some()
    }

    fn current_match_count(&self) -> usize {
        self.current_list_len()
    }
}

fn render_main_content(frame: &mut Frame, app: &mut App, log_store: &crate::logs::LogStore, theme: &Theme, area: Rect, tab_bg: ratatui::style::Color) {
    match app.current_tab {
        Tab::Logs => render_logs(frame, app, log_store, theme, area, tab_bg),
        Tab::Summary => render_summary(frame, app, theme, area, tab_bg),
        Tab::Components => render_component_table(frame, app, theme, area, false, tab_bg),
        Tab::Crypto => render_component_table(frame, app, theme, area, true, tab_bg),
        Tab::Services => render_service_table(frame, app, theme, area, tab_bg),
        Tab::Formulation => render_formulation(frame, app, theme, area, tab_bg),
        Tab::Dependencies => render_dependencies(frame, app, theme, area, tab_bg),
    }
}

fn render_logs(frame: &mut Frame, app: &mut App, log_store: &crate::logs::LogStore, theme: &Theme, area: Rect, tab_bg: ratatui::style::Color) {
    let in_gen = app.generating || app.generation_done;
    let has_thoughts = in_gen && !app.thought_text.is_empty();

    let constraints: Vec<Constraint> = if has_thoughts {
        vec![Constraint::Percentage(40), Constraint::Percentage(60)]
    } else {
        vec![Constraint::Percentage(100)]
    };

    let panels = Layout::default().direction(Direction::Vertical).constraints(constraints).split(area);

    if has_thoughts {
        render_thoughts_panel(frame, app, theme, panels[0]);
    }
    render_stdout_panel(frame, app, log_store, theme, if has_thoughts { panels[1] } else { panels[0] });
}

fn render_thoughts_panel(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let text = &app.thought_text;

    let lines: Vec<Line> = text.lines().map(|line| {
        let trimmed = line.trim();
        let stripped = trimmed
            .replace("<think>", "").replace("</think>", "")
            .replace("<think", "").trim().to_string();
        if stripped.is_empty() {
            Line::from("")
        } else {
            let style = if trimmed.starts_with("<think") || trimmed.ends_with("</think>") {
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.crypto_accent)
            };
            Line::from(vec![Span::styled(
                if stripped.len() > area.width.saturating_sub(4) as usize {
                    format!("{}…", &stripped[..area.width.saturating_sub(7) as usize])
                } else { stripped },
                style,
            )])
        }
    }).collect();

    let title = if app.generating { " 💭 Thoughts (live) " } else { " 💭 Thoughts " };
    let p = Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title(title).style(Style::default().bg(theme.bg)))
        .scroll((app.thought_scroll, 0));
    frame.render_widget(p, area);
}

fn render_stdout_panel(frame: &mut Frame, app: &mut App, log_store: &crate::logs::LogStore, theme: &Theme, area: Rect) {
    let entries = log_store.entries();

    let mut items: Vec<ListItem> = Vec::new();
    for entry in entries.iter() {
        let level_style = match entry.level {
            crate::logs::LogLevel::Error => Style::default().fg(theme.error),
            crate::logs::LogLevel::Warn => Style::default().fg(theme.warn),
            crate::logs::LogLevel::ProcessExit(_) => Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            _ => Style::default().fg(theme.fg),
        };
        let icon = match entry.level {
            crate::logs::LogLevel::Error => "✗",
            crate::logs::LogLevel::Warn => "⚠",
            crate::logs::LogLevel::ProcessExit(_) => "✓",
            _ => " ",
        };
        let text = truncate_str(&entry.text, area.width.saturating_sub(6) as usize);
        items.push(ListItem::new(Line::from(vec![Span::styled(
            format!(" {} {}", icon, text),
            level_style,
        )])));
    }

    app.last_item_count = items.len();
    let total = items.len();
    let title = if app.generating { format!(" Stdout ({} lines, generating…) ", total) }
                else { format!(" Stdout ({} lines) ", total) };

    let visible = area.height.saturating_sub(3) as usize;
    let start = (app.stdout_scroll as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(Block::default().borders(Borders::ALL).title(title).style(Style::default().bg(theme.bg)))
        .highlight_style(theme.selected_style());
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_summary(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect, tab_bg: ratatui::style::Color) {
    let store = &app.store;

    let annotations: Vec<&crate::bom::schema::Annotation> = store.bom_files.iter()
        .filter_map(|bf| bf.bom.annotations.as_ref())
        .flatten()
        .collect();

    let has_annotations = !annotations.is_empty();

    let constraints: Vec<Constraint> = {
        let mut c = vec![];
        if has_annotations { c.push(Constraint::Length(5)); }
        c.push(Constraint::Length(3)); // stats bar
        c.push(Constraint::Length(10)); // types + licenses
        c.push(Constraint::Min(10));  // dep tree
        c.push(Constraint::Min(6));   // metadata
        c
    };

    let vert = Layout::default().direction(Direction::Vertical).constraints(constraints).split(area);
    let mut idx = 0;

    if has_annotations {
        render_annotation_text(frame, &annotations, theme, vert[idx]);
        idx += 1;
    }

    render_stats_bar(frame, app, theme, vert[idx]);
    idx += 1;

    let mid = vert[idx];
    idx += 1;
    let mid_split = Layout::default().direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(mid);
    render_license_chart(frame, app, theme, mid_split[0]);
    render_type_breakdown(frame, app, theme, mid_split[1]);

    render_mini_dep_tree(frame, app, theme, vert[idx]);
    idx += 1;

    render_metadata_panel(frame, app, theme, vert[idx]);
}

fn render_annotation_text(frame: &mut Frame, annotations: &[&crate::bom::schema::Annotation], theme: &Theme, area: Rect) {
    let text = annotations.first()
        .and_then(|a| a.text.as_deref())
        .map(|t| {
            if t.len() > 200 { format!("{}…", &t[..197]) } else { t.to_string() }
        })
        .unwrap_or_default();
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL)
            .title(format!(" Annotations ({}) ", annotations.len()))
            .style(Style::default().bg(theme.bg)))
        .style(Style::default().fg(theme.warn));
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

    let header = Row::new(["License", "Count", "Distribution"].iter().map(|c| {
        Cell::from(Span::styled(*c, theme.header_style()))
    }));

    let rows: Vec<Row> = top.iter().enumerate().map(|(i, (lic, count))| {
        let bar_len = (*count * 20 / max).max(1);
        let bar = "█".repeat(bar_len);
        let is_alt = i % 2 == 1;
        let s = if is_alt { Style::default().fg(theme.table_row_fg).bg(theme.table_alt_bg) }
                else { Style::default().fg(theme.table_row_fg).bg(theme.bg) };
        Row::new(vec![
            Cell::from(Span::styled(if lic.len() > 18 { format!("{}…", &lic[..15]) } else { lic.clone() }, s)),
            Cell::from(Span::styled(format!("{}", count), s)),
            Cell::from(Span::styled(format!("{} {}", bar, count), s.fg(theme.accent))),
        ])
    }).collect();

    let table = Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(10), Constraint::Percentage(50)])
        .header(header)
        .block(Block::default().borders(Borders::ALL)
            .title(format!(" License Distribution ({} unique) ", sorted.len()))
            .style(Style::default().bg(theme.bg)))
        .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_mini_dep_tree(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let roots = store.dependency_roots();
    let mut items: Vec<ListItem> = Vec::new();
    app.dep_tree_refs.clear();

    if roots.is_empty() {
        let all = store.all_dependencies();
        if all.is_empty() {
            items.push(ListItem::new(Line::from(vec![Span::styled("No dependencies", Style::default().fg(theme.warn))])));
            app.dep_tree_refs.push(String::new());
        } else {
            for d in all.iter().take(15) {
                let name = store.resolve_bom_ref(&d.ref_field);
                let has_children = d.depends_on.as_ref().map_or(false, |c| !c.is_empty());
                let is_expanded = app.dep_expanded.contains(&d.ref_field);
                let icon = if has_children { if is_expanded { "▾" } else { "▸" } } else { " " };
                items.push(ListItem::new(Line::from(vec![Span::styled(
                    format!("{} {}", icon, name),
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                )])));
                app.dep_tree_refs.push(d.ref_field.clone());
                if is_expanded {
                    if let Some(ref children) = d.depends_on {
                        for child in children {
                            let cname = store.resolve_bom_ref(child);
                            items.push(ListItem::new(format!("  └── {}", cname)));
                            app.dep_tree_refs.push(child.clone());
                        }
                    }
                }
            }
        }
    } else {
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        for root in &roots {
            build_dep_list(&mut items, &mut app.dep_tree_refs, store, theme, root, "", &app.dep_expanded, &mut visited);
        }
    }

    app.last_item_count = items.len();
    let total = items.len();
    let title = format!(" Dependency Roots ({}, {} visible) ", roots.len(), total);

    let visible = area.height.saturating_sub(3) as usize;
    let start = (app.scroll_offset as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(Block::default().borders(Borders::ALL).title(title).style(Style::default().bg(theme.bg)))
        .highlight_style(theme.selected_style());
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_type_breakdown(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let type_counts = store.component_type_counts();
    let max_rows = 5usize;
    let shown = type_counts.iter().take(max_rows);
    let remaining = type_counts.len().saturating_sub(max_rows);

    let header = Row::new(["Component Type", "Count"].iter().map(|c| {
        Cell::from(Span::styled(*c, theme.header_style()))
    }));

    let mut rows: Vec<Row> = shown.enumerate().map(|(i, (ct, count))| {
        let is_alt = i % 2 == 1;
        let s = if is_alt {
            Style::default().fg(theme.table_row_fg).bg(theme.table_alt_bg)
        } else {
            Style::default().fg(theme.table_row_fg).bg(theme.bg)
        };
        let type_s = if ct == "cryptographic-asset" { s.fg(theme.crypto_accent) } else { s };
        Row::new(vec![
            Cell::from(Span::styled(ct.clone(), type_s)),
            Cell::from(Span::styled(format!("{}", count), s.add_modifier(Modifier::BOLD))),
        ])
    }).collect();

    if remaining > 0 {
        rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("… +{} more", remaining), Style::default().fg(theme.warn))),
            Cell::from(Span::raw("")),
        ]));
    }

    let table = Table::new(rows, [Constraint::Percentage(70), Constraint::Percentage(30)])
        .header(header)
        .block(Block::default().borders(Borders::ALL)
            .title(format!(" Component Types ({}) ", store.component_type_counts().iter().map(|(_, c)| c).sum::<usize>()))
            .style(Style::default().bg(theme.bg)))
        .column_spacing(2);
    frame.render_widget(table, area);
}

fn render_stats_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let items = vec![
        ("Components", store.total_components, theme.accent),
        ("Services", store.total_services, theme.accent),
        ("Crypto", store.total_crypto, theme.crypto_accent),
        ("Formulas", store.total_formulas, theme.accent),
        ("Deps", store.total_dependencies, theme.accent),
    ];

    let spans: Vec<Span> = items.iter().flat_map(|(label, count, color)| {
        vec![
            Span::styled(format!(" {}:{} ", label, count), Style::default().fg(*color)),
            Span::raw("│"),
        ]
    }).collect();

    let vuln = store.total_vulnerabilities;
    let mut all_spans = spans;
    if vuln > 0 {
        all_spans.push(Span::styled(
            format!(" Vulns:{} ", vuln),
            Style::default().fg(theme.error).add_modifier(Modifier::BOLD),
        ));
    }
    let ann_count: usize = store.bom_files.iter()
        .filter_map(|bf| bf.bom.annotations.as_ref())
        .map(|a| a.len()).sum();
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
        .block(Block::default().borders(Borders::ALL)
            .title(" Stats ")
            .style(Style::default().bg(theme.bg)))
        .alignment(Alignment::Center);
    frame.render_widget(p, area);
}

fn render_metadata_panel(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let mut rows: Vec<Row> = Vec::new();

    for (fi, bf) in store.bom_files.iter().enumerate() {
        if store.bom_files.len() > 1 {
            rows.push(Row::new(vec![
                Cell::from(Span::styled(format!("── File {}", fi + 1), theme.header_style())),
                Cell::from(Span::raw("")),
            ]));
        }
        for (label, val) in [
            ("Format", bf.bom.bom_format.as_deref().unwrap_or("-")),
            ("Spec", bf.bom.spec_version.as_deref().unwrap_or("-")),
            ("Serial", bf.bom.serial_number.as_deref().unwrap_or("-")),
        ] {
            rows.push(Row::new(vec![
                Cell::from(Span::styled(label.to_string(), Style::default().fg(theme.detail_fg))),
                Cell::from(Span::raw(val.to_string())),
            ]));
        }
        if let Some(ref meta) = bf.bom.metadata {
            if let Some(ref ts) = meta.timestamp {
                rows.push(Row::new(vec![
                    Cell::from(Span::styled("Timestamp", Style::default().fg(theme.detail_fg))),
                    Cell::from(Span::raw(ts.clone())),
                ]));
            }
            if let Some(ref root) = meta.component {
                rows.push(Row::new(vec![
                    Cell::from(Span::styled("Root Component", Style::default().fg(theme.detail_fg))),
                    Cell::from(Span::styled(
                        format!("{} {} [{}]", root.name.as_deref().unwrap_or("-"), root.version.as_deref().unwrap_or(""), root.component_type),
                        Style::default().fg(theme.accent),
                    )),
                ]));
            }
            if let Some(ref lc) = meta.lifecycles {
                let phases: Vec<&str> = lc.iter().filter_map(|l| l.phase.as_deref()).collect();
                if !phases.is_empty() {
                    rows.push(Row::new(vec![
                        Cell::from(Span::styled("Lifecycle", Style::default().fg(theme.detail_fg))),
                        Cell::from(Span::styled(phases.join(", "), Style::default().fg(theme.warn))),
                    ]));
                }
            }
            if let Some(ref tools) = meta.tools {
                if let Some(ref tc) = tools.components {
                    for t in tc {
                        rows.push(Row::new(vec![
                            Cell::from(Span::styled("Tool", Style::default().fg(theme.detail_fg))),
                            Cell::from(Span::raw(format!("{} {}", t.name.as_deref().unwrap_or("-"), t.version.as_deref().unwrap_or("")))),
                        ]));
                    }
                }
            }
            if let Some(ref props) = meta.properties {
                for p in props.iter().take(10) {
                    let n = p.name.as_deref().unwrap_or("-");
                    let v = p.value.as_deref().unwrap_or("-");
                    let vd = split_newlines_display(v, 100);
                    rows.push(Row::new(vec![
                        Cell::from(Span::styled(n.to_string(), Style::default().fg(theme.crypto_accent))),
                        Cell::from(Span::raw(vd)),
                    ]));
                }
                if props.len() > 10 {
                    rows.push(Row::new(vec![
                        Cell::from(Span::raw("")),
                        Cell::from(Span::styled(format!("… and {} more", props.len() - 10), Style::default().fg(theme.warn))),
                    ]));
                }
            }
        }
    }

    let table = Table::new(rows, [Constraint::Percentage(20), Constraint::Percentage(80)])
        .block(Block::default().borders(Borders::ALL)
            .title(" Metadata ")
            .style(Style::default().bg(theme.bg)))
        .column_spacing(2);

    frame.render_widget(table, area);
}

fn render_component_table(
    frame: &mut Frame,
    app: &App,
    theme: &Theme,
    area: Rect,
    crypto_only: bool,
    tab_bg: ratatui::style::Color,
) {
    let store = &app.store;

    let header_cells: Vec<Cell> = COMPONENT_COLUMNS
        .iter()
        .map(|c| {
            Cell::from(Span::styled(
                if Some(*c) == store.sort_field_to_str() {
                    let arrow = match store.sort_order {
                        SortOrder::Ascending => " ▲",
                        SortOrder::Descending => " ▼",
                    };
                    format!("{}{}", c, arrow)
                } else {
                    c.to_string()
                },
                theme.header_style(),
            ))
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
            store.total_crypto,
            store.total_components
        )
    } else {
        format!(
            " Components ({}/{}) ",
            store.filtered_components_count(),
            store.total_components
        )
    };

    let widths = [
        Constraint::Percentage(15),
        Constraint::Percentage(25),
        Constraint::Percentage(12),
        Constraint::Percentage(28),
        Constraint::Percentage(20),
    ];

    let total_items = indices.len();
    if total_items == 0 {
        let empty = Paragraph::new("No components found matching the current filter.")
            .style(Style::default().fg(theme.warn))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(empty, area);
        return;
    }

    let visible_rows = area.height.saturating_sub(4) as usize;
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

            let base_style = if is_selected {
                theme.selected_style()
            } else if is_alt {
                Style::default().fg(theme.table_row_fg).bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };

            let type_style = if row.component.component_type == "cryptographic-asset" {
                base_style.fg(theme.crypto_accent)
            } else {
                base_style
            };

            let cells = vec![
                Cell::from(Span::styled(
                    truncate_str(row.type_display(), 18),
                    type_style,
                )),
                Cell::from(Span::styled(
                    truncate_str(row.name_display(), 30),
                    base_style,
                )),
                Cell::from(Span::styled(
                    truncate_str(row.version_display(), 15),
                    base_style,
                )),
                Cell::from(Span::styled(
                    truncate_str(row.purl_display(), 40),
                    base_style,
                )),
                Cell::from(Span::styled(
                    truncate_str(&row.license_display(), 25),
                    base_style,
                )),
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

fn render_service_table(frame: &mut Frame, app: &App, theme: &Theme, area: Rect, tab_bg: ratatui::style::Color) {
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
        let empty = Paragraph::new("No services found matching the current filter.")
            .style(Style::default().fg(theme.warn))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(empty, area);
        return;
    }

    let visible_rows = area.height.saturating_sub(4) as usize;
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

            let base_style = if is_selected {
                theme.selected_style()
            } else if is_alt {
                Style::default().fg(theme.table_row_fg).bg(theme.table_alt_bg)
            } else {
                Style::default().fg(theme.table_row_fg).bg(theme.bg)
            };

            let cells = vec![
                Cell::from(Span::styled(
                    truncate_str(row.name_display(), 25),
                    base_style,
                )),
                Cell::from(Span::styled(
                    truncate_str(&row.endpoints_display(), 40),
                    base_style,
                )),
                Cell::from(Span::styled(
                    row.authenticated_display(),
                    base_style,
                )),
                Cell::from(Span::styled(
                    truncate_str(row.description_display(), 40),
                    base_style,
                )),
                Cell::from(Span::styled(
                    truncate_str(row.bom_ref_display(), 40),
                    base_style,
                )),
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

fn render_formulation(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect, tab_bg: ratatui::style::Color) {
    let store = &app.store;
    let mut items: Vec<ListItem> = Vec::new();

    for bom_file in &store.bom_files {
        if let Some(ref formulas) = bom_file.bom.formulation {
            for formula in formulas {
                let name = formula.name.as_deref().unwrap_or("-");
                items.push(ListItem::new(Line::from(vec![Span::styled(
                    format!("▸ {}", name),
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
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
                                                let ed = if ex.len() > 90 { format!("{}…", &ex[..87]) } else { ex.to_string() };
                                                items.push(ListItem::new(format!("        $ {}", ed)));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(ref task_deps) = wf.task_dependencies {
                            if !task_deps.is_empty() {
                                let deps_str: Vec<&str> = task_deps.iter().filter_map(|td| td.ref_field.as_deref()).collect();
                                items.push(ListItem::new(format!("    Task deps: {}", deps_str.join(", "))));
                            }
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
    app.last_item_count = total;
    let title = format!(" Formulation ({} items, #{} selected) ", total,
        if total > 0 { app.table_selected + 1 } else { 0 });

    let visible = area.height.saturating_sub(3) as usize;
    let start = (app.scroll_offset as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(Block::default().borders(Borders::ALL)
            .title(title)
            .style(Style::default().bg(theme.bg)))
        .highlight_style(theme.selected_style());

    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_dependencies(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect, tab_bg: ratatui::style::Color) {
    let store = &app.store;
    let mut items: Vec<ListItem> = Vec::new();

    let roots = store.dependency_roots();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let expanded = &app.dep_expanded;
    app.dep_tree_refs.clear();

    if !roots.is_empty() {
        for root in &roots {
            build_dep_list(&mut items, &mut app.dep_tree_refs, store, theme, root, "", expanded, &mut visited);
        }
    } else {
        let all_deps = store.all_dependencies();
        for d in all_deps {
            let name = store.resolve_bom_ref(&d.ref_field);
            let has_children = d.depends_on.as_ref().map_or(false, |c| !c.is_empty());
            let is_expanded = expanded.contains(&d.ref_field);
            let icon = if has_children { if is_expanded { "▾ " } else { "▸ " } } else { "  " };
            items.push(ListItem::new(Line::from(vec![Span::styled(
                format!("{}{}", icon, name),
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
            )])));
            app.dep_tree_refs.push(d.ref_field.clone());
            if is_expanded {
                if let Some(ref depends_on) = d.depends_on {
                    for (i, child) in depends_on.iter().enumerate() {
                        let prefix = if i == depends_on.len() - 1 { "  └── " } else { "  ├── " };
                        let cname = store.resolve_bom_ref(child);
                        items.push(ListItem::new(format!("{}{}", prefix, cname)));
                        app.dep_tree_refs.push(child.clone());
                    }
                }
            }
        }
    }

    let total = items.len();
    app.last_item_count = total;

    let all_node_count = store.all_dependencies().len();
    let expanded_count = expanded.len();
    let title = if total > 0 {
        format!(" Dependencies ({} visible, {} total, {} expanded, #{} selected) ",
            total, all_node_count, expanded_count, app.table_selected + 1)
    } else {
        " Dependencies (empty) ".to_string()
    };

    let visible = area.height.saturating_sub(3) as usize;
    let start = (app.scroll_offset as usize).min(total.saturating_sub(1));
    let end = (start + visible).min(total);
    let visible_items: Vec<ListItem> = items[start..end].to_vec();

    let mut list_state = ratatui::widgets::ListState::default();
    if total > 0 {
        let rel = app.table_selected.saturating_sub(start);
        list_state.select(Some(rel.min(visible_items.len().saturating_sub(1))));
    }

    let list = ratatui::widgets::List::new(visible_items)
        .block(Block::default().borders(Borders::ALL)
            .title(title)
            .style(Style::default().bg(theme.bg)))
        .highlight_style(theme.selected_style());

    frame.render_stateful_widget(list, area, &mut list_state);
}

fn build_dep_list(
    items: &mut Vec<ListItem>,
    refs: &mut Vec<String>,
    store: &BomStore,
    theme: &Theme,
    ref_field: &str,
    prefix: &str,
    expanded: &std::collections::HashSet<String>,
    visited: &mut std::collections::HashSet<String>,
) {
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

    let icon = if has_children { if is_expanded { "▾ " } else { "▸ " } } else { "  " };
    items.push(ListItem::new(Line::from(vec![Span::styled(
        format!("{}{}{}", prefix, icon, name),
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
    )])));
    refs.push(ref_field.to_string());

    if is_expanded {
        for (i, child) in children.iter().enumerate() {
            let is_last = i == children.len() - 1;
            let child_prefix = if is_last {
                format!("{}  └── ", prefix)
            } else {
                format!("{}  ├── ", prefix)
            };
            build_dep_list(items, refs, store, theme, child, &child_prefix, expanded, visited);
        }
    }
}

fn render_status_bar(frame: &mut Frame, app: &App, trace_state: &crate::trace::TraceState, theme: &Theme, area: Rect) {
    let mut spans = Vec::new();

    if app.generating {
        let icon = trace_state.status_icon();
        let activity = &trace_state.activity_label;
        let spinner_style = Style::default().fg(theme.accent);
        spans.push(Span::styled(format!(" {} ", icon), spinner_style));
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

    let tab_info = format!("Tab {}/{} {}", Tab::ALL.iter().position(|t| *t == app.current_tab).map(|i| i + 1).unwrap_or(1), Tab::ALL.len(), app.current_tab.label());
    spans.push(Span::styled(tab_info, Style::default().fg(theme.status_fg)));
    spans.push(Span::raw(" │ "));
    spans.push(Span::styled("↑↓:nav /:search s:sort f:filter Enter:detail Tab:next q:quit".to_string(), Style::default().fg(theme.status_fg).add_modifier(Modifier::DIM)));

    let status = Paragraph::new(Line::from(spans))
        .style(Style::default().bg(theme.status_bg))
        .alignment(Alignment::Left);

    frame.render_widget(status, area);
}

fn truncate_str(s: &str, max_len: usize) -> String {
    let s = s.trim();
    if s.len() > max_len {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    } else {
        s.to_string()
    }
}

fn split_newlines_display(value: &str, max_len: usize) -> String {
    if value.contains("\\n") {
        let parts: Vec<&str> = value.split("\\n").map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
        let joined = parts.join(", ");
        if joined.len() > max_len {
            format!("{}…", &joined[..max_len.saturating_sub(1)])
        } else {
            joined
        }
    } else if value.len() > max_len {
        format!("{}…", &value[..max_len.saturating_sub(1)])
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
        assert_eq!(split_newlines_display("composer\\ngem\\nnpm", 100), "composer, gem, npm");
        assert_eq!(split_newlines_display("single", 100), "single");
        assert_eq!(split_newlines_display("a\\nb\\nc", 6), "a, b,…");
        assert_eq!(split_newlines_display("", 100), "");
    }
}
