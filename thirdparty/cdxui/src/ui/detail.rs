use crate::app::App;
use crate::bom::schema::Component;
use crate::bom::store::BomStore;
use crate::ui::theme::Theme;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

pub fn render_detail_panel(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let store = &app.store;
    let (lines, title) = build_detail_content(app, store, theme);

    let detail = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(theme.detail_bg).fg(theme.detail_fg)),
        )
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, area);
}

pub fn section_header(text: &str, theme: &Theme) -> Line<'static> {
    Line::from(vec![Span::styled(
        format!("── {} ──", text),
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
    )])
}

fn dim(_s: &str, theme: &Theme) -> Style {
    Style::default().fg(theme.detail_fg).add_modifier(Modifier::DIM)
}

fn accent(theme: &Theme) -> Style {
    Style::default().fg(theme.accent)
}

fn build_detail_content(app: &App, store: &BomStore, theme: &Theme) -> (Vec<Line<'static>>, String) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut title = " Detail ".to_string();

    match app.current_tab {
        crate::app::Tab::Components | crate::app::Tab::Crypto => {
            if let Some(row) = store.filtered_component(app.table_selected) {
                title = format!(" {} {} ", row.name_display(), row.version_display());
                render_component_detail(&mut lines, &row.component, theme);
            } else {
                lines.push(Line::from("No item selected"));
            }
        }
        crate::app::Tab::Dependencies => {
            let ref_field = app.dep_tree_refs.get(app.table_selected).cloned().unwrap_or_default();
            if let Some((_, row)) = store.get_component_by_ref(&ref_field) {
                title = format!(" {} {} ", row.name_display(), row.version_display());
                render_component_detail(&mut lines, &row.component, theme);
            } else {
                let name = store.resolve_bom_ref(&ref_field);
                title = format!(" {} ", name);
                lines.push(Line::from("Component not found in BOM"));
            }
        }
        crate::app::Tab::Services => {
            if let Some(row) = store.filtered_service(app.table_selected) {
                title = format!(" {} ", row.name_display());
                render_service_detail(&mut lines, &row.service, theme);
            } else {
                lines.push(Line::from("No item selected"));
            }
        }
        _ => {
            lines.push(Line::from("Detail view not available for this tab"));
        }
    }

    (lines, title)
}

fn render_component_detail(lines: &mut Vec<Line<'static>>, c: &Component, theme: &Theme) {
    table_row(lines, theme, "Type", &c.component_type);
    if let Some(ref s) = c.scope { table_row(lines, theme, "Scope", s); }
    if let Some(ref s) = c.purl { table_row(lines, theme, "Purl", s); }
    if let Some(ref s) = c.bom_ref { table_row(lines, theme, "BOM Ref", s); }
    if let Some(ref s) = c.group { table_row(lines, theme, "Group", s); }
    if let Some(ref s) = c.description { table_row(lines, theme, "Description", s); }
    if let Some(ref s) = c.publisher { table_row(lines, theme, "Publisher", s); }
    if let Some(ref s) = c.copyright { table_row(lines, theme, "Copyright", s); }
    lines.push(Line::from(""));

    if let Some(ref licenses) = c.licenses {
        lines.push(section_header(&format!("Licenses ({})", licenses.len()), theme));
        for lc in licenses {
            let mut parts: Vec<String> = Vec::new();
            if let Some(ref expr) = lc.expression { parts.push(expr.clone()); }
            if let Some(ref lic) = lc.license {
                if let Some(ref id) = lic.id { parts.push(id.clone()); }
                if let Some(ref name) = lic.name { parts.push(format!("({})", name)); }
            }
            lines.push(Line::from(vec![Span::styled(
                format!("  • {}", parts.join(" ")),
                accent(theme),
            )]));
            if let Some(ref lic) = lc.license {
                if let Some(ref url) = lic.url {
                    lines.push(Line::from(vec![Span::styled(
                        format!("    {}", url),
                        Style::default().fg(theme.crypto_accent),
                    )]));
                }
            }
        }
        lines.push(Line::from(""));
    }

    if let Some(ref properties) = c.properties {
        lines.push(section_header(&format!("Properties ({})", properties.len()), theme));
        let mut sorted: Vec<(&String, &String)> = properties.iter()
            .filter_map(|p| Some((p.name.as_ref()?, p.value.as_ref()?)))
            .collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (name, value) in sorted {
            let ns = if name.contains(':') {
                Style::default().fg(theme.crypto_accent)
            } else {
                Style::default().fg(theme.fg)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {}:", name), ns),
            ]));
            if value.contains("\\n") {
                for part in value.split("\\n").map(|p| p.trim()).filter(|p| !p.is_empty()) {
                    lines.push(Line::from(vec![
                        Span::raw("    • "),
                        Span::styled(part.to_string(), ns),
                    ]));
                }
            } else {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(value.clone(), ns),
                ]));
            }
        }
        lines.push(Line::from(""));
    }

    if let Some(ref evidence) = c.evidence {
        let has_data = evidence.identity.as_ref().map_or(false, |v| !v.is_empty())
            || evidence.occurrences.as_ref().map_or(false, |v| !v.is_empty());
        if has_data {
            lines.push(section_header("Evidence", theme));
            if let Some(ref ids) = evidence.identity {
                for (i, ident) in ids.iter().enumerate() {
                    let label = ident.name.as_deref().unwrap_or("-");
                    lines.push(Line::from(vec![
                        Span::styled(format!("  [{}] ", i + 1), dim("", theme)),
                        Span::raw(label.to_string()),
                    ]));
                    for (k, v) in &ident.extra {
                        lines.push(Line::from(vec![
                            Span::styled(format!("    {}: ", k), dim("", theme)),
                            Span::raw(format!("{}", v)),
                        ]));
                    }
                }
            }
            if let Some(ref occs) = evidence.occurrences {
                for o in occs {
                    if let Some(ref loc) = o.location {
                        lines.push(Line::from(vec![
                            Span::raw("  📁 "),
                            Span::raw(loc.clone()),
                        ]));
                    }
                }
            }
            lines.push(Line::from(""));
        }
    }

    if let Some(ref hashes) = c.hashes {
        lines.push(section_header(&format!("Hashes ({})", hashes.len()), theme));
        for h in hashes {
            let alg = h.alg.as_deref().unwrap_or("-");
            let content = h.content.as_deref().unwrap_or("-");
            lines.push(Line::from(vec![
                Span::styled(format!("  {:12}", alg), dim("", theme)),
                Span::raw(content.to_string()),
            ]));
        }
        lines.push(Line::from(""));
    }

    if let Some(ref ext_refs) = c.external_references {
        lines.push(section_header(&format!("External References ({})", ext_refs.len()), theme));
        for eref in ext_refs {
            let rt = eref.ref_type.as_deref().unwrap_or("?");
            let url = eref.url.as_deref().unwrap_or("-");
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("[{}]", rt), accent(theme)),
                Span::raw(" "),
                Span::styled(url.to_string(), Style::default().fg(theme.crypto_accent)),
            ]));
            if let Some(ref c) = eref.comment {
                lines.push(Line::from(vec![Span::raw(format!("    {}", c))]));
            }
        }
        lines.push(Line::from(""));
    }

    if let Some(ref crypto) = c.crypto_properties {
        lines.push(section_header("Crypto", theme));
        if let Some(ref at) = crypto.asset_type { table_row(lines, theme, "Asset Type", at); }
        if let Some(ref oid) = crypto.oid { table_row(lines, theme, "OID", oid); }
        if let Some(ref cl) = crypto.certification_level {
            lines.push(Line::from(format!("  Certification: {}", cl.join(", "))));
        }
        if let Some(ref algo) = crypto.algorithm_properties {
            lines.push(Line::from(""));
            lines.push(section_header("Algorithm", theme));
            if let Some(ref p) = algo.primitive { table_row(lines, theme, "Primitive", p); }
            if let Some(ref m) = algo.mode { table_row(lines, theme, "Mode", m); }
            if let Some(ref p) = algo.padding { table_row(lines, theme, "Padding", p); }
            if let Some(ref c) = algo.curve { table_row(lines, theme, "Curve", c); }
            if let Some(ref funcs) = algo.crypto_functions {
                lines.push(Line::from(format!("  Functions: {}", funcs.join(", "))));
            }
            if let Some(l) = algo.classical_security_level {
                lines.push(Line::from(format!("  Classical Security: {}", l)));
            }
            if let Some(l) = algo.nist_quantum_security_level {
                lines.push(Line::from(format!("  NIST Quantum: {}", l)));
            }
        }
        if let Some(ref cert) = crypto.certificate_properties {
            lines.push(Line::from(""));
            lines.push(section_header("Certificate", theme));
            if let Some(ref s) = cert.subject_name { table_row(lines, theme, "Subject", s); }
            if let Some(ref s) = cert.issuer_name { table_row(lines, theme, "Issuer", s); }
            if let Some(ref s) = cert.not_valid_before { table_row(lines, theme, "Valid From", s); }
            if let Some(ref s) = cert.not_valid_after { table_row(lines, theme, "Valid To", s); }
            if let Some(ref s) = cert.certificate_format { table_row(lines, theme, "Format", s); }
        }
        lines.push(Line::from(""));
    }
}

fn table_row(lines: &mut Vec<Line<'static>>, theme: &Theme, key: &str, value: &str) {
    lines.push(Line::from(vec![
        Span::styled(format!("  {:16}", key), Style::default().fg(theme.detail_fg)),
        Span::raw(value.to_string()),
    ]));
}

fn render_service_detail(
    lines: &mut Vec<Line<'static>>,
    service: &crate::bom::schema::Service,
    theme: &Theme,
) {
    if let Some(ref n) = service.name { table_row(lines, theme, "Name", n); }
    if let Some(ref r) = service.bom_ref { table_row(lines, theme, "BOM Ref", r); }
    if let Some(ref g) = service.group { table_row(lines, theme, "Group", g); }
    if let Some(ref v) = service.version { table_row(lines, theme, "Version", v); }
    if let Some(ref d) = service.description { table_row(lines, theme, "Description", d); }
    if let Some(a) = service.authenticated { table_row(lines, theme, "Authenticated", if a { "yes" } else { "no" }); }
    if let Some(t) = service.x_trust_boundary { table_row(lines, theme, "Trust Boundary", if t { "yes" } else { "no" }); }
    lines.push(Line::from(""));

    if let Some(ref eps) = service.endpoints {
        lines.push(section_header("Endpoints", theme));
        for ep in eps {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(ep.clone(), Style::default().fg(theme.crypto_accent)),
            ]));
        }
        lines.push(Line::from(""));
    }
    if let Some(ref data) = service.data {
        lines.push(section_header("Data Flow", theme));
        for d in data {
            if let Some(ref c) = d.classification { table_row(lines, theme, "Classification", c); }
            if let Some(ref f) = d.flow { table_row(lines, theme, "Flow", f); }
        }
        lines.push(Line::from(""));
    }
    if let Some(ref props) = service.properties {
        lines.push(section_header(&format!("Properties ({})", props.len()), theme));
        for p in props {
            let n = p.name.as_deref().unwrap_or("-");
            let v = p.value.as_deref().unwrap_or("-");
            lines.push(Line::from(vec![
                Span::styled(format!("  {}: ", n), Style::default().fg(theme.detail_fg)),
                Span::raw(v.to_string()),
            ]));
        }
        lines.push(Line::from(""));
    }
    if let Some(ref erefs) = service.external_references {
        lines.push(section_header(&format!("External References ({})", erefs.len()), theme));
        for eref in erefs {
            let rt = eref.ref_type.as_deref().unwrap_or("?");
            let url = eref.url.as_deref().unwrap_or("-");
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("[{}]", rt), Style::default().fg(theme.accent)),
                Span::raw(" "),
                Span::styled(url.to_string(), Style::default().fg(theme.crypto_accent)),
            ]));
        }
        lines.push(Line::from(""));
    }
}
