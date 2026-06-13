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
        .wrap(Wrap { trim: true });

    frame.render_widget(detail, area);
}

pub fn section_header(text: &str, theme: &Theme) -> Line<'static> {
    Line::from(vec![Span::styled(
        format!("── {} ──", text),
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )])
}

pub fn key_value_line(key: &str, value: String, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{}: ", key),
            Style::default().fg(theme.detail_fg),
        ),
        Span::styled(
            if value.is_empty() { "-".to_string() } else { value },
            Style::default().fg(theme.fg),
        ),
    ])
}

pub fn key_value_dim(key: &str, value: String, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{}: ", key), Style::default().fg(theme.detail_fg)),
        Span::styled(
            if value.is_empty() { "-".to_string() } else { value },
            Style::default().fg(theme.fg),
        ),
    ])
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

fn render_component_detail(lines: &mut Vec<Line<'static>>, component: &Component, theme: &Theme) {
    macro_rules! kv {
        ($key:expr, $val:expr) => {
            lines.push(key_value_line($key, $val.to_string(), theme));
        };
    }

    kv!("Type", component.component_type.as_str());
    if let Some(ref s) = component.scope {
        kv!("Scope", s.as_str());
    }
    if let Some(ref s) = component.purl {
        kv!("Purl", s.as_str());
    }
    if let Some(ref s) = component.bom_ref {
        kv!("BOM Ref", s.as_str());
    }
    if let Some(ref s) = component.group {
        kv!("Group", s.as_str());
    }
    if let Some(ref s) = component.description {
        let d = if s.len() > 200 {
            format!("{}…", &s[..197])
        } else {
            s.clone()
        };
        kv!("Description", &d);
    }
    if let Some(ref s) = component.publisher {
        kv!("Publisher", s.as_str());
    }
    if let Some(ref s) = component.copyright {
        kv!("Copyright", s.as_str());
    }
    lines.push(Line::from(""));

    if let Some(ref licenses) = component.licenses {
        lines.push(section_header("Licenses", theme));
        for lc in licenses {
            if let Some(ref expr) = lc.expression {
                lines.push(Line::from(vec![Span::styled(
                    expr.clone(),
                    Style::default().fg(theme.fg),
                )]));
            }
            if let Some(ref license) = lc.license {
                if let Some(ref id) = license.id {
                    lines.push(Line::from(vec![Span::styled(
                        id.clone(),
                        Style::default().fg(theme.accent),
                    )]));
                }
                if let Some(ref name) = license.name {
                    lines.push(Line::from(vec![Span::raw(format!("  {}", name))]));
                }
                if let Some(ref url) = license.url {
                    lines.push(Line::from(vec![Span::raw(format!("  {}", url))]));
                }
            }
        }
        lines.push(Line::from(""));
    }

    if let Some(ref properties) = component.properties {
        lines.push(section_header(
            &format!("Properties ({})", properties.len()),
            theme,
        ));
        let mut sorted: Vec<(&String, &String)> = Vec::new();
        for p in properties {
            if let (Some(ref n), Some(ref v)) = (&p.name, &p.value) {
                sorted.push((n, v));
            }
        }
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (name, value) in sorted {
            let style = if name.contains(':') {
                Style::default().fg(theme.crypto_accent)
            } else {
                Style::default().fg(theme.fg)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {}:", name), style),
            ]));
            if value.contains("\\n") {
                for part in value.split("\\n") {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        let vd = if trimmed.len() > 100 { format!("{}…", &trimmed[..97]) } else { trimmed.to_string() };
                        lines.push(Line::from(vec![
                            Span::raw("    • "),
                            Span::styled(vd, style),
                        ]));
                    }
                }
            } else {
                let vd = if value.len() > 120 { format!("{}…", &value[..117]) } else { value.clone() };
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(vd, style),
                ]));
            }
        }
        lines.push(Line::from(""));
    }

    if let Some(ref evidence) = component.evidence {
        lines.push(section_header("Evidence", theme));
        if let Some(ref ids) = evidence.identity {
            for (i, ident) in ids.iter().enumerate() {
                if let Some(ref n) = ident.name {
                    lines.push(Line::from(format!("  [{}] {}", i + 1, n)));
                }
                if let Some(ref urls) = ident.url {
                    for u in urls {
                        lines.push(Line::from(format!("    url: {}", u)));
                    }
                }
                for (k, v) in &ident.extra {
                    let s = v.to_string();
                    let ds = if s.len() > 80 { format!("{}…", &s[..77]) } else { s };
                    lines.push(Line::from(format!("    {}: {}", k, ds)));
                }
            }
        }
        if let Some(ref occs) = evidence.occurrences {
            for o in occs {
                if let Some(ref loc) = o.location {
                    lines.push(Line::from(format!("  location: {}", loc)));
                }
            }
        }
        if let Some(ref evl) = evidence.licenses {
            for l in evl.iter().take(5) {
                if let Some(ref e) = l.expression {
                    lines.push(Line::from(format!("  license: {}", e)));
                }
                if let Some(ref lic) = l.license {
                    if let Some(ref id) = lic.id {
                        lines.push(Line::from(format!("    id: {}", id)));
                    }
                }
            }
        }
        if let Some(ref crs) = evidence.copyright {
            for c in crs.iter().take(3) {
                if let Some(ref t) = c.text {
                    lines.push(Line::from(format!("  copyright: {}", t)));
                }
            }
        }
        lines.push(Line::from(""));
    }

    if let Some(ref hashes) = component.hashes {
        lines.push(section_header("Hashes", theme));
        for h in hashes {
            let alg = h.alg.as_deref().unwrap_or("-");
            let content = h.content.as_deref().unwrap_or("-");
            let cd = if content.len() > 40 {
                format!("{}…", &content[..37])
            } else {
                content.to_string()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {}: ", alg),
                    Style::default().fg(theme.detail_fg),
                ),
                Span::raw(cd),
            ]));
        }
        lines.push(Line::from(""));
    }

    if let Some(ref ext_refs) = component.external_references {
        lines.push(section_header(
            &format!("External References ({})", ext_refs.len()),
            theme,
        ));
        for eref in ext_refs {
            let rt = eref.ref_type.as_deref().unwrap_or("-");
            let url = eref.url.as_deref().unwrap_or("-");
            let ud = if url.len() > 80 {
                format!("{}…", &url[..77])
            } else {
                url.to_string()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("[{}] ", rt), Style::default().fg(theme.accent)),
                Span::raw(ud),
            ]));
            if let Some(ref c) = eref.comment {
                lines.push(Line::from(format!("    {}", c)));
            }
        }
        lines.push(Line::from(""));
    }

    if let Some(ref crypto) = component.crypto_properties {
        lines.push(section_header("Crypto", theme));
        if let Some(ref at) = crypto.asset_type {
            kv!("Asset Type", at.as_str());
        }
        if let Some(ref oid) = crypto.oid {
            kv!("OID", oid.as_str());
        }
        if let Some(ref ee) = crypto.execution_environment {
            kv!("Exec Env", ee.as_str());
        }
        if let Some(ref cl) = crypto.certification_level {
            lines.push(Line::from(format!(
                "  Certification: {}",
                cl.join(", ")
            )));
        }
        if let Some(ref algo) = crypto.algorithm_properties {
            lines.push(Line::from(""));
            lines.push(section_header("Algorithm", theme));
            if let Some(ref p) = algo.primitive {
                kv!("Primitive", p.as_str());
            }
            if let Some(ref m) = algo.mode {
                kv!("Mode", m.as_str());
            }
            if let Some(ref p) = algo.padding {
                kv!("Padding", p.as_str());
            }
            if let Some(ref c) = algo.curve {
                kv!("Curve", c.as_str());
            }
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
            if let Some(ref s) = cert.subject_name {
                kv!("Subject", s.as_str());
            }
            if let Some(ref s) = cert.issuer_name {
                kv!("Issuer", s.as_str());
            }
            if let Some(ref s) = cert.not_valid_before {
                kv!("Valid From", s.as_str());
            }
            if let Some(ref s) = cert.not_valid_after {
                kv!("Valid To", s.as_str());
            }
            if let Some(ref s) = cert.certificate_format {
                kv!("Format", s.as_str());
            }
        }
        lines.push(Line::from(""));
    }
}

fn render_service_detail(
    lines: &mut Vec<Line<'static>>,
    service: &crate::bom::schema::Service,
    theme: &Theme,
) {
    macro_rules! kv {
        ($key:expr, $val:expr) => {
            lines.push(key_value_line($key, $val.to_string(), theme));
        };
    }

    if let Some(ref n) = service.name {
        kv!("Name", n.as_str());
    }
    if let Some(ref r) = service.bom_ref {
        kv!("BOM Ref", r.as_str());
    }
    if let Some(ref g) = service.group {
        kv!("Group", g.as_str());
    }
    if let Some(ref v) = service.version {
        kv!("Version", v.as_str());
    }
    if let Some(ref d) = service.description {
        kv!("Description", d.as_str());
    }
    if let Some(a) = service.authenticated {
        kv!("Authenticated", if a { "yes" } else { "no" });
    }
    if let Some(t) = service.x_trust_boundary {
        kv!("Trust Boundary", if t { "yes" } else { "no" });
    }
    if let Some(ref eps) = service.endpoints {
        lines.push(Line::from(""));
        lines.push(section_header("Endpoints", theme));
        for ep in eps {
            lines.push(Line::from(format!("  {}", ep)));
        }
    }
    if let Some(ref data) = service.data {
        lines.push(Line::from(""));
        lines.push(section_header("Data Flow", theme));
        for d in data {
            if let Some(ref c) = d.classification {
                kv!("Classification", c.as_str());
            }
            if let Some(ref f) = d.flow {
                kv!("Flow", f.as_str());
            }
        }
    }
    if let Some(ref props) = service.properties {
        lines.push(Line::from(""));
        lines.push(section_header(
            &format!("Properties ({})", props.len()),
            theme,
        ));
        for p in props {
            let n = p.name.as_deref().unwrap_or("-");
            let v = p.value.as_deref().unwrap_or("-");
            lines.push(key_value_dim(n, v.to_string(), theme));
        }
    }
    if let Some(ref erefs) = service.external_references {
        lines.push(Line::from(""));
        lines.push(section_header(
            &format!("External References ({})", erefs.len()),
            theme,
        ));
        for eref in erefs {
            let rt = eref.ref_type.as_deref().unwrap_or("-");
            let url = eref.url.as_deref().unwrap_or("-");
            lines.push(Line::from(vec![
                Span::styled(format!("[{}] ", rt), Style::default().fg(theme.accent)),
                Span::raw(url.to_string()),
            ]));
        }
    }
}
