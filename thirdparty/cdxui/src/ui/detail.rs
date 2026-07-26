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
                render_component_vulns(&mut lines, store, &row.component, theme);
            } else {
                lines.push(Line::from("No item selected"));
            }
        }
        crate::app::Tab::Dependencies => {
            let ref_field = app.dep_tree_refs.get(app.table_selected).cloned().unwrap_or_default();
            if let Some((_, row)) = store.get_component_by_ref(&ref_field) {
                title = format!(" {} {} ", row.name_display(), row.version_display());
                render_component_detail(&mut lines, &row.component, theme);
                render_component_vulns(&mut lines, store, &row.component, theme);
            } else {
                let name = store.resolve_bom_ref(&ref_field);
                title = format!(" {} ", name);
                // Carry the ref so its vulnerabilities still render even though
                // the component isn't a first-class entry in the BOM.
                let stub = crate::bom::schema::Component {
                    bom_ref: Some(ref_field.clone()),
                    ..Default::default()
                };
                render_component_vulns(&mut lines, store, &stub, theme);
                if store.vulns_for_component(&ref_field).is_empty() {
                    lines.push(Line::from("Component not found in BOM"));
                }
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
        crate::app::Tab::Vulnerabilities => {
            if let Some(row) = store.filtered_vulnerability(app.table_selected) {
                title = format!(" {} ", row.id_display());
                render_vulnerability_detail(&mut lines, row, theme);
            } else {
                lines.push(Line::from("No vulnerability selected"));
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
            if let Some(ref lic) = lc.license
                && let Some(ref url) = lic.url {
                    lines.push(Line::from(vec![Span::styled(
                        format!("    {}", url),
                        Style::default().fg(theme.crypto_accent),
                    )]));
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
        let has_data = evidence.identity.as_ref().is_some_and(|v| !v.is_empty())
            || evidence.occurrences.as_ref().is_some_and(|v| !v.is_empty());
        if has_data {
            lines.push(section_header("Evidence", theme));
            if let Some(ref ids) = evidence.identity {
                for (i, ident) in ids.iter().enumerate() {
                    let label = ident.field.as_deref().unwrap_or("-");
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
) {    if let Some(ref n) = service.name { table_row(lines, theme, "Name", n); }
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

fn render_vulnerability_detail(
    lines: &mut Vec<Line<'static>>,
    row: &crate::bom::store::VulnerabilityRow,
    theme: &Theme,
) {
    let v = &row.vuln;
    let sev = row.severity();
    let sev_color = theme.severity_color(sev);

    // Header / identity
    if row.is_prioritized() {
        lines.push(Line::from(vec![
            Span::styled("⚑ PRIORITIZED", Style::default().fg(theme.error).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
        ]));
        lines.push(Line::from(""));
    }
    table_row(lines, theme, "ID", row.id_display());
    if let Some(ref b) = v.bom_ref { table_row(lines, theme, "BOM Ref", b); }
    table_row(lines, theme, "Severity", sev);
    table_row(lines, theme, "Score", &format!("{:.1}", row.max_score()));
    table_row(lines, theme, "Method", row.method());
    table_row(lines, theme, "Package", &row.package_name());
    if let Some(p) = row.affects_purl() { table_row(lines, theme, "Affected Purl", p); }
    table_row(lines, theme, "Fix", &row.fix_version());
    let reach = if row.is_endpoint_reachable() {
        "Endpoint-reachable"
    } else if row.is_reachable() {
        "Reachable"
    } else {
        "Not reachable"
    };
    let reach_val = match row.used_in_locations() {
        Some(n) => format!("{} (used in {} location{})", reach, n, if n == 1 { "" } else { "s" }),
        None => reach.to_string(),
    };
    table_row(lines, theme, "Reachability", &reach_val);
    let _ = sev_color;
    lines.push(Line::from(""));

    // Reachability & insights
    let labels = row.insight_labels();
    if !labels.is_empty() {
        lines.push(section_header(&format!("Reachability & Insights ({})", labels.len()), theme));
        for label in &labels {
            let low = label.to_lowercase();
            let style = if low.contains("exploit") || low == "exploitable" {
                Style::default().fg(theme.error).add_modifier(Modifier::BOLD)
            } else if low.contains("reachable") || low.contains("endpoint") {
                Style::default().fg(theme.warn).add_modifier(Modifier::BOLD)
            } else if low.contains("malicious") {
                Style::default().fg(theme.error).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.detail_fg)
            };
            lines.push(Line::from(vec![
                Span::raw("  • "),
                Span::styled(label.clone(), style),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Description / detail
    let desc = v.description.as_deref().unwrap_or("");
    let detail = v.detail.as_deref().unwrap_or("");
    if !desc.is_empty() {
        lines.push(section_header("Description", theme));
        for ln in wrap_text(desc, 76) {
            lines.push(Line::from(format!("  {}", ln)));
        }
        lines.push(Line::from(""));
    }
    if !detail.is_empty() {
        lines.push(section_header("Detail", theme));
        for ln in wrap_text(detail, 76) {
            lines.push(Line::from(format!("  {}", ln)));
        }
        lines.push(Line::from(""));
    }

    // Recommendation / fix
    let rec = v.recommendation.as_deref().unwrap_or("");
    if !rec.is_empty() {
        lines.push(section_header("Recommendation / Fix", theme));
        for ln in wrap_text(rec, 76) {
            lines.push(Line::from(vec![Span::styled(format!("  {}", ln), accent(theme))]));
        }
        // Affected → unaffected version mapping
        if let Some(affects) = &v.affects {
            for a in affects {
                if let Some(versions) = &a.versions {
                    for ver in versions {
                        let status = ver.status.as_deref().unwrap_or("-");
                        let vv = ver.version.as_deref().or(ver.range.as_deref()).unwrap_or("-");
                        let st = if status == "unaffected" {
                            Style::default().fg(theme.accent)
                        } else {
                            Style::default().fg(theme.detail_fg)
                        };
                        lines.push(Line::from(vec![
                            Span::styled(format!("  {:12}", status), st),
                            Span::raw(vv.to_string()),
                        ]));
                    }
                }
            }
        }
        lines.push(Line::from(""));
    }

    // Ratings
    if let Some(ratings) = &v.ratings
        && !ratings.is_empty() {
            lines.push(section_header(&format!("Ratings ({})", ratings.len()), theme));
            for r in ratings {
                let method = r.method.as_deref().unwrap_or("-");
                let score = r.score.map(|s| format!("{:.1}", s)).unwrap_or_else(|| "-".to_string());
                let sev_r = r.severity.as_deref().unwrap_or("-");
                let col = theme.severity_color(sev_r);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:10}", method), dim("", theme)),
                    Span::styled(format!("{:>5}", score), Style::default().fg(col).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  {:9}", sev_r), Style::default().fg(col)),
                ]));
                if let Some(vec) = &r.vector {
                    lines.push(Line::from(vec![
                        Span::styled("    vector: ", dim("", theme)),
                        Span::raw(vec.clone()),
                    ]));
                }
            }
            lines.push(Line::from(""));
        }

    // VEX analysis
    if let Some(analysis) = &v.analysis {
        let state = analysis.state.as_deref().unwrap_or("");
        let adetail = analysis.detail.as_deref().unwrap_or("");
        if !state.is_empty() || !adetail.is_empty() {
            lines.push(section_header("VEX Analysis", theme));
            if !state.is_empty() {
                let col = if state.eq_ignore_ascii_case("exploitable") { theme.error } else { theme.warn };
                table_row_styled(lines, theme, "State", state, col);
            }
            if !adetail.is_empty() {
                for ln in wrap_text(adetail, 76) {
                    lines.push(Line::from(format!("    {}", ln)));
                }
            }
            if let Some(j) = &analysis.justification {
                table_row(lines, theme, "Justification", j);
            }
            if let Some(resp) = &analysis.response
                && !resp.is_empty() {
                    table_row(lines, theme, "Response", &resp.join(", "));
                }
            lines.push(Line::from(""));
        }
    }

    // CWEs
    if let Some(cwes) = &v.cwes {
        let real: Vec<u32> = cwes.iter().copied().filter(|&c| c > 0).collect();
        if !real.is_empty() {
            lines.push(section_header(&format!("CWEs ({})", real.len()), theme));
            for cwe in &real {
                lines.push(Line::from(vec![
                    Span::raw("  • "),
                    Span::styled(format!("CWE-{}", cwe), accent(theme)),
                    Span::styled(format!("  https://cwe.mitre.org/data/definitions/{}.html", cwe), dim("", theme)),
                ]));
            }
            lines.push(Line::from(""));
        }
    }

    // Advisories
    if let Some(advs) = &v.advisories
        && !advs.is_empty() {
            lines.push(section_header(&format!("Advisories ({})", advs.len()), theme));
            for adv in advs {
                let t = adv.title.as_deref().unwrap_or("-");
                let u = adv.url.as_deref().unwrap_or("-");
                lines.push(Line::from(vec![
                    Span::styled(format!("  • {:30}", truncate(t, 30)), Style::default().fg(theme.detail_fg)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("    ", dim("", theme)),
                    Span::styled(u.to_string(), Style::default().fg(theme.crypto_accent)),
                ]));
            }
            lines.push(Line::from(""));
        }

    // References
    if let Some(refs) = &v.references
        && !refs.is_empty() {
            lines.push(section_header(&format!("References ({})", refs.len()), theme));
            for rf in refs {
                let rid = rf.id.as_deref().unwrap_or("-");
                let src = rf.source.as_ref().and_then(|s| s.name.as_deref()).unwrap_or("");
                let url = rf.source.as_ref().and_then(|s| s.url.as_deref()).unwrap_or("");
                lines.push(Line::from(vec![
                    Span::styled(format!("  • {:18}", truncate(rid, 18)), accent(theme)),
                    Span::styled(src.to_string(), dim("", theme)),
                ]));
                if !url.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("    ", dim("", theme)),
                        Span::styled(url.to_string(), Style::default().fg(theme.crypto_accent)),
                    ]));
                }
            }
            lines.push(Line::from(""));
        }

    // Source / timestamps
    let src_name = v.source.as_ref().and_then(|s| s.name.as_deref()).unwrap_or("");
    let src_url = v.source.as_ref().and_then(|s| s.url.as_deref()).unwrap_or("");
    let published = v.published.as_deref().unwrap_or("");
    let updated = v.updated.as_deref().unwrap_or("");
    if !src_name.is_empty() || !src_url.is_empty() || !published.is_empty() || !updated.is_empty() {
        lines.push(section_header("Source / Timestamps", theme));
        if !src_name.is_empty() { table_row(lines, theme, "Source", src_name); }
        if !src_url.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(format!("  {:16}", "URL"), Style::default().fg(theme.detail_fg)),
                Span::styled(src_url.to_string(), Style::default().fg(theme.crypto_accent)),
            ]));
        }
        if !published.is_empty() { table_row(lines, theme, "Published", published); }
        if !updated.is_empty() { table_row(lines, theme, "Updated", updated); }
        lines.push(Line::from(""));
    }
}

fn table_row_styled(lines: &mut Vec<Line<'static>>, theme: &Theme, key: &str, value: &str, value_style: ratatui::style::Color) {
    lines.push(Line::from(vec![
        Span::styled(format!("  {:16}", key), Style::default().fg(theme.detail_fg)),
        Span::styled(value.to_string(), Style::default().fg(value_style).add_modifier(Modifier::BOLD)),
    ]));
}

fn truncate(s: &str, max: usize) -> &str {
    if s.chars().count() <= max {
        s
    } else {
        let end = s.char_indices().take(max).last().map(|(i, _)| i).unwrap_or(s.len());
        &s[..end]
    }
}

/// Naive word-wrap to a max column width for the detail panel.
fn wrap_text(text: &str, max: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw_line in text.lines() {
        if raw_line.starts_with("#") || raw_line.starts_with("-") || raw_line.starts_with("```") {
            // keep structural lines intact but trimmed
            out.push(raw_line.trim().to_string());
            continue;
        }
        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            if current.is_empty() {
                current = word.to_string();
            } else if current.chars().count() + 1 + word.chars().count() <= max {
                current.push(' ');
                current.push_str(word);
            } else {
                out.push(current.clone());
                current = word.to_string();
            }
        }
        if !current.is_empty() || raw_line.trim().is_empty() {
            out.push(current);
        }
    }
    out
}

/// Inline "Vulnerabilities (N)" section for the Components/Dependencies detail
/// panel — lists matching CVEs with severity + reach/priority markers.
fn render_component_vulns(
    lines: &mut Vec<Line<'static>>,
    store: &BomStore,
    c: &Component,
    theme: &Theme,
) {
    if store.total_vulnerabilities == 0 {
        return;
    }
    let key = c.purl.as_deref().or(c.bom_ref.as_deref()).unwrap_or("");
    let vulns = store.vulns_for_component(key);
    if vulns.is_empty() {
        return;
    }

    lines.push(section_header(&format!("Vulnerabilities ({})", vulns.len()), theme));
    for v in vulns.iter().take(30) {
        let sev = v.severity();
        let col = theme.severity_color(sev);
        let mut prefix = String::new();
        if v.is_prioritized() {
            prefix.push('⚑');
        }
        if v.any_reachability() {
            prefix.push('⚡');
        }
        if !prefix.is_empty() {
            prefix.push(' ');
        }
        let mut spans: Vec<Span<'static>> = vec![
            Span::styled(format!("  {}{:20}", prefix, v.id_display()), Style::default().fg(col)),
            Span::styled(format!(" {:9}", sev), Style::default().fg(col).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" {:.1}", v.max_score()), Style::default().fg(col)),
        ];
        if v.is_exploitable() {
            spans.push(Span::styled(" exploitable", Style::default().fg(theme.error).add_modifier(Modifier::BOLD)));
        }
        if let Some(fix) = {
            let f = v.fix_version();
            if f == "-" { None } else { Some(f) }
        } {
            spans.push(Span::styled(format!("  → {}", fix), accent(theme)));
        }
        lines.push(Line::from(spans));
    }
    if vulns.len() > 30 {
        lines.push(Line::from(vec![Span::styled(
            format!("  … and {} more", vulns.len() - 30),
            dim("", theme),
        )]));
    }
    lines.push(Line::from(""));
}
