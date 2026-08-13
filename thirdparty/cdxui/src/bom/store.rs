use crate::bom::schema::*;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BomFile {
    pub bom: Bom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Type,
    Name,
    Version,
    Purl,
    License,
    VulnCount,
    MaxSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

impl SortOrder {
    pub fn toggle(self) -> Self {
        match self {
            SortOrder::Ascending => SortOrder::Descending,
            SortOrder::Descending => SortOrder::Ascending,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub query: String,
    pub component_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ComponentRow {
    pub component: Component,
}

impl ComponentRow {
    pub fn type_display(&self) -> &str {
        &self.component.component_type
    }

    pub fn name_display(&self) -> &str {
        self.component.name.as_deref().unwrap_or("-")
    }

    pub fn version_display(&self) -> &str {
        self.component.version.as_deref().unwrap_or("-")
    }

    pub fn purl_display(&self) -> &str {
        self.component.purl.as_deref().unwrap_or("-")
    }

    pub fn license_display(&self) -> String {
        self.component
            .licenses
            .as_ref()
            .and_then(|licenses| {
                licenses.first().and_then(|lc| {
                    lc.expression
                        .clone()
                        .or_else(|| lc.license.as_ref().and_then(|l| l.id.clone()))
                        .or_else(|| lc.license.as_ref().and_then(|l| l.name.clone()))
                })
            })
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn bom_ref_display(&self) -> &str {
        self.component.bom_ref.as_deref().unwrap_or("-")
    }

    pub fn description_display(&self) -> &str {
        self.component.description.as_deref().unwrap_or("-")
    }

    pub fn crypto_algorithm(&self) -> Option<String> {
        self.component.crypto_properties.as_ref().and_then(|cp| {
            cp.algorithm_properties
                .as_ref()
                .and_then(|ap| ap.primitive.clone())
        })
    }

    pub fn matches_query(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.name_display().to_lowercase().contains(&q)
            || self.type_display().to_lowercase().contains(&q)
            || self.version_display().to_lowercase().contains(&q)
            || self.purl_display().to_lowercase().contains(&q)
            || self.license_display().to_lowercase().contains(&q)
            || self.bom_ref_display().to_lowercase().contains(&q)
            || self.description_display().to_lowercase().contains(&q)
            || self
                .component
                .group
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains(&q)
            || self
                .crypto_algorithm()
                .unwrap_or_default()
                .to_lowercase()
                .contains(&q)
    }
}

#[derive(Debug, Clone)]
pub struct ServiceRow {
    pub service: Service,
}

impl ServiceRow {
    pub fn name_display(&self) -> &str {
        self.service.name.as_deref().unwrap_or("-")
    }

    pub fn endpoints_display(&self) -> String {
        self.service
            .endpoints
            .as_ref()
            .map(|eps| eps.join(", "))
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn authenticated_display(&self) -> &str {
        match self.service.authenticated {
            Some(true) => "yes",
            Some(false) => "no",
            None => "-",
        }
    }

    pub fn description_display(&self) -> &str {
        self.service.description.as_deref().unwrap_or("-")
    }

    pub fn bom_ref_display(&self) -> &str {
        self.service.bom_ref.as_deref().unwrap_or("-")
    }

    pub fn matches_query(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.name_display().to_lowercase().contains(&q)
            || self.endpoints_display().to_lowercase().contains(&q)
            || self.description_display().to_lowercase().contains(&q)
            || self.bom_ref_display().to_lowercase().contains(&q)
    }
}

fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Strip Rich markup `[...]` and `:emoji:` tokens from an insight label.
fn strip_rich(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' {
            // skip until matching ]
            for ic in chars.by_ref() {
                if ic == ']' {
                    break;
                }
            }
        } else if c == ':' {
            // skip a :token: if it looks like an emoji token
            let rest: String = chars.clone().collect();
            if let Some(end) = rest.find(':') {
                let token = &rest[..end];
                let is_emoji = !token.is_empty()
                    && token
                        .chars()
                        .all(|t| t.is_alphanumeric() || t == '_' || t == '+' || t == '-');
                if is_emoji {
                    for _ in 0..end {
                        chars.next();
                    }
                    chars.next(); // consume trailing ':'
                    continue;
                }
            }
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// Derive a short display name (namespace/name) from a purl.
fn purl_display_name(purl: &str) -> String {
    let no_qual = purl.split('?').next().unwrap_or(purl);
    let no_ver = match no_qual.find('@') {
        Some(i) => &no_qual[..i],
        None => no_qual,
    };
    match no_ver.find('/') {
        Some(slash) => no_ver[slash + 1..].to_string(),
        None => no_ver.to_string(),
    }
}

/// Candidate lookup keys for a component purl, most specific first: full,
/// then without `?qualifiers`, then without `@version`. Used when *querying*
/// the vuln index for a component.
fn purl_keys(purl: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let full = purl.to_string();
    keys.push(full.clone());
    let no_qual = purl.split('?').next().unwrap_or(purl).to_string();
    if no_qual != full {
        keys.push(no_qual.clone());
    }
    let no_ver = match no_qual.find('@') {
        Some(i) => no_qual[..i].to_string(),
        None => no_qual.clone(),
    };
    if no_ver != no_qual {
        keys.push(no_ver);
    }
    keys
}

/// Keys under which a *vulnerability's* affected purl is indexed. dep-scan
/// already scopes each VDR entry to an installed component, so the affected
/// ref is a real purl. We index at the granularity the ref actually carries:
/// a versioned ref only under its exact (full + no-qualifier) forms, so it can
/// never leak onto a *different* version of the same package via a shared
/// name-only key; a version-less ref collapses to its name form, which still
/// matches the installed versioned component on lookup.
fn purl_index_keys(purl: &str) -> Vec<String> {
    let full = purl.to_string();
    let no_qual = purl.split('?').next().unwrap_or(purl).to_string();
    if no_qual != full {
        vec![full, no_qual]
    } else {
        vec![full]
    }
}

#[derive(Debug, Clone)]
pub struct VulnerabilityRow {
    pub vuln: Vulnerability,
}

impl VulnerabilityRow {
    pub fn id_display(&self) -> &str {
        self.vuln.id.as_deref().unwrap_or("-")
    }

    pub fn bom_ref_display(&self) -> &str {
        self.vuln.bom_ref.as_deref().unwrap_or("-")
    }

    /// Highest-severity rating across all ratings (by rank, then score).
    pub fn severity(&self) -> &str {
        let mut best_rank = 0u8;
        let mut best: &str = "none";
        if let Some(ratings) = &self.vuln.ratings {
            for r in ratings {
                if let Some(sev) = &r.severity {
                    let rank = severity_rank(sev);
                    if rank >= best_rank {
                        best_rank = rank;
                        best = sev.as_str();
                    }
                }
            }
        }
        best
    }

    pub fn severity_rank(&self) -> u8 {
        severity_rank(self.severity())
    }

    pub fn max_score(&self) -> f64 {
        self.vuln
            .ratings
            .as_ref()
            .and_then(|rs| {
                rs.iter()
                    .filter_map(|r| r.score)
                    .fold(None::<f64>, |acc, s| Some(acc.map_or(s, |a: f64| a.max(s))))
            })
            .unwrap_or(0.0)
    }

    pub fn method(&self) -> &str {
        self.vuln
            .ratings
            .as_ref()
            .and_then(|rs| rs.first())
            .and_then(|r| r.method.as_deref())
            .unwrap_or("-")
    }

    pub fn affects_purl(&self) -> Option<&str> {
        self.vuln
            .affects
            .as_ref()
            .and_then(|affects| affects.first())
            .map(|a| a.ref_field.as_str())
    }

    pub fn package_name(&self) -> String {
        match self.affects_purl() {
            Some(p) => purl_display_name(p),
            None => self.vuln.id.clone().unwrap_or_else(|| "-".to_string()),
        }
    }

    /// The `unaffected` (fix) version from affects, if present.
    pub fn fix_version(&self) -> String {
        if let Some(affects) = &self.vuln.affects {
            for a in affects {
                if let Some(versions) = &a.versions {
                    for v in versions {
                        if v.status.as_deref() == Some("unaffected")
                            && let Some(ver) = &v.version
                        {
                            return ver.clone();
                        }
                    }
                }
            }
        }
        "-".to_string()
    }

    /// Parsed, cleaned labels from the `depscan:insights` property.
    pub fn insight_labels(&self) -> Vec<String> {
        let raw = self
            .vuln
            .properties
            .as_ref()
            .and_then(|props| {
                props
                    .iter()
                    .find(|p| p.name.as_deref() == Some("depscan:insights"))
            })
            .and_then(|p| p.value.clone())
            .unwrap_or_default();
        if raw.is_empty() {
            return Vec::new();
        }
        // dep-scan emits a literal "\n" (backslash-n) separator; also accept real newlines.
        let normalized = raw.replace("\\n", "\n");
        normalized
            .split('\n')
            .map(|s| strip_rich(s.trim()))
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn is_prioritized(&self) -> bool {
        self.vuln
            .properties
            .as_ref()
            .and_then(|props| {
                props
                    .iter()
                    .find(|p| p.name.as_deref() == Some("depscan:prioritized"))
            })
            .and_then(|p| p.value.as_deref())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    pub fn is_endpoint_reachable(&self) -> bool {
        self.insight_labels()
            .iter()
            .any(|l| l.to_lowercase().contains("endpoint"))
    }

    pub fn is_reachable(&self) -> bool {
        self.insight_labels().iter().any(|l| {
            let l = l.to_lowercase();
            l.contains("reachable") && !l.contains("endpoint")
        })
    }

    pub fn any_reachability(&self) -> bool {
        self.is_reachable() || self.is_endpoint_reachable()
    }

    /// Number of call sites the reachability engine attributed to this vuln,
    /// parsed from a `"Used in N locations"` insight label. `None` when absent.
    pub fn used_in_locations(&self) -> Option<u32> {
        self.insight_labels().iter().find_map(|l| {
            let low = l.to_lowercase();
            if !low.contains("used in") || !low.contains("location") {
                return None;
            }
            l.split_whitespace().find_map(|tok| tok.parse::<u32>().ok())
        })
    }

    pub fn is_exploitable(&self) -> bool {
        if self
            .vuln
            .analysis
            .as_ref()
            .and_then(|a| a.state.as_deref())
            .map(|s| s.eq_ignore_ascii_case("exploitable"))
            .unwrap_or(false)
        {
            return true;
        }
        self.insight_labels().iter().any(|l| {
            let l = l.to_lowercase();
            l.contains("exploit") || l == "exploitable"
        })
    }

    pub fn matches_query(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.id_display().to_lowercase().contains(&q)
            || self.package_name().to_lowercase().contains(&q)
            || self.severity().to_lowercase().contains(&q)
            || self.bom_ref_display().to_lowercase().contains(&q)
            || self
                .insight_labels()
                .iter()
                .any(|l| l.to_lowercase().contains(&q))
            || self
                .vuln
                .description
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains(&q)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnSortField {
    Priority,
    Id,
    Severity,
    Score,
    Reach,
    Package,
    Fix,
}

impl VulnSortField {
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            VulnSortField::Priority => "Priority",
            VulnSortField::Id => "Id",
            VulnSortField::Severity => "Severity",
            VulnSortField::Score => "CVSS",
            VulnSortField::Reach => "Reach",
            VulnSortField::Package => "Package",
            VulnSortField::Fix => "Fix",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VulnFilter {
    #[default]
    All,
    Prioritized,
    Reachable,
    Exploitable,
    CriticalHigh,
}

impl VulnFilter {
    pub fn next(self) -> Self {
        match self {
            VulnFilter::All => VulnFilter::Prioritized,
            VulnFilter::Prioritized => VulnFilter::Reachable,
            VulnFilter::Reachable => VulnFilter::Exploitable,
            VulnFilter::Exploitable => VulnFilter::CriticalHigh,
            VulnFilter::CriticalHigh => VulnFilter::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            VulnFilter::All => "All",
            VulnFilter::Prioritized => "Prioritized",
            VulnFilter::Reachable => "Reachable",
            VulnFilter::Exploitable => "Exploitable",
            VulnFilter::CriticalHigh => "Critical/High",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PurlVulnSummary {
    pub count: usize,
    pub max_severity_rank: u8,
    pub max_score: f64,
    pub prioritized: bool,
    pub reachable: bool,
    pub exploitable: bool,
    pub display_name: String,
}

impl Default for PurlVulnSummary {
    fn default() -> Self {
        Self {
            count: 0,
            max_severity_rank: 0,
            max_score: 0.0,
            prioritized: false,
            reachable: false,
            exploitable: false,
            display_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecuritySummary {
    pub total_vulns: usize,
    /// Indexed by severity rank: [0]=none, [1]=low, [2]=medium, [3]=high, [4]=critical
    pub severity_counts: [usize; 5],
    pub prioritized_vulns: usize,
    pub reachable_vulns: usize,
    pub endpoint_reachable_vulns: usize,
    pub exploitable_vulns: usize,
    pub reachable_exploitable_vulns: usize,
    pub vulnerable_components: usize,
    pub total_components: usize,
    pub top_by_count: Vec<(String, PurlVulnSummary)>,
    pub top_by_reach_exploit: Vec<(String, PurlVulnSummary)>,
}

impl SecuritySummary {
    /// Severity counts paired with their label, ordered highest-severity first.
    /// Single source of truth for the dashboard so the label↔count mapping
    /// cannot silently invert (regression guard for the rank-indexing bug).
    pub fn severity_display(&self) -> [(&'static str, usize); 5] {
        [
            ("critical", self.severity_counts[4]),
            ("high", self.severity_counts[3]),
            ("medium", self.severity_counts[2]),
            ("low", self.severity_counts[1]),
            ("none", self.severity_counts[0]),
        ]
    }
}

/// Tolerant purl/bom-ref lookup against a vuln aggregation map (free fn so it
/// can be borrowed disjointly inside a sort closure).
fn summary_for_purl<'a>(
    map: &'a HashMap<String, PurlVulnSummary>,
    purl_or_ref: &str,
) -> Option<&'a PurlVulnSummary> {
    if purl_or_ref.is_empty() {
        return None;
    }
    for key in purl_keys(purl_or_ref) {
        if let Some(s) = map.get(&key) {
            return Some(s);
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct BomStore {
    pub bom_files: Vec<BomFile>,
    pub components: Vec<ComponentRow>,
    pub crypto_assets: Vec<usize>,
    pub services: Vec<ServiceRow>,
    pub filtered_component_indices: Vec<usize>,
    pub filtered_service_indices: Vec<usize>,
    pub current_filter: FilterState,
    pub sort_field: SortField,
    pub sort_order: SortOrder,
    pub total_components: usize,
    pub total_services: usize,
    pub total_crypto: usize,
    pub total_formulas: usize,
    pub total_dependencies: usize,
    pub total_vulnerabilities: usize,
    pub vulnerabilities: Vec<VulnerabilityRow>,
    pub filtered_vulnerability_indices: Vec<usize>,
    pub vuln_sort_field: VulnSortField,
    pub vuln_sort_order: SortOrder,
    pub vuln_filter: VulnFilter,
    pub vuln_by_purl: HashMap<String, PurlVulnSummary>,
    pub security_summary: SecuritySummary,
    pub loaded: bool,
}

impl BomStore {
    pub fn new() -> Self {
        Self {
            bom_files: Vec::new(),
            components: Vec::new(),
            crypto_assets: Vec::new(),
            services: Vec::new(),
            filtered_component_indices: Vec::new(),
            filtered_service_indices: Vec::new(),
            current_filter: FilterState::default(),
            sort_field: SortField::Name,
            sort_order: SortOrder::Ascending,
            total_components: 0,
            total_services: 0,
            total_crypto: 0,
            total_formulas: 0,
            total_dependencies: 0,
            total_vulnerabilities: 0,
            vulnerabilities: Vec::new(),
            filtered_vulnerability_indices: Vec::new(),
            vuln_sort_field: VulnSortField::Priority,
            vuln_sort_order: SortOrder::Descending,
            vuln_filter: VulnFilter::All,
            vuln_by_purl: HashMap::new(),
            security_summary: SecuritySummary::default(),
            loaded: false,
        }
    }

    pub fn load_path(&mut self, path: &Path) -> Result<usize, LoadError> {
        if path.is_dir() {
            let count = self.load_directory(path)?;
            self.merge_duplicates();
            Ok(count)
        } else if path.is_file() {
            let n = self.load_file(path)?;
            self.merge_duplicates();
            Ok(n)
        } else {
            Err(LoadError::NotFound(path.to_path_buf()))
        }
    }

    fn load_file(&mut self, path: &Path) -> Result<usize, LoadError> {
        let content = fs::read_to_string(path).map_err(|e| LoadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let bom: Bom = serde_json::from_str(&content).map_err(|e| LoadError::Parse {
            path: path.to_path_buf(),
            source: e,
        })?;

        let bom_ref = BomFile { bom };
        self.index_bom(&bom_ref);
        self.bom_files.push(bom_ref);
        self.rebuild_filtered_indices();
        self.loaded = true;
        Ok(1)
    }

    fn load_directory(&mut self, dir: &Path) -> Result<usize, LoadError> {
        let mut count = 0;
        let entries = fs::read_dir(dir).map_err(|e| LoadError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| LoadError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?;
            let path = entry.path();
            if path.is_file()
                && let Some(ext) = path.extension()
                && (ext == "json" || ext == "cdx")
            {
                match self.load_file(&path) {
                    Ok(n) => count += n,
                    Err(e) => eprintln!("Warning: skipping {}: {}", path.display(), e),
                }
            }
        }

        if count == 0 {
            return Err(LoadError::NoBomFiles(dir.to_path_buf()));
        }

        Ok(count)
    }

    fn merge_duplicates(&mut self) {
        if self.bom_files.len() < 2 {
            return;
        }

        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut merged = Vec::new();
        let mut crypto_merged = Vec::new();
        let mut old_to_new: HashMap<usize, usize> = HashMap::new();

        for (i, comp) in self.components.iter().enumerate() {
            let key = comp
                .component
                .purl
                .clone()
                .or_else(|| comp.component.bom_ref.clone())
                .unwrap_or_else(|| {
                    format!(
                        "{}:{}:{}",
                        comp.component.component_type,
                        comp.name_display(),
                        comp.version_display()
                    )
                });

            if let Some(&existing_idx) = seen.get(&key) {
                let existing: &mut ComponentRow = &mut merged[existing_idx];
                merge_component_properties(&mut existing.component, &comp.component);
                old_to_new.insert(i, existing_idx);
            } else {
                let new_idx = merged.len();
                seen.insert(key, new_idx);
                old_to_new.insert(i, new_idx);
                merged.push(comp.clone());
            }
        }

        let old_crypto: Vec<usize> = self.crypto_assets.clone();
        for &old_idx in &old_crypto {
            if let Some(&new_idx) = old_to_new.get(&old_idx)
                && !crypto_merged.contains(&new_idx)
            {
                crypto_merged.push(new_idx);
            }
        }

        self.components = merged;
        self.crypto_assets = crypto_merged;
        self.total_components = self.components.len();
        self.total_crypto = self.crypto_assets.len();
        // Components changed by dedup; refresh the vuln aggregates (vulnerable
        // component count depends on the merged component list).
        self.compute_vuln_aggregates();
        self.rebuild_filtered_indices();
    }

    fn index_bom(&mut self, bom_file: &BomFile) {
        let bom = &bom_file.bom;

        if let Some(ref components) = bom.components {
            for component in components.iter() {
                let row = ComponentRow {
                    component: component.clone(),
                };
                if component.component_type == "cryptographic-asset" {
                    self.crypto_assets.push(self.components.len());
                }
                self.components.push(row);
            }
        }

        if let Some(ref services) = bom.services {
            for service in services.iter() {
                let row = ServiceRow {
                    service: service.clone(),
                };
                self.services.push(row);
            }
        }

        self.total_components = self.components.len();
        self.total_services = self.services.len();
        self.total_crypto = self.crypto_assets.len();
        self.total_formulas = bom.formulation.as_ref().map(|f| f.len()).unwrap_or(0);
        self.total_dependencies = bom.dependencies.as_ref().map(|d| d.len()).unwrap_or(0);

        if let Some(ref vulns) = bom.vulnerabilities {
            let existing: std::collections::HashSet<String> = self
                .vulnerabilities
                .iter()
                .filter_map(|r| r.vuln.bom_ref.clone())
                .collect();
            for v in vulns.iter() {
                let key = v.bom_ref.clone().unwrap_or_else(|| {
                    format!(
                        "{}/{}",
                        v.id.as_deref().unwrap_or("?"),
                        v.affects
                            .as_ref()
                            .and_then(|a| a.first())
                            .map(|a| a.ref_field.as_str())
                            .unwrap_or("?")
                    )
                });
                if existing.contains(&key) {
                    continue;
                }
                self.vulnerabilities
                    .push(VulnerabilityRow { vuln: v.clone() });
            }
        }
        self.total_vulnerabilities = self.vulnerabilities.len();
        self.compute_vuln_aggregates();
    }

    /// Build the `vuln_by_purl` aggregation map and the `SecuritySummary`
    /// from the indexed vulnerabilities. Called once per load/index — never
    /// per row or per frame.
    fn compute_vuln_aggregates(&mut self) {
        self.vuln_by_purl.clear();
        let mut summary = SecuritySummary {
            total_vulns: self.vulnerabilities.len(),
            ..Default::default()
        };

        for row in &self.vulnerabilities {
            let rank = row.severity_rank();
            let sev_idx = (rank as usize).min(4);
            summary.severity_counts[sev_idx] += 1;
            if row.is_prioritized() {
                summary.prioritized_vulns += 1;
            }
            let reach = row.any_reachability();
            if reach {
                summary.reachable_vulns += 1;
            }
            if row.is_endpoint_reachable() {
                summary.endpoint_reachable_vulns += 1;
            }
            if row.is_exploitable() {
                summary.exploitable_vulns += 1;
            }
            if reach && row.is_exploitable() {
                summary.reachable_exploitable_vulns += 1;
            }

            if let Some(purl) = row.affects_purl() {
                let display = purl_display_name(purl);
                for key in purl_index_keys(purl) {
                    let entry = self.vuln_by_purl.entry(key).or_default();
                    entry.count += 1;
                    if rank > entry.max_severity_rank {
                        entry.max_severity_rank = rank;
                    }
                    let score = row.max_score();
                    if score > entry.max_score {
                        entry.max_score = score;
                    }
                    entry.prioritized |= row.is_prioritized();
                    entry.reachable |= reach;
                    entry.exploitable |= row.is_exploitable();
                    if entry.display_name.is_empty() {
                        entry.display_name = display.clone();
                    }
                }
            }
        }

        summary.total_components = self.total_components;
        summary.vulnerable_components = self.count_vulnerable_components();

        // Deduplicate by package display name (a package is indexed under
        // multiple key forms, so `vuln_by_purl.values()` repeats it).
        let mut by_name: HashMap<&str, &PurlVulnSummary> = HashMap::new();
        for s in self.vuln_by_purl.values() {
            by_name
                .entry(s.display_name.as_str())
                .and_modify(|cur| {
                    if s.count > cur.count {
                        *cur = s;
                    }
                })
                .or_insert(s);
        }
        let unique: Vec<&PurlVulnSummary> = by_name.into_values().collect();

        let sev_score_cmp = |a: &PurlVulnSummary, b: &PurlVulnSummary| {
            b.max_severity_rank
                .cmp(&a.max_severity_rank)
                .then_with(|| {
                    b.max_score
                        .partial_cmp(&a.max_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.display_name.cmp(&b.display_name))
        };

        // Top packages by CVE count.
        let mut by_count = unique.clone();
        by_count.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| sev_score_cmp(a, b)));
        summary.top_by_count = by_count
            .iter()
            .take(8)
            .map(|s| (s.display_name.clone(), (*s).clone()))
            .collect();

        // Top packages by reachable/exploitable vulns.
        let mut by_reach: Vec<&PurlVulnSummary> = unique
            .into_iter()
            .filter(|s| s.reachable || s.exploitable)
            .collect();
        by_reach.sort_by(|a, b| {
            let a_flags = (a.reachable as u8) + (a.exploitable as u8);
            let b_flags = (b.reachable as u8) + (b.exploitable as u8);
            b_flags.cmp(&a_flags).then_with(|| sev_score_cmp(a, b))
        });
        summary.top_by_reach_exploit = by_reach
            .iter()
            .take(8)
            .map(|s| (s.display_name.clone(), (*s).clone()))
            .collect();

        self.security_summary = summary;
    }

    fn count_vulnerable_components(&self) -> usize {
        let mut count = 0usize;
        for row in &self.components {
            let key = row.component.purl.as_deref().unwrap_or("");
            if !key.is_empty() && self.vuln_summary_for(key).is_some() {
                count += 1;
                continue;
            }
            // fall back to bom-ref
            let bref = row.component.bom_ref.as_deref().unwrap_or("");
            if !bref.is_empty() && self.vuln_summary_for(bref).is_some() {
                count += 1;
            }
        }
        count
    }

    pub fn search_components(&mut self, query: &str) {
        self.current_filter.query = query.to_string();
        self.rebuild_filtered_indices();
    }

    fn rebuild_filtered_indices(&mut self) {
        self.filtered_component_indices = self
            .components
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                let query_match = row.matches_query(&self.current_filter.query);
                let type_match = self
                    .current_filter
                    .component_type
                    .as_ref()
                    .map(|t| row.component.component_type == *t)
                    .unwrap_or(true);
                query_match && type_match
            })
            .map(|(i, _)| i)
            .collect();

        self.filtered_service_indices = self
            .services
            .iter()
            .enumerate()
            .filter(|(_, row)| row.matches_query(&self.current_filter.query))
            .map(|(i, _)| i)
            .collect();

        self.filtered_vulnerability_indices = self
            .vulnerabilities
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                let query_match = row.matches_query(&self.current_filter.query);
                let filter_match = match self.vuln_filter {
                    VulnFilter::All => true,
                    VulnFilter::Prioritized => row.is_prioritized(),
                    VulnFilter::Reachable => row.any_reachability(),
                    VulnFilter::Exploitable => row.is_exploitable(),
                    VulnFilter::CriticalHigh => row.severity_rank() >= 3,
                };
                query_match && filter_match
            })
            .map(|(i, _)| i)
            .collect();

        self.sort_filtered();
        self.sort_vulnerabilities();
    }

    pub fn sort_filtered(&mut self) {
        match self.sort_field {
            SortField::Name => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .name_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].name_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::Type => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .type_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].type_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::Version => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .version_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].version_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::Purl => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .purl_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].purl_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::License => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .license_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].license_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::VulnCount => {
                let map = &self.vuln_by_purl;
                self.filtered_component_indices.sort_by(|a, b| {
                    let ca = self.components[*a]
                        .component
                        .purl
                        .as_deref()
                        .or_else(|| self.components[*a].component.bom_ref.as_deref())
                        .and_then(|p| summary_for_purl(map, p))
                        .map_or(0usize, |s| s.count);
                    let cb = self.components[*b]
                        .component
                        .purl
                        .as_deref()
                        .or_else(|| self.components[*b].component.bom_ref.as_deref())
                        .and_then(|p| summary_for_purl(map, p))
                        .map_or(0usize, |s| s.count);
                    let cmp = cb.cmp(&ca);
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::MaxSeverity => {
                let map = &self.vuln_by_purl;
                self.filtered_component_indices.sort_by(|a, b| {
                    let ra = self.components[*a]
                        .component
                        .purl
                        .as_deref()
                        .or_else(|| self.components[*a].component.bom_ref.as_deref())
                        .and_then(|p| summary_for_purl(map, p))
                        .map_or(0u8, |s| s.max_severity_rank);
                    let rb = self.components[*b]
                        .component
                        .purl
                        .as_deref()
                        .or_else(|| self.components[*b].component.bom_ref.as_deref())
                        .and_then(|p| summary_for_purl(map, p))
                        .map_or(0u8, |s| s.max_severity_rank);
                    let cmp = rb.cmp(&ra);
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
        }
    }

    pub fn cycle_sort(&mut self) {
        self.sort_field = match self.sort_field {
            SortField::Type => SortField::Name,
            SortField::Name => SortField::Version,
            SortField::Version => SortField::Purl,
            SortField::Purl => SortField::License,
            SortField::License => SortField::VulnCount,
            SortField::VulnCount => SortField::MaxSeverity,
            SortField::MaxSeverity => SortField::Type,
        };
        if matches!(self.sort_field, SortField::Type) {
            self.sort_order = self.sort_order.toggle();
        }
        self.sort_filtered();
    }

    pub fn set_sort(&mut self, field: SortField) {
        if self.sort_field == field {
            self.sort_order = self.sort_order.toggle();
        } else {
            self.sort_field = field;
            self.sort_order = SortOrder::Ascending;
        }
        self.sort_filtered();
    }

    pub fn sort_vulnerabilities(&mut self) {
        let order = self.vuln_sort_order;
        let field = self.vuln_sort_field;
        self.filtered_vulnerability_indices.sort_by(|a, b| {
            let ra = &self.vulnerabilities[*a];
            let rb = &self.vulnerabilities[*b];
            // Default tie-breakers always applied in this order.
            let base = ra
                .is_prioritized()
                .cmp(&rb.is_prioritized())
                .then_with(|| rb.severity_rank().cmp(&ra.severity_rank()))
                .then_with(|| {
                    rb.max_score()
                        .partial_cmp(&ra.max_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            let primary = match field {
                VulnSortField::Priority => ra.is_prioritized().cmp(&rb.is_prioritized()),
                VulnSortField::Id => ra
                    .id_display()
                    .to_lowercase()
                    .cmp(&rb.id_display().to_lowercase()),
                VulnSortField::Severity => rb.severity_rank().cmp(&ra.severity_rank()),
                VulnSortField::Score => rb
                    .max_score()
                    .partial_cmp(&ra.max_score())
                    .unwrap_or(std::cmp::Ordering::Equal),
                VulnSortField::Reach => {
                    let av = ra.any_reachability() as u8 + (ra.is_endpoint_reachable() as u8);
                    let bv = rb.any_reachability() as u8 + (rb.is_endpoint_reachable() as u8);
                    bv.cmp(&av)
                }
                VulnSortField::Package => ra
                    .package_name()
                    .to_lowercase()
                    .cmp(&rb.package_name().to_lowercase()),
                VulnSortField::Fix => ra.fix_version().cmp(&rb.fix_version()),
            };

            match field {
                // For the columns that already encode "higher is riskier",
                // ascending vs descending flips naturally.
                VulnSortField::Priority
                | VulnSortField::Severity
                | VulnSortField::Score
                | VulnSortField::Reach => {
                    if order == SortOrder::Ascending {
                        primary.reverse().then(base)
                    } else {
                        primary.then(base)
                    }
                }
                _ => {
                    if order == SortOrder::Ascending {
                        primary.then(base)
                    } else {
                        primary.reverse().then(base)
                    }
                }
            }
        });
    }

    pub fn cycle_vuln_sort(&mut self) {
        self.vuln_sort_field = match self.vuln_sort_field {
            VulnSortField::Priority => VulnSortField::Id,
            VulnSortField::Id => VulnSortField::Severity,
            VulnSortField::Severity => VulnSortField::Score,
            VulnSortField::Score => VulnSortField::Reach,
            VulnSortField::Reach => VulnSortField::Package,
            VulnSortField::Package => VulnSortField::Fix,
            VulnSortField::Fix => VulnSortField::Priority,
        };
        self.vuln_sort_order = self.vuln_sort_order.toggle();
        self.sort_vulnerabilities();
    }

    pub fn set_vuln_sort(&mut self, field: VulnSortField) {
        if self.vuln_sort_field == field {
            self.vuln_sort_order = self.vuln_sort_order.toggle();
        } else {
            self.vuln_sort_field = field;
            self.vuln_sort_order = SortOrder::Descending;
        }
        self.sort_vulnerabilities();
    }

    #[allow(dead_code)]
    pub fn set_vuln_filter(&mut self, filter: VulnFilter) {
        self.vuln_filter = filter;
        self.rebuild_filtered_indices();
    }

    pub fn cycle_vuln_filter(&mut self) {
        self.vuln_filter = self.vuln_filter.next();
        self.rebuild_filtered_indices();
    }

    pub fn filtered_vulnerability(&self, idx: usize) -> Option<&VulnerabilityRow> {
        self.filtered_vulnerability_indices
            .get(idx)
            .and_then(|&i| self.vulnerabilities.get(i))
    }

    pub fn filtered_vulnerabilities_count(&self) -> usize {
        self.filtered_vulnerability_indices.len()
    }

    /// Tolerant purl/bom-ref lookup against the prebuilt vuln aggregation map.
    pub fn vuln_summary_for(&self, purl_or_ref: &str) -> Option<&PurlVulnSummary> {
        if purl_or_ref.is_empty() {
            return None;
        }
        for key in purl_keys(purl_or_ref) {
            if let Some(s) = self.vuln_by_purl.get(&key) {
                return Some(s);
            }
        }
        None
    }

    /// Individual vulnerabilities affecting a component (purl/bom-ref).
    /// Used only by the detail panel for the *selected* component — not per row.
    pub fn vulns_for_component(&self, purl_or_ref: &str) -> Vec<&VulnerabilityRow> {
        if purl_or_ref.is_empty() {
            return Vec::new();
        }
        let keys: std::collections::HashSet<String> = purl_keys(purl_or_ref).into_iter().collect();
        let mut found: Vec<&VulnerabilityRow> = self
            .vulnerabilities
            .iter()
            .filter(|row| {
                row.affects_purl()
                    .is_some_and(|p| purl_keys(p).iter().any(|k| keys.contains(k)))
            })
            .collect();
        found.sort_by(|a, b| {
            b.severity_rank().cmp(&a.severity_rank()).then_with(|| {
                b.max_score()
                    .partial_cmp(&a.max_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        found
    }

    pub fn filtered_component(&self, idx: usize) -> Option<&ComponentRow> {
        self.filtered_component_indices
            .get(idx)
            .and_then(|&i| self.components.get(i))
    }

    pub fn filtered_service(&self, idx: usize) -> Option<&ServiceRow> {
        self.filtered_service_indices
            .get(idx)
            .and_then(|&i| self.services.get(i))
    }

    pub fn filtered_components_count(&self) -> usize {
        self.filtered_component_indices.len()
    }

    pub fn filtered_services_count(&self) -> usize {
        self.filtered_service_indices.len()
    }

    pub fn formula_count(&self) -> usize {
        self.bom_files
            .iter()
            .flat_map(|bf| bf.bom.formulation.as_ref())
            .map(|f| f.len())
            .sum()
    }

    pub fn component_type_counts(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for row in &self.components {
            *counts
                .entry(row.component.component_type.clone())
                .or_insert(0) += 1;
        }
        let mut result: Vec<(String, usize)> = counts.into_iter().collect();
        result.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        result
    }

    pub fn set_type_filter(&mut self, component_type: Option<String>) {
        self.current_filter.component_type = component_type;
        self.rebuild_filtered_indices();
    }

    pub fn resolve_bom_ref(&self, ref_field: &str) -> String {
        for row in &self.components {
            if row.component.bom_ref.as_deref() == Some(ref_field) {
                return format!("{} {}", row.name_display(), row.version_display());
            }
        }
        for row in &self.services {
            if row.service.bom_ref.as_deref() == Some(ref_field) {
                return row.name_display().to_string();
            }
        }
        if ref_field.len() > 80 {
            format!("{}…", &ref_field[..77])
        } else {
            ref_field.to_string()
        }
    }

    pub fn dependency_roots(&self) -> Vec<String> {
        let mut roots = Vec::new();
        let dep_children: std::collections::HashSet<String> = self
            .bom_files
            .iter()
            .flat_map(|bf| bf.bom.dependencies.as_deref().unwrap_or_default())
            .flat_map(|d| d.depends_on.as_deref().unwrap_or_default())
            .cloned()
            .collect();

        for bf in &self.bom_files {
            if let Some(ref deps) = bf.bom.dependencies {
                for d in deps {
                    if !dep_children.contains(&d.ref_field) {
                        roots.push(d.ref_field.clone());
                    }
                }
            }
        }
        roots
    }

    pub fn dependency_children(&self, ref_field: &str) -> Vec<String> {
        for bf in &self.bom_files {
            if let Some(ref deps) = bf.bom.dependencies {
                for d in deps {
                    if d.ref_field == ref_field {
                        return d.depends_on.clone().unwrap_or_default();
                    }
                }
            }
        }
        Vec::new()
    }

    pub fn all_dependencies(&self) -> Vec<&Dependency> {
        self.bom_files
            .iter()
            .flat_map(|bf| bf.bom.dependencies.as_deref().unwrap_or_default())
            .collect()
    }

    pub fn get_component_by_ref(&self, ref_field: &str) -> Option<(usize, &ComponentRow)> {
        self.components
            .iter()
            .enumerate()
            .find(|(_, row)| row.component.bom_ref.as_deref() == Some(ref_field))
    }

    pub fn file_count(&self) -> usize {
        self.bom_files.len()
    }

    pub fn sort_field_to_str(&self) -> Option<&'static str> {
        match self.sort_field {
            SortField::Type => Some("Type"),
            SortField::Name => Some("Name"),
            SortField::Version => Some("Version"),
            SortField::Purl => Some("Purl"),
            SortField::License => Some("License"),
            SortField::VulnCount => Some("CVE"),
            SortField::MaxSeverity => Some("Risk"),
        }
    }
}

fn merge_component_properties(existing: &mut Component, duplicate: &Component) {
    if let Some(ref dup_props) = duplicate.properties {
        let existing_props = existing.properties.get_or_insert_with(Vec::new);
        for prop in dup_props {
            let is_new = !existing_props
                .iter()
                .any(|p| p.name == prop.name && p.value == prop.value);
            if is_new {
                existing_props.push(prop.clone());
            }
        }
    }

    if let Some(ref dup_ev) = duplicate.evidence {
        if existing.evidence.is_none() && !is_evidence_empty(dup_ev) {
            existing.evidence = Some(dup_ev.clone());
        } else if let Some(ref existing_ev) = existing.evidence {
            let mut merged_ev = existing_ev.clone();
            if let Some(ref ids) = dup_ev.identity {
                let eids = merged_ev.identity.get_or_insert_with(Vec::new);
                for id in ids {
                    if !eids.iter().any(|e| e.field == id.field) {
                        eids.push(id.clone());
                    }
                }
            }
            if let Some(ref occs) = dup_ev.occurrences {
                let eoccs = merged_ev.occurrences.get_or_insert_with(Vec::new);
                for occ in occs {
                    if !eoccs.iter().any(|e| e.location == occ.location) {
                        eoccs.push(occ.clone());
                    }
                }
            }
            existing.evidence = Some(merged_ev);
        }
    }

    if let Some(ref dup_hashes) = duplicate.hashes {
        let existing_hashes = existing.hashes.get_or_insert_with(Vec::new);
        for h in dup_hashes {
            let is_new = !existing_hashes
                .iter()
                .any(|eh| eh.alg == h.alg && eh.content == h.content);
            if is_new {
                existing_hashes.push(h.clone());
            }
        }
    }

    if let Some(ref dup_refs) = duplicate.external_references {
        let existing_refs = existing.external_references.get_or_insert_with(Vec::new);
        for eref in dup_refs {
            let is_new = !existing_refs.iter().any(|e| e.url == eref.url);
            if is_new {
                existing_refs.push(eref.clone());
            }
        }
    }

    if let Some(ref dup_licenses) = duplicate.licenses {
        let existing_licenses = existing.licenses.get_or_insert_with(Vec::new);
        for lic in dup_licenses {
            let is_new = !existing_licenses.iter().any(|el| {
                el.expression == lic.expression
                    && el.license.as_ref().and_then(|l| l.id.as_deref())
                        == lic.license.as_ref().and_then(|l| l.id.as_deref())
            });
            if is_new {
                existing_licenses.push(lic.clone());
            }
        }
    }
}

fn is_evidence_empty(ev: &ComponentEvidence) -> bool {
    ev.identity.as_ref().is_none_or(|v| v.is_empty())
        && ev.occurrences.as_ref().is_none_or(|v| v.is_empty())
        && ev.licenses.as_ref().is_none_or(|v| v.is_empty())
        && ev.copyright.as_ref().is_none_or(|v| v.is_empty())
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("path not found: {0}")]
    NotFound(PathBuf),

    #[error("no BOM files found in directory: {0}")]
    NoBomFiles(PathBuf),

    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("JSON parse error in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl fmt::Display for SortField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortField::Type => write!(f, "Type"),
            SortField::Name => write!(f, "Name"),
            SortField::Version => write!(f, "Version"),
            SortField::Purl => write!(f, "Purl"),
            SortField::License => write!(f, "License"),
            SortField::VulnCount => write!(f, "CVE"),
            SortField::MaxSeverity => write!(f, "Risk"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_bom_json() -> &'static str {
        r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:test-123",
            "version": 1,
            "metadata": {
                "timestamp": "2025-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0"
                }
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:npm/express@4.18.0",
                    "name": "express",
                    "version": "4.18.0",
                    "purl": "pkg:npm/express@4.18.0",
                    "licenses": [{"license": {"id": "MIT"}}]
                },
                {
                    "type": "cryptographic-asset",
                    "bom-ref": "crypto:openssl-aes",
                    "name": "AES-256-GCM",
                    "version": "1.0",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "AES",
                            "mode": "GCM",
                            "cryptoFunctions": ["encrypt", "decrypt"]
                        }
                    }
                },
                {
                    "type": "container",
                    "bom-ref": "docker:alpine",
                    "name": "alpine",
                    "version": "3.19",
                    "purl": "pkg:docker/alpine@3.19"
                }
            ],
            "services": [
                {
                    "bom-ref": "svc:api",
                    "name": "api-gateway",
                    "endpoints": ["https://api.example.com", "https://api.internal.example.com"],
                    "authenticated": true,
                    "description": "API Gateway service"
                }
            ],
            "dependencies": [
                {"ref": "pkg:npm/express@4.18.0", "dependsOn": []},
                {"ref": "crypto:openssl-aes", "dependsOn": ["pkg:npm/express@4.18.0"]}
            ],
            "formulation": [
                {
                    "name": "build-pipeline",
                    "description": "CI/CD build pipeline",
                    "workflows": [
                        {
                            "uid": "wf-1",
                            "name": "build-and-test",
                            "tasks": [
                                {
                                    "uid": "task-1",
                                    "name": "compile",
                                    "steps": [
                                        {
                                            "name": "cargo build",
                                            "commands": [{"executed": "cargo build --release"}]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#
    }

    #[test]
    fn test_load_bom_from_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        let count = store.load_path(tmp.path()).unwrap();
        assert_eq!(count, 1);
        assert!(store.loaded);

        assert_eq!(store.total_components, 3);
        assert_eq!(store.total_services, 1);
        assert_eq!(store.total_crypto, 1);
        assert_eq!(store.total_formulas, 1);
        assert_eq!(store.total_dependencies, 2);
    }

    #[test]
    fn test_search_components() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.search_components("express");
        assert_eq!(store.filtered_components_count(), 1);

        store.search_components("alpine");
        assert_eq!(store.filtered_components_count(), 1);

        store.search_components("aes");
        assert_eq!(store.filtered_components_count(), 1);

        store.search_components("");
        assert_eq!(store.filtered_components_count(), 3);
    }

    #[test]
    fn test_search_services() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.search_components("gateway");
        assert_eq!(store.filtered_services_count(), 1);

        store.search_components("nonexistent");
        assert_eq!(store.filtered_services_count(), 0);
    }

    #[test]
    fn test_filter_by_type() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.set_type_filter(Some("library".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(Some("cryptographic-asset".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(None);
        assert_eq!(store.filtered_components_count(), 3);
    }

    #[test]
    fn test_sort_components() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.sort_field = SortField::Name;
        store.sort_order = SortOrder::Ascending;
        store.sort_filtered();

        let names: Vec<&str> = (0..store.filtered_components_count())
            .filter_map(|i| store.filtered_component(i).map(|r| r.name_display()))
            .collect();
        assert_eq!(names, vec!["AES-256-GCM", "alpine", "express"]);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let mut store = BomStore::new();
        let result = store.load_path(Path::new("/nonexistent/path/bom.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_component_type_counts() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let counts = store.component_type_counts();
        let library_count = counts
            .iter()
            .find(|(t, _)| t == "library")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        assert_eq!(library_count, 1);
    }

    #[test]
    fn test_crypto_asset_detection() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        assert_eq!(store.total_crypto, 1);
        assert_eq!(store.crypto_assets.len(), 1);

        let crypto_row = &store.components[store.crypto_assets[0]];
        assert_eq!(
            crypto_row
                .component
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.asset_type.clone()),
            Some("algorithm".to_string())
        );
        assert_eq!(crypto_row.crypto_algorithm().unwrap(), "AES");
    }

    #[test]
    fn test_load_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file1_path = dir.path().join("bom1.json");
        let file2_path = dir.path().join("bom2.json");
        std::fs::write(&file1_path, sample_bom_json()).unwrap();
        std::fs::write(&file2_path, sample_bom_json()).unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a bom").unwrap();

        let mut store = BomStore::new();
        let count = store.load_path(dir.path()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(store.total_components, 3); // merged duplicates
        assert_eq!(store.total_services, 2); // services not merged (no purl matching)
        assert_eq!(store.file_count(), 2);
    }

    #[test]
    fn test_load_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = BomStore::new();
        let result = store.load_path(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_cycle_sort() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        assert_eq!(store.sort_field, SortField::Name);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Version);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Purl);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::License);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::VulnCount);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::MaxSeverity);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Type);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Name);
    }

    #[test]
    fn test_dependency_roots_and_children() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let roots = store.dependency_roots();
        assert!(!roots.is_empty());
        let crypto_root = roots.iter().find(|r| r.contains("crypto:openssl-aes"));
        assert!(crypto_root.is_some());

        let children = store.dependency_children("crypto:openssl-aes");
        assert!(!children.is_empty());
        assert!(children.contains(&"pkg:npm/express@4.18.0".to_string()));
    }

    #[test]
    fn test_resolve_bom_ref() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let resolved = store.resolve_bom_ref("pkg:npm/express@4.18.0");
        assert!(resolved.contains("express"));
        assert!(resolved.contains("4.18.0"));

        let resolved = store.resolve_bom_ref("svc:api");
        assert!(resolved.contains("api-gateway"));
    }

    #[test]
    fn test_set_type_filter() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.set_type_filter(Some("library".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(Some("container".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(None);
        assert_eq!(store.filtered_components_count(), 3);
    }

    #[test]
    fn test_sort_field_to_str() {
        let store = BomStore::new();
        assert_eq!(store.sort_field_to_str(), Some("Name"));
    }

    #[test]
    fn test_get_component_by_ref() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let (_idx, row) = store
            .get_component_by_ref("pkg:npm/express@4.18.0")
            .unwrap();
        assert_eq!(row.name_display(), "express");

        assert!(store.get_component_by_ref("nonexistent").is_none());
    }

    #[test]
    fn test_merge_duplicate_components() {
        let json_a = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [
                {"type": "library", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0", "licenses": [{"license": {"id": "MIT"}}], "properties": [{"name": "SrcFile", "value": "file-a.lock"}]},
                {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
            ]
        }"#;
        let json_b = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [
                {"type": "library", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0", "licenses": [{"license": {"id": "Apache-2.0"}}], "properties": [{"name": "SrcFile", "value": "file-b.lock"}, {"name": "Namespaces", "value": "test"}], "hashes": [{"alg": "SHA-256", "content": "abc"}]},
                {"type": "container", "name": "alpine", "version": "3.19", "purl": "pkg:docker/alpine@3.19"}
            ]
        }"#;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.json"), json_a).unwrap();
        std::fs::write(dir.path().join("b.json"), json_b).unwrap();

        let mut store = BomStore::new();
        store.load_path(dir.path()).unwrap();

        assert_eq!(store.total_components, 3, "express should be merged");

        let express = store
            .components
            .iter()
            .find(|r| r.name_display() == "express")
            .unwrap();
        let props = express.component.properties.as_ref().unwrap();
        assert_eq!(props.len(), 3, "3 unique properties after merge");
        let lic = express.component.licenses.as_ref().unwrap();
        assert_eq!(lic.len(), 2, "2 licenses after merge");
        let hashes = express.component.hashes.as_ref().unwrap();
        assert_eq!(hashes.len(), 1, "hashes merged");
    }

    fn sample_vdr_json() -> &'static str {
        r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": 1,
            "components": [
                {"type": "library", "bom-ref": "pkg:npm/express@4.18.0", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
                {"type": "library", "bom-ref": "pkg:npm/socket.io@3.1.2", "name": "socket.io", "version": "3.1.2", "purl": "pkg:npm/socket.io@3.1.2"},
                {"type": "library", "bom-ref": "pkg:npm/clean@1.0.0", "name": "clean", "version": "1.0.0", "purl": "pkg:npm/clean@1.0.0"}
            ],
            "vulnerabilities": [
                {
                    "bom-ref": "CVE-A/pkg:npm/express@4.18.0",
                    "id": "CVE-A",
                    "ratings": [{"severity": "high", "score": 7.5, "method": "CVSSv31"}],
                    "affects": [{"ref": "pkg:npm/express@4.18.0", "versions": [{"version": "4.18.1", "status": "unaffected"}]}],
                    "properties": [{"name": "depscan:prioritized", "value": "true"}, {"name": "depscan:insights", "value": "Reachable\\nUsed in 3 locations"}]
                },
                {
                    "bom-ref": "CVE-B/pkg:npm/express@4.18.0",
                    "id": "CVE-B",
                    "ratings": [{"severity": "medium", "score": 5.0}],
                    "affects": [{"ref": "pkg:npm/express@4.18.0"}],
                    "properties": [{"name": "depscan:prioritized", "value": "false"}, {"name": "depscan:insights", "value": "Indirect dependency"}]
                },
                {
                    "bom-ref": "CVE-C/pkg:npm/socket.io@3.1.2",
                    "id": "CVE-C",
                    "ratings": [{"severity": "critical", "score": 9.8}],
                    "affects": [{"ref": "pkg:npm/socket.io@3.1.2"}],
                    "analysis": {"state": "exploitable"},
                    "properties": [{"name": "depscan:prioritized", "value": "true"}, {"name": "depscan:insights", "value": "Endpoint-Reachable\\nKnown Exploits"}]
                }
            ]
        }"#
    }

    #[test]
    fn test_vdr_index_and_aggregates() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_vdr_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        assert_eq!(store.total_vulnerabilities, 3);
        assert_eq!(store.vulnerabilities.len(), 3);
        assert_eq!(store.filtered_vulnerabilities_count(), 3);

        // Security summary
        let s = &store.security_summary;
        assert_eq!(s.total_vulns, 3);
        assert_eq!(s.severity_counts[4], 1, "critical"); // idx 4 = critical
        assert_eq!(s.severity_counts[3], 1, "high"); // idx 3 = high
        assert_eq!(s.severity_counts[2], 1, "medium"); // idx 2 = medium
        assert_eq!(s.prioritized_vulns, 2);
        assert_eq!(s.reachable_vulns, 2); // CVE-A + CVE-C
        assert_eq!(s.endpoint_reachable_vulns, 1); // CVE-C
        assert_eq!(s.exploitable_vulns, 1); // CVE-C
        assert_eq!(s.vulnerable_components, 2); // express + socket.io
        assert_eq!(s.total_components, 3);
        assert!(!s.top_by_count.is_empty());

        // vuln_by_purl aggregation: express has 2 vulns, max severity high.
        let express = store.vuln_summary_for("pkg:npm/express@4.18.0").unwrap();
        assert_eq!(express.count, 2);
        assert_eq!(express.max_severity_rank, 3); // high
        assert!(express.prioritized);
        assert!(express.reachable);
        assert!(!express.exploitable);

        // tolerant matching: qualifiers stripped
        let with_qual = store
            .vuln_summary_for("pkg:npm/express@4.18.0?foo=bar")
            .unwrap();
        assert_eq!(with_qual.count, 2);

        // clean package has no vulns
        assert!(store.vuln_summary_for("pkg:npm/clean@1.0.0").is_none());

        // hardening: a *different* version of a vulnerable package must NOT
        // inherit its CVEs via a version-stripped key (no false positive).
        assert!(
            store.vuln_summary_for("pkg:npm/express@9.9.9").is_none(),
            "unaffected version must not match a versioned vuln ref"
        );

        // top lists are deduplicated by package name (indexed under >1 key).
        let names: Vec<&str> = store
            .security_summary
            .top_by_count
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            names.len(),
            sorted.len(),
            "top_by_count has duplicate packages"
        );
    }

    #[test]
    fn test_vdr_insight_and_reachability_parsing() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_vdr_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let cve_a = store
            .vulnerabilities
            .iter()
            .find(|r| r.id_display() == "CVE-A")
            .unwrap();
        // literal backslash-n must split into two labels
        assert_eq!(
            cve_a.insight_labels(),
            vec!["Reachable".to_string(), "Used in 3 locations".to_string()]
        );
        assert!(cve_a.is_reachable());
        assert!(!cve_a.is_endpoint_reachable());
        assert!(!cve_a.is_exploitable());
        assert!(cve_a.is_prioritized());
        assert_eq!(cve_a.fix_version(), "4.18.1");
        assert_eq!(cve_a.package_name(), "express");

        let cve_c = store
            .vulnerabilities
            .iter()
            .find(|r| r.id_display() == "CVE-C")
            .unwrap();
        assert!(cve_c.is_endpoint_reachable());
        assert!(cve_c.is_exploitable()); // analysis.state == exploitable
        assert_eq!(cve_c.severity(), "critical");
        assert_eq!(cve_c.max_score(), 9.8);

        // call-site provenance parsed from "Used in N locations"
        assert_eq!(cve_a.used_in_locations(), Some(3));
        assert_eq!(cve_c.used_in_locations(), None);
    }

    #[test]
    fn test_severity_display_mapping() {
        // Guards against the label↔count inversion: severity_display() must
        // pair "critical" with the rank-4 slot, not the rank-0 slot.
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_vdr_json().as_bytes()).unwrap();
        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let disp = store.security_summary.severity_display();
        assert_eq!(disp[0], ("critical", 1));
        assert_eq!(disp[1], ("high", 1));
        assert_eq!(disp[2], ("medium", 1));
        assert_eq!(disp[3], ("low", 0));
        assert_eq!(disp[4], ("none", 0));
    }

    #[test]
    fn test_vuln_quick_filter() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_vdr_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.set_vuln_filter(VulnFilter::Prioritized);
        assert_eq!(store.filtered_vulnerabilities_count(), 2);

        store.set_vuln_filter(VulnFilter::Reachable);
        assert_eq!(store.filtered_vulnerabilities_count(), 2);

        store.set_vuln_filter(VulnFilter::Exploitable);
        assert_eq!(store.filtered_vulnerabilities_count(), 1);

        store.set_vuln_filter(VulnFilter::CriticalHigh);
        assert_eq!(store.filtered_vulnerabilities_count(), 2);

        store.set_vuln_filter(VulnFilter::All);
        assert_eq!(store.filtered_vulnerabilities_count(), 3);
    }

    #[test]
    fn test_plain_sbom_has_no_vuln_state() {
        // A BOM with no vulnerabilities[] must leave all vuln state empty.
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        assert_eq!(store.total_vulnerabilities, 0);
        assert!(store.vulnerabilities.is_empty());
        assert!(store.vuln_by_purl.is_empty());
        assert_eq!(store.security_summary.total_vulns, 0);
        assert_eq!(store.security_summary.vulnerable_components, 0);
        assert_eq!(store.filtered_vulnerabilities_count(), 0);
        // lookup returns None, no panic
        assert!(store.vuln_summary_for("pkg:npm/express@4.18.0").is_none());
    }

    #[test]
    fn test_strip_rich_markup() {
        assert_eq!(strip_rich("[green]Reachable[/green]"), "Reachable");
        assert_eq!(strip_rich(":fire: Known Exploits"), "Known Exploits");
        assert_eq!(strip_rich("clean text"), "clean text");
        assert_eq!(strip_rich("Endpoint-Reachable"), "Endpoint-Reachable");
    }
}
