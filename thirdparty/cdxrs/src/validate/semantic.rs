//! Semantic validation rules — ports of validateMetadata, validatePurls,
//! validateRefs, validateProps from lib/validator/bomValidator.js.
//!
//! Each function returns a `Vec<Finding>`. Warnings never block; errors do.

use serde_json::Value;

use super::findings::{Finding, Severity};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn warning(id: &str, path: &str, message: &str) -> Finding {
    Finding {
        id: id.to_string(),
        severity: Severity::Warning,
        path: path.to_string(),
        bom_ref: None,
        message: message.to_string(),
        hint: None,
    }
}

fn placeholder_names() -> &'static [&'static str] {
    &["app", "application", "project"]
}

/// Types that should not carry qualifiers per the purl spec.
const NO_QUALIFIER_TYPES: &[&str] = &[
    "cargo",
    "cocoapods",
    "composer",
    "cran",
    "github",
    "golang",
    "hackage",
    "nuget",
    "opam",
    "pub",
    "qpkg",
    "swift",
];

// ---------------------------------------------------------------------------
// validateMetadata
// ---------------------------------------------------------------------------

pub fn validate_metadata(bom: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let metadata = match bom.get("metadata") {
        Some(m) => m,
        None => return findings,
    };
    let meta_comp = metadata.get("component");
    if meta_comp.is_none()
        || meta_comp
            .unwrap()
            .as_object()
            .map(|o| o.is_empty())
            .unwrap_or(true)
    {
        findings.push(warning(
            "metadata.component-missing",
            "/metadata/component",
            "metadata.component is missing. Run cdxgen with both --project-name and --project-version argument.",
        ));
        return findings;
    }

    let comp = meta_comp.unwrap();

    if comp.get("purl").is_none() {
        findings.push(warning(
            "metadata.component-purl-missing",
            "/metadata/component/purl",
            "purl is missing for metadata.component",
        ));
    }
    if comp.get("bom-ref").is_none() {
        findings.push(warning(
            "metadata.component-bomref-missing",
            "/metadata/component/bom-ref",
            "bom-ref is missing for metadata.component",
        ));
    }
    if comp.get("version").is_none() {
        findings.push(warning(
            "metadata.component-version-missing",
            "/metadata/component/version",
            "Version is missing for metadata.component. Pass the version using --project-version argument.",
        ));
    }

    let name_lower = comp
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase());
    if let Some(ref name) = name_lower
        && placeholder_names().contains(&name.as_str())
    {
        let orig = comp.get("name").and_then(|v| v.as_str()).unwrap_or(name);
        findings.push(warning(
                "metadata.component-placeholder-name",
                "/metadata/component/name",
                &format!(
                    "metadata.component.name appears to be a placeholder ('{orig}'). Pass --project-name to set the correct parent component name."
                ),
            ));
    }

    // Check for parent component repeated in metadata.component.components
    if let Some(sub_comps) = comp.get("components").and_then(|v| v.as_array()) {
        let parent_ref = comp.get("bom-ref").and_then(|v| v.as_str());
        let parent_name = comp.get("name").and_then(|v| v.as_str());
        for sub in sub_comps {
            let sub_ref = sub.get("bom-ref").and_then(|v| v.as_str());
            let sub_name = sub.get("name").and_then(|v| v.as_str());
            if let (Some(pr), Some(sr)) = (parent_ref, sub_ref) {
                if pr == sr {
                    findings.push(warning(
                        "metadata.duplicate-parent-in-components",
                        "/metadata/component/components",
                        &format!(
                            "Found parent component with ref {sr} in metadata.component.components"
                        ),
                    ));
                }
            } else if let (Some(pn), Some(sn)) = (parent_name, sub_name)
                && (sub_ref.is_none() || parent_ref.is_none())
                && pn == sn
            {
                findings.push(warning(
                    "metadata.duplicate-parent-by-name",
                    "/metadata/component/components",
                    &format!(
                        "Found parent component with name {sn} in metadata.component.components"
                    ),
                ));
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// validatePurls
// ---------------------------------------------------------------------------

pub fn validate_purls(bom: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let components = match bom.get("components").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => return findings,
    };

    let mut frameworks_count = 0u32;

    for (i, comp) in components.iter().enumerate() {
        let comp_type = comp.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if comp_type == "framework" {
            frameworks_count += 1;
        }

        let path = format!("/components/{i}");
        let purl_str = comp.get("purl").and_then(|v| v.as_str());
        let bom_ref = comp
            .get("bom-ref")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let version = comp.get("version").and_then(|v| v.as_str()).unwrap_or("");

        if comp_type == "cryptographic-asset" {
            if let Some(ref p) = purl_str
                && !p.is_empty()
            {
                findings.push(Finding {
                    id: "purl.crypto-asset-has-purl".to_string(),
                    severity: Severity::Error,
                    path: format!("{path}/purl"),
                    bom_ref: bom_ref.clone(),
                    message: format!("purl should not be defined for cryptographic-asset {p}"),
                    hint: None,
                });
            }
            let crypto_props = comp.get("cryptoProperties");
            if crypto_props.is_none() {
                findings.push(Finding {
                    id: "crypto.asset-missing-crypto-properties".to_string(),
                    severity: Severity::Error,
                    path: format!("{path}/cryptoProperties"),
                    bom_ref: bom_ref.clone(),
                    message: format!(
                        "cryptoProperties is missing for cryptographic-asset {}",
                        purl_str.unwrap_or("")
                    ),
                    hint: None,
                });
            } else if let Some(cp) = crypto_props {
                let asset_type = cp.get("assetType").and_then(|v| v.as_str()).unwrap_or("");
                if asset_type == "algorithm" && cp.get("oid").is_none() {
                    findings.push(Finding {
                        id: "crypto.algorithm-missing-oid".to_string(),
                        severity: Severity::Error,
                        path: format!("{path}/cryptoProperties/oid"),
                        bom_ref: bom_ref.clone(),
                        message: format!(
                            "cryptoProperties.oid is missing for cryptographic-asset of type algorithm {}",
                            purl_str.unwrap_or("")
                        ),
                        hint: None,
                    });
                }
                if asset_type == "certificate" && cp.get("algorithmProperties").is_none() {
                    findings.push(Finding {
                        id: "crypto.certificate-missing-algorithm-properties".to_string(),
                        severity: Severity::Error,
                        path: format!("{path}/cryptoProperties/algorithmProperties"),
                        bom_ref: bom_ref.clone(),
                        message: format!(
                            "cryptoProperties.algorithmProperties is missing for cryptographic-asset of type certificate {}",
                            purl_str.unwrap_or("")
                        ),
                        hint: None,
                    });
                }
            }
            continue;
        }

        // Non-crypto components: validate purl
        if let Some(ref purl) = purl_str {
            match parse_purl(purl) {
                Ok(parsed) => {
                    // Type normalization
                    if parsed.purl_type != parsed.purl_type.to_lowercase() {
                        findings.push(Finding {
                            id: "purl.type-not-normalized".to_string(),
                            severity: Severity::Warning,
                            path: format!("{path}/purl"),
                            bom_ref: bom_ref.clone(),
                            message: format!("purl type is not normalized to lower case {purl}"),
                            hint: None,
                        });
                    }
                    // Encoded slash without namespace (npm/golang).
                    //
                    // Test the *raw* purl string, not `parsed.name`: the purl
                    // parser percent-decodes the name, so `parsed.name` never
                    // contains a literal "%2F" and this rule could never fire.
                    if matches!(parsed.purl_type.as_str(), "npm" | "golang")
                        && purl.contains("%2F")
                        && parsed.namespace.is_empty()
                    {
                        findings.push(Finding {
                            id: "purl.encoded-slash-without-namespace".to_string(),
                            severity: Severity::Error,
                            path: format!("{path}/purl"),
                            bom_ref: bom_ref.clone(),
                            message: format!(
                                "purl does not include namespace but includes encoded slash in name for npm type. {purl}"
                            ),
                            hint: None,
                        });
                    }
                    // Unexpected qualifiers
                    if !parsed.qualifiers.is_empty()
                        && NO_QUALIFIER_TYPES.contains(&parsed.purl_type.as_str())
                    {
                        let qkeys: Vec<&str> =
                            parsed.qualifiers.keys().map(|k| k.as_str()).collect();
                        findings.push(Finding {
                            id: "purl.unexpected-qualifiers".to_string(),
                            severity: Severity::Warning,
                            path: format!("{path}/purl"),
                            bom_ref: bom_ref.clone(),
                            message: format!(
                                "SPEC VIOLATION: Qualifiers are not expected for {} type. Purl: {}, Qualifier(s): {}.",
                                parsed.purl_type, purl, qkeys.join(", ")
                            ),
                            hint: None,
                        });
                    }
                    // Epoch mismatch
                    if let Some(epoch) = parsed.qualifiers.get("epoch")
                        && !version.starts_with(&format!("{epoch}:"))
                    {
                        findings.push(Finding {
                            id: "purl.version-missing-epoch".to_string(),
                            severity: Severity::Error,
                            path: format!("{path}/version"),
                            bom_ref: bom_ref.clone(),
                            message: format!(
                                "'{}' version '{}' doesn't include epoch '{}'.",
                                comp.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                                version,
                                epoch
                            ),
                            hint: None,
                        });
                    }
                }
                Err(_) => {
                    findings.push(Finding {
                        id: "purl.invalid-syntax".to_string(),
                        severity: Severity::Error,
                        path: format!("{path}/purl"),
                        bom_ref: bom_ref.clone(),
                        message: format!("Invalid purl {purl}"),
                        hint: None,
                    });
                }
            }
        }
    }

    if frameworks_count > 20 {
        findings.push(warning(
            "purl.too-many-frameworks",
            "/components",
            &format!("BOM likey has too many framework components. Count: {frameworks_count}"),
        ));
    }

    findings
}

// ---------------------------------------------------------------------------
// PURL parser — minimal, sufficient for the checks above.
// Mirrors the packageurl-js PackageURL.fromString() behavior.
// ---------------------------------------------------------------------------

struct ParsedPurl {
    purl_type: String,
    namespace: String,
    // Retained for completeness of the parsed form, and because the purl type
    // table is due to be extended by later deliverables. No rule reads it today:
    // the encoded-slash check deliberately inspects the raw purl instead, since
    // the parser percent-decodes this field.
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    version: String,
    qualifiers: std::collections::BTreeMap<String, String>,
}

/// Parse a package URL.
///
/// Format: `pkg:type/namespace/name@version?qualifiers#subpath`
///
/// Hand-rolled rather than pulling in the `packageurl` crate, but aligned with
/// the purl spec and `packageurl.rs` on the points that were previously wrong:
///
/// * the scheme is compared case-insensitively (`PKG:` is valid), and leading
///   slashes after it are permitted (`pkg://npm/foo`);
/// * `name` is **required** — `pkg:npm`, `pkg:npm/` and `pkg:npm/@1.0.0` are
///   errors, where before they parsed successfully with an empty name;
/// * empty path segments are ignored, per the spec;
/// * `version` is percent-decoded, as namespace and name already were;
/// * qualifiers with an empty value are dropped, per the spec.
///
/// The version separator remains the **first** `@`, deliberately. A literal `@`
/// inside a namespace is not legal — the spec requires `%40` — so
/// `pkg:npm/@scope/pkg@1.0.0` is an invalid purl and splitting at the scope's
/// `@` leaves an empty name, which the name-required check above now rejects.
/// Searching from the right would instead silently accept a malformed purl.
fn parse_purl(purl: &str) -> Result<ParsedPurl, String> {
    let scheme_end = purl
        .find(':')
        .ok_or_else(|| "purl must start with pkg:".to_string())?;
    if !purl[..scheme_end].eq_ignore_ascii_case("pkg") {
        return Err("purl must start with pkg:".to_string());
    }
    // The spec tolerates `pkg://` for historical reasons.
    let body = purl[scheme_end + 1..].trim_start_matches('/');

    // Split off subpath
    let (rest, _subpath) = match body.find('#') {
        Some(pos) => (&body[..pos], Some(&body[pos + 1..])),
        None => (body, None),
    };

    // Split off qualifiers
    let (rest, qualifiers_str) = match rest.find('?') {
        Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
        None => (rest, None),
    };

    // Split off version
    let (rest, version) = match rest.find('@') {
        Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
        None => (rest, None),
    };

    // Split type from name/namespace
    let (type_part, name_part) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };

    if type_part.is_empty() {
        return Err("purl type is empty".to_string());
    }

    // The last non-empty segment is the name; anything before it is the
    // namespace. Empty segments are ignored, so `pkg:npm//foo` == `pkg:npm/foo`.
    // Each segment is decoded individually: decoding the joined string first
    // would turn an encoded `%2F` inside a segment into a spurious separator.
    let segments: Vec<&str> = name_part.split('/').filter(|s| !s.is_empty()).collect();
    let (namespace, name) = match segments.split_last() {
        Some((last, before)) => (
            before
                .iter()
                .map(|s| url_decode(s))
                .collect::<Vec<_>>()
                .join("/"),
            url_decode(last),
        ),
        None => (String::new(), String::new()),
    };

    if name.is_empty() {
        return Err("purl name is required".to_string());
    }

    let purl_type = type_part.to_lowercase();

    let mut qualifiers = std::collections::BTreeMap::new();
    if let Some(qs) = qualifiers_str {
        for pair in qs.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let key = pair[..eq_pos].to_lowercase();
                let val = url_decode(&pair[eq_pos + 1..]);
                // The spec says a qualifier with an empty value must be ignored.
                if !val.is_empty() {
                    qualifiers.insert(key, val);
                }
            }
        }
    }

    Ok(ParsedPurl {
        purl_type,
        namespace,
        name,
        version: version.map(url_decode).unwrap_or_default(),
        qualifiers,
    })
}

/// Percent-decode a purl component.
///
/// Decodes into a byte buffer and interprets the result as UTF-8 at the end,
/// rather than pushing each decoded byte as a `char`. Pushing bytes as `char`
/// applies a Latin-1 reading, so any multi-byte sequence is mangled: `%C3%A9`
/// yields `Ã©` instead of `é`. Undecodable input falls back lossily, since a
/// validator must never panic on a malformed purl.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// validateRefs
// ---------------------------------------------------------------------------

/// Build the set of known bom-refs (components, services, formulation, etc.)
fn build_ref_set(bom: &Value) -> std::collections::HashSet<String> {
    let mut refs = std::collections::HashSet::new();

    fn walk_component(comp: &Value, refs: &mut std::collections::HashSet<String>) {
        if let Some(r) = comp.get("bom-ref").and_then(|v| v.as_str()) {
            refs.insert(r.to_string());
        }
        if let Some(subs) = comp.get("components").and_then(|v| v.as_array()) {
            for sub in subs {
                walk_component(sub, refs);
            }
        }
    }

    if let Some(meta_comp) = bom.get("metadata").and_then(|m| m.get("component")) {
        walk_component(meta_comp, &mut refs);
    }
    if let Some(comps) = bom.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            walk_component(comp, &mut refs);
        }
    }
    if let Some(formulations) = bom.get("formulation").and_then(|v| v.as_array()) {
        for formulation in formulations {
            if let Some(comps) = formulation.get("components").and_then(|v| v.as_array()) {
                for comp in comps {
                    walk_component(comp, &mut refs);
                }
            }
            if let Some(workflows) = formulation.get("workflows").and_then(|v| v.as_array()) {
                for wf in workflows {
                    if let Some(r) = wf.get("bom-ref").and_then(|v| v.as_str()) {
                        refs.insert(r.to_string());
                    }
                    if let Some(tasks) = wf.get("tasks").and_then(|v| v.as_array()) {
                        for task in tasks {
                            if let Some(r) = task.get("bom-ref").and_then(|v| v.as_str()) {
                                refs.insert(r.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    refs
}

/// Check if the dependency tree is partial (multiple empty dependsOn).
fn is_partial_tree(dependencies: &[Value], components_count: usize) -> bool {
    if components_count <= 1 {
        return false;
    }
    if dependencies.len() <= 1 {
        return true;
    }
    let mut is_cbom = false;
    let mut parents_with_children = 0u32;
    for dep in dependencies {
        let depends_on = dep.get("dependsOn").and_then(|v| v.as_array());
        if let Some(arr) = depends_on
            && !arr.is_empty()
        {
            parents_with_children += 1;
        }
        if !is_cbom
            && let Some(provides) = dep.get("provides").and_then(|v| v.as_array())
            && !provides.is_empty()
        {
            is_cbom = true;
        }
    }
    let threshold = std::cmp::min(
        (components_count as f64 / 3.0).round() as u32,
        components_count as u32,
    );
    !is_cbom && parents_with_children < threshold
}

pub fn validate_refs(bom: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dependencies = match bom.get("dependencies").and_then(|v| v.as_array()) {
        Some(d) => d,
        None => return findings,
    };

    let ref_set = build_ref_set(bom);
    let components_count = bom
        .get("components")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let parent_component_ref = bom
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("bom-ref"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if is_partial_tree(dependencies, components_count) {
        findings.push(warning(
            "ref.partial-tree",
            "/dependencies",
            "Dependency tree has multiple empty dependsOn attributes.",
        ));
    }

    for (i, dep) in dependencies.iter().enumerate() {
        let dep_ref = dep.get("ref").and_then(|v| v.as_str()).unwrap_or("");
        let path = format!("/dependencies/{i}");

        // Encoded characters in ref
        if dep_ref.contains("%40") || dep_ref.contains("%3A") || dep_ref.contains("%2F") {
            findings.push(Finding {
                id: "ref.encoded-dependency-ref".to_string(),
                severity: Severity::Error,
                path: format!("{path}/ref"),
                bom_ref: None,
                message: format!("Invalid encoded ref in dependencies {dep_ref}"),
                hint: None,
            });
        }

        // Dangling ref
        if !dep_ref.is_empty() && !ref_set.contains(dep_ref) {
            findings.push(warning(
                "ref.dangling-dependency-ref",
                &format!("{path}/ref"),
                &format!("Invalid ref in dependencies {dep_ref}"),
            ));
        }

        let parent_purl_type = parse_purl(dep_ref).map(|p| p.purl_type).ok();

        // Parent without children
        if let Some(ref pcr) = parent_component_ref
            && dep_ref == pcr.as_str()
        {
            let depends_on = dep.get("dependsOn").and_then(|v| v.as_array());
            let is_empty = depends_on.map(|a| a.is_empty()).unwrap_or(true);
            if is_empty && dependencies.len() > 1 {
                findings.push(warning(
                        "ref.parent-without-children",
                        &format!("{path}/dependsOn"),
                        &format!(
                            "Parent component {pcr} doesn't have any children. The dependency tree must contain dangling nodes, which are unsupported by tools such as Dependency-Track."
                        ),
                    ));
            }
        }

        // dependsOn checks
        if let Some(depends_on) = dep.get("dependsOn").and_then(|v| v.as_array()) {
            for don in depends_on {
                if let Some(don_str) = don.as_str() {
                    if !ref_set.contains(don_str) {
                        findings.push(warning(
                            "ref.dangling-dependson-ref",
                            &format!("{path}/dependsOn"),
                            &format!(
                                "Invalid ref in dependencies.dependsOn {don_str}. Parent: {dep_ref}"
                            ),
                        ));
                    }
                    let child_purl_type = parse_purl(don_str).map(|p| p.purl_type).ok();
                    if let (Some(pt), Some(ct)) = (&parent_purl_type, &child_purl_type)
                        && pt != ct
                        && !matches!(pt.as_str(), "oci" | "generic" | "container")
                    {
                        findings.push(warning(
                                "ref.type-mismatch",
                                &format!("{path}/dependsOn"),
                                &format!(
                                    "The parent package '{dep_ref}' (type {pt}) depends on the child package '{don_str}' (type {ct}). This is a bug in cdxgen if this project is not a monorepo."
                                ),
                            ));
                    }
                }
            }
        }

        // provides checks
        if let Some(provides) = dep.get("provides").and_then(|v| v.as_array()) {
            for don in provides {
                if let Some(don_str) = don.as_str()
                    && !ref_set.contains(don_str)
                {
                    findings.push(warning(
                        "ref.dangling-provides-ref",
                        &format!("{path}/provides"),
                        &format!("Invalid ref in dependencies.provides {don_str}"),
                    ));
                }
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// validateProps
// ---------------------------------------------------------------------------

const NPM_NATIVE_ADDON_EVIDENCE_PROPERTIES: &[&str] = &[
    "cdx:npm:native_addon",
    "cdx:npm:has_binary",
    "cdx:npm:os",
    "cdx:npm:cpu",
];

pub fn validate_props(bom: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Early return if metadata.component.type is not application/framework/library
    let meta_type = bom
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !matches!(meta_type, "application" | "framework" | "library") {
        return findings;
    }

    let components = match bom.get("components").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => return findings,
    };

    let mut is_workspace_mode = false;
    let mut lacks_properties = false;
    let mut lacks_evidence = false;
    let mut lacks_relative_path = false;
    let mut npm_without_tarball = 0u32;
    let mut npm_with_tarball = 0u32;

    for comp in components {
        let comp_type = comp.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if !matches!(comp_type, "library" | "framework") {
            continue;
        }
        let purl = comp.get("purl").and_then(|v| v.as_str()).unwrap_or("");
        if !purl.starts_with("pkg:npm") && !purl.starts_with("pkg:pypi") {
            continue;
        }

        if purl.starts_with("pkg:npm") {
            let has_dist = comp
                .get("externalReferences")
                .and_then(|v| v.as_array())
                .map(|refs| {
                    refs.iter().any(|r| {
                        r.get("type").and_then(|v| v.as_str()) == Some("distribution")
                            && r.get("url").is_some()
                    })
                })
                .unwrap_or(false);
            if has_dist {
                npm_with_tarball += 1;
            } else {
                npm_without_tarball += 1;
            }
        }

        let bom_ref = comp.get("bom-ref").and_then(|v| v.as_str()).unwrap_or("");

        let properties = comp.get("properties").and_then(|v| v.as_array());
        if let Some(props) = properties {
            let mut src_file_found = false;
            let mut workspace_found = false;
            for p in props {
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let value = p.get("value").and_then(|v| v.as_str()).unwrap_or("");
                if name == "SrcFile" {
                    src_file_found = true;
                    if !lacks_relative_path && value.starts_with('/') {
                        lacks_relative_path = true;
                    }
                }
                if name == "internal:workspaceRef" {
                    is_workspace_mode = true;
                    workspace_found = true;
                }
            }
            let scope = comp.get("scope").and_then(|v| v.as_str()).unwrap_or("");
            if is_workspace_mode && !workspace_found && !src_file_found && scope != "optional" {
                findings.push(warning(
                    "props.missing-workspace-properties",
                    &format!("/components/{}", bom_ref),
                    &format!("{bom_ref} lacks workspace-related properties."),
                ));
            }
            if !src_file_found && !lacks_properties {
                findings.push(warning(
                    "props.missing-srcfile",
                    &format!("/components/{}", bom_ref),
                    &format!("{bom_ref} lacks SrcFile property."),
                ));
                lacks_properties = true;
            }
        } else if !lacks_properties {
            findings.push(warning(
                "props.missing-properties",
                &format!("/components/{}", bom_ref),
                &format!("{bom_ref} lacks properties."),
            ));
            lacks_properties = true;
        }

        if comp.get("evidence").is_none() && !lacks_evidence {
            lacks_evidence = true;
            findings.push(warning(
                "props.missing-evidence",
                &format!("/components/{}", bom_ref),
                &format!("{bom_ref} lacks evidence."),
            ));
        }
    }

    if npm_without_tarball > 0 && npm_with_tarball > 0 {
        findings.push(warning(
            "props.npm-missing-tarball",
            "/components",
            &format!(
                "Found {npm_without_tarball} pkg:npm components without externalReferences.distribution. Please file a bug, if your package-lock.json or pnpm-lock.yaml includes the tarball url."
            ),
        ));
    }

    if lacks_relative_path {
        findings.push(warning(
            "props.absolute-srcfile-path",
            "/components",
            "BOM includes absolute paths for properties like SrcFile.",
        ));
    }

    // suppress unused warning
    let _ = NPM_NATIVE_ADDON_EVIDENCE_PROPERTIES;

    findings
}
