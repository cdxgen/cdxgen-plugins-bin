use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusi_schema::{
    CallGraph, CryptoEvidence, DataFlowEvidence, DataFlowPattern, DataFlowPatternSet,
    DataFlowStats, Report,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnalysisScope {
    #[default]
    Default,
    Cryptos,
}

impl AnalysisScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Cryptos => "cryptos",
        }
    }
}

pub fn load_custom_pattern_set(path: &Path) -> Result<DataFlowPatternSet> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read custom pattern file {}", path.display()))?;
    let mut patterns: DataFlowPatternSet = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse custom pattern file {}", path.display()))?;
    normalize_pattern_targets(&mut patterns);
    Ok(patterns)
}

pub fn merge_pattern_sets(base: &mut DataFlowPatternSet, mut extra: DataFlowPatternSet) {
    normalize_pattern_targets(&mut extra);
    merge_pattern_collection(&mut base.sources, extra.sources, "source");
    merge_pattern_collection(&mut base.sinks, extra.sinks, "sink");
    merge_pattern_collection(&mut base.passthroughs, extra.passthroughs, "passthrough");
}

pub fn crypto_only_pattern_set(base: DataFlowPatternSet) -> DataFlowPatternSet {
    let mut patterns = DataFlowPatternSet {
        sources: base.sources,
        sinks: crypto_sink_patterns(),
        passthroughs: base.passthroughs,
    };
    patterns.sources.extend(crypto_source_patterns());
    normalize_pattern_targets(&mut patterns);
    patterns
}

pub fn retain_crypto_focus(report: &mut Report) {
    if let Some(data_flow) = report.data_flow.take() {
        report.data_flow = Some(filter_crypto_data_flow(data_flow));
    }
    if let Some(call_graph) = report.call_graph.take() {
        report.call_graph = Some(filter_crypto_call_graph(
            call_graph,
            report.crypto.as_ref(),
            report.data_flow.as_ref(),
        ));
    }
}

pub fn is_crypto_dataflow_category(category: &str) -> bool {
    let normalized = category.to_ascii_lowercase();
    normalized.starts_with("crypto")
        || matches!(normalized.as_str(), "secret" | "jwt" | "certificate" | "tls")
}

fn crypto_source_patterns() -> Vec<DataFlowPattern> {
    vec![
        DataFlowPattern {
            target: "source".to_string(),
            pattern: "std::env::var".to_string(),
            category: "secret".to_string(),
            relevant_arguments: vec![],
        },
        DataFlowPattern {
            target: "source".to_string(),
            pattern: "std::env::var_os".to_string(),
            category: "secret".to_string(),
            relevant_arguments: vec![],
        },
        DataFlowPattern {
            target: "source".to_string(),
            pattern: "env::var".to_string(),
            category: "secret".to_string(),
            relevant_arguments: vec![],
        },
        DataFlowPattern {
            target: "source".to_string(),
            pattern: "std::fs::read_to_string".to_string(),
            category: "crypto-material".to_string(),
            relevant_arguments: vec![],
        },
        DataFlowPattern {
            target: "source".to_string(),
            pattern: "fs::read_to_string".to_string(),
            category: "crypto-material".to_string(),
            relevant_arguments: vec![],
        },
    ]
}

fn crypto_sink_patterns() -> Vec<DataFlowPattern> {
    vec![
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "sha2::Sha256::digest".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "Sha256::digest".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "sha2::Sha512::digest".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "Sha512::digest".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "sha1::Sha1::digest".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "Sha1::digest".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "md5::compute".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "blake3::hash".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "ring::digest::digest".to_string(),
            category: "crypto-digest".to_string(),
            relevant_arguments: vec![1],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "aes_gcm::aead::KeyInit::new_from_slice".to_string(),
            category: "crypto-key".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "Aes256Gcm::new_from_slice".to_string(),
            category: "crypto-key".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "chacha20poly1305::aead::KeyInit::new_from_slice".to_string(),
            category: "crypto-key".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "ChaCha20Poly1305::new_from_slice".to_string(),
            category: "crypto-key".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "ring::aead::UnboundKey::new".to_string(),
            category: "crypto-key".to_string(),
            relevant_arguments: vec![1],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "hmac::Mac::new_from_slice".to_string(),
            category: "crypto-key".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "pbkdf2::pbkdf2_hmac".to_string(),
            category: "crypto-kdf".to_string(),
            relevant_arguments: vec![1],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "argon2::Argon2::hash_password".to_string(),
            category: "crypto-kdf".to_string(),
            relevant_arguments: vec![1],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "jsonwebtoken::EncodingKey::from_secret".to_string(),
            category: "jwt".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "rustls::ClientConfig::builder".to_string(),
            category: "tls".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "rustls::ServerConfig::builder".to_string(),
            category: "tls".to_string(),
            relevant_arguments: vec![0],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "rsa::RsaPrivateKey::new".to_string(),
            category: "crypto-keygen".to_string(),
            relevant_arguments: vec![1],
        },
        DataFlowPattern {
            target: "sink".to_string(),
            pattern: "ed25519_dalek::SigningKey::from_bytes".to_string(),
            category: "crypto-key".to_string(),
            relevant_arguments: vec![0],
        },
    ]
}

fn merge_pattern_collection(
    target: &mut Vec<DataFlowPattern>,
    incoming: Vec<DataFlowPattern>,
    default_target: &str,
) {
    for mut pattern in incoming {
        if pattern.target.is_empty() {
            pattern.target = default_target.to_string();
        }
        if !target.iter().any(|existing| existing == &pattern) {
            target.push(pattern);
        }
    }
}

fn normalize_pattern_targets(patterns: &mut DataFlowPatternSet) {
    for pattern in &mut patterns.sources {
        if pattern.target.is_empty() {
            pattern.target = "source".to_string();
        }
    }
    for pattern in &mut patterns.sinks {
        if pattern.target.is_empty() {
            pattern.target = "sink".to_string();
        }
    }
    for pattern in &mut patterns.passthroughs {
        if pattern.target.is_empty() {
            pattern.target = "passthrough".to_string();
        }
    }
}

fn filter_crypto_data_flow(mut data_flow: DataFlowEvidence) -> DataFlowEvidence {
    data_flow.patterns.sources.retain(pattern_is_crypto_related);
    data_flow.patterns.sinks.retain(pattern_is_crypto_related);
    data_flow
        .patterns
        .passthroughs
        .retain(pattern_is_crypto_related_passthrough);

    let retained_slices = data_flow
        .slices
        .into_iter()
        .filter(|slice| {
            is_crypto_dataflow_category(&slice.source_category)
                || is_crypto_dataflow_category(&slice.sink_category)
                || looks_crypto_symbol(&slice.source_name)
                || looks_crypto_symbol(&slice.sink_name)
                || looks_crypto_symbol(&slice.rule_name)
        })
        .collect::<Vec<_>>();

    let retained_node_ids = retained_slices
        .iter()
        .flat_map(|slice| slice.node_ids.iter().cloned())
        .collect::<HashSet<_>>();
    let retained_edge_ids = retained_slices
        .iter()
        .flat_map(|slice| slice.edge_ids.iter().cloned())
        .collect::<HashSet<_>>();
    let retained_functions = retained_slices
        .iter()
        .flat_map(|slice| [slice.source_function.clone(), slice.sink_function.clone()])
        .collect::<HashSet<_>>();

    data_flow.nodes.retain(|node| {
        retained_node_ids.contains(&node.id)
            || retained_functions.contains(&node.function)
            || is_crypto_dataflow_category(&node.category)
            || looks_crypto_symbol(&node.name)
    });
    let surviving_node_ids = data_flow
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<HashSet<_>>();
    data_flow.edges.retain(|edge| {
        retained_edge_ids.contains(&edge.id)
            || (surviving_node_ids.contains(&edge.source_id)
                && surviving_node_ids.contains(&edge.target_id))
    });
    data_flow.slices = retained_slices;
    data_flow.summaries.retain(|summary| {
        retained_functions.contains(&summary.function)
            || summary
                .param_to_sink
                .keys()
                .any(|category| is_crypto_dataflow_category(category))
            || summary
                .source_returns
                .iter()
                .any(|category| is_crypto_dataflow_category(category))
            || looks_crypto_symbol(&summary.function)
    });
    data_flow.diagnostics.retain(|diagnostic| {
        diagnostic
            .message
            .split_whitespace()
            .any(looks_crypto_symbol)
            || diagnostic
                .file_path
                .as_deref()
                .is_some_and(looks_crypto_symbol)
    });
    data_flow.stats = DataFlowStats {
        source_count: data_flow.nodes.iter().filter(|node| node.source).count(),
        sink_count: data_flow.nodes.iter().filter(|node| node.sink).count(),
        slice_count: data_flow.slices.len(),
        node_count: data_flow.nodes.len(),
        edge_count: data_flow.edges.len(),
        summary_count: data_flow.summaries.len(),
    };
    data_flow
}

fn filter_crypto_call_graph(
    mut call_graph: CallGraph,
    crypto: Option<&CryptoEvidence>,
    data_flow: Option<&DataFlowEvidence>,
) -> CallGraph {
    let mut retained_node_ids = HashSet::new();
    let mut retained_edge_ids = HashSet::new();
    let mut seed_names = HashSet::new();
    let mut seed_files = HashSet::new();

    if let Some(data_flow) = data_flow {
        for slice in &data_flow.slices {
            seed_names.insert(slice.source_function.clone());
            seed_names.insert(slice.sink_function.clone());
        }
        for node in &data_flow.nodes {
            if is_crypto_dataflow_category(&node.category) || looks_crypto_symbol(&node.name) {
                seed_names.insert(node.function.clone());
            }
        }
    }
    if let Some(crypto) = crypto {
        for library in &crypto.libraries {
            if !library.file_path.is_empty() {
                seed_files.insert(library.file_path.clone());
            }
        }
        for component in &crypto.components {
            if !component.file_path.is_empty() {
                seed_files.insert(component.file_path.clone());
            }
        }
        for material in &crypto.materials {
            if !material.file_path.is_empty() {
                seed_files.insert(material.file_path.clone());
            }
            if !material.function.is_empty() {
                seed_names.insert(material.function.clone());
            }
        }
        for finding in &crypto.findings {
            if !finding.file_path.is_empty() {
                seed_files.insert(finding.file_path.clone());
            }
        }
    }

    let mut incoming = HashMap::<String, Vec<(String, String)>>::new();
    for edge in &call_graph.edges {
        incoming
            .entry(edge.target_id.clone())
            .or_default()
            .push((edge.id.clone(), edge.source_id.clone()));
    }

    let mut queue = VecDeque::new();
    for node in &call_graph.nodes {
        let crypto_seed = seed_names.contains(&node.qualified_name)
            || seed_files.contains(&node.file_path)
            || looks_crypto_symbol(&node.qualified_name)
            || looks_crypto_symbol(&node.name)
            || node.external;
        let edge_seed = call_graph.edges.iter().any(|edge| {
            edge.source_id == node.id
                && edge
                    .properties
                    .get("calleeText")
                    .is_some_and(|callee| looks_crypto_symbol(callee))
        });
        if crypto_seed && (looks_crypto_symbol(&node.qualified_name) || seed_names.contains(&node.qualified_name) || seed_files.contains(&node.file_path) || edge_seed) {
            queue.push_back(node.id.clone());
        }
    }

    while let Some(node_id) = queue.pop_front() {
        if !retained_node_ids.insert(node_id.clone()) {
            continue;
        }
        if let Some(parents) = incoming.get(&node_id) {
            for (edge_id, source_id) in parents {
                retained_edge_ids.insert(edge_id.clone());
                queue.push_back(source_id.clone());
            }
        }
    }

    for edge in &call_graph.edges {
        if retained_node_ids.contains(&edge.source_id) && retained_node_ids.contains(&edge.target_id) {
            retained_edge_ids.insert(edge.id.clone());
        }
        if edge
            .properties
            .get("calleeText")
            .is_some_and(|callee| looks_crypto_symbol(callee))
        {
            retained_node_ids.insert(edge.source_id.clone());
            retained_node_ids.insert(edge.target_id.clone());
            retained_edge_ids.insert(edge.id.clone());
        }
    }

    call_graph.nodes.retain(|node| retained_node_ids.contains(&node.id));
    let surviving_node_ids = call_graph
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<HashSet<_>>();
    call_graph.edges.retain(|edge| {
        retained_edge_ids.contains(&edge.id)
            || (surviving_node_ids.contains(&edge.source_id)
                && surviving_node_ids.contains(&edge.target_id))
    });
    call_graph.diagnostics.retain(|diagnostic| {
        diagnostic
            .file_path
            .as_deref()
            .is_some_and(|file| seed_files.contains(file))
            || diagnostic
                .message
                .split_whitespace()
                .any(looks_crypto_symbol)
            || diagnostic
                .position
                .as_ref()
                .is_some_and(|position| seed_files.contains(&position.filename))
    });
    call_graph.stats.node_count = call_graph.nodes.len();
    call_graph.stats.edge_count = call_graph.edges.len();
    call_graph
}

fn pattern_is_crypto_related(pattern: &DataFlowPattern) -> bool {
    is_crypto_dataflow_category(&pattern.category) || looks_crypto_symbol(&pattern.pattern)
}

fn pattern_is_crypto_related_passthrough(pattern: &DataFlowPattern) -> bool {
    pattern_is_crypto_related(pattern)
        || matches!(pattern.category.as_str(), "value-wrapper" | "string-format" | "ffi-wrapper")
}

fn looks_crypto_symbol(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace(' ', "");
    [
        "crypto",
        "sha1",
        "sha2",
        "sha256",
        "sha512",
        "md5",
        "blake3",
        "aes",
        "aead",
        "chacha",
        "hmac",
        "argon2",
        "pbkdf2",
        "scrypt",
        "hkdf",
        "jsonwebtoken",
        "jwt",
        "rustls",
        "tls",
        "openssl",
        "native_tls",
        "x509",
        "certificate",
        "rsa",
        "ed25519",
        "x25519",
        "p256",
        "p384",
        "k256",
        "keyinit",
        "new_from_slice",
        "digest",
        "signingkey",
        "encodingkey",
        "unboundkey",
    ]
    .iter()
    .any(|token| normalized.contains(token))
}
