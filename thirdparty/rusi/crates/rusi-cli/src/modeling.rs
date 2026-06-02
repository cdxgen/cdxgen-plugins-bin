use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use rusi_core::{AnalysisScope, AnalyzeOptionsInput, load_custom_pattern_set};

#[derive(Debug, Clone, Default, Args)]
pub struct ModelingArgs {
    #[arg(
        long,
        help = "Merge a custom JSON file containing data-flow sources, sinks, and passthroughs with the built-in modeling"
    )]
    pub patterns: Option<PathBuf>,
}

pub fn apply_modeling(
    options: &mut AnalyzeOptionsInput,
    scope: AnalysisScope,
    modeling: &ModelingArgs,
) -> Result<()> {
    options.analysis_scope = scope;
    options.custom_data_flow_patterns = modeling
        .patterns
        .as_deref()
        .map(load_custom_pattern_set)
        .transpose()?;
    Ok(())
}
