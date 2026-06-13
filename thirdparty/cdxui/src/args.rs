use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cdxui", version, about = "Interactive terminal UI for CycloneDX BOM exploration")]
pub struct Args {
    #[arg(help = "Path to a CycloneDX BOM file (.json) or directory containing BOM files")]
    pub path: PathBuf,

    #[arg(
        long,
        default_value = "false",
        help = "Skip alternate screen (useful for debugging)"
    )]
    pub no_alternate_screen: bool,

    #[arg(
        long = "theme",
        default_value = "dark",
        help = "Color theme: dark, light"
    )]
    pub theme: String,
}
