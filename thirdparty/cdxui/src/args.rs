use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cdxui",
    version,
    about = "Interactive terminal UI for CycloneDX BOM exploration"
)]
pub struct Args {
    #[arg(help = "Path to a CycloneDX BOM file (.json) or directory.")]
    pub path: Option<PathBuf>,

    #[arg(
        long,
        default_value = "false",
        help = "Generate BOM by spawning cdxgen. All args after -- are passed to cdxgen."
    )]
    pub generate: bool,

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

    #[arg(
        long = "output",
        default_value = "/tmp/bom.json",
        help = "Output BOM file path (for --generate mode)"
    )]
    pub output: PathBuf,
}

/// ASCII unit separator, the delimiter cdxgen uses for `CDXGEN_ARGS` and
/// `CDXGEN_CMD`. It cannot occur in a path or a flag, so arguments survive the
/// round trip whether or not they contain spaces.
pub const ARG_SEPARATOR: char = '\u{1f}';

/// Split an environment-passed argument vector.
///
/// Values from cdxgen v13 are separator-delimited. Older releases joined on
/// spaces, so a value with no separator falls back to whitespace splitting.
pub fn split_env_args(value: &str) -> Vec<String> {
    if value.contains(ARG_SEPARATOR) {
        return value
            .split(ARG_SEPARATOR)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
    }
    value.split_whitespace().map(|s| s.to_string()).collect()
}

pub fn parse_cdxgen_args() -> Vec<String> {
    let cdgenv = std::env::var("CDXGEN_ARGS").unwrap_or_default();
    if !cdgenv.is_empty() {
        return split_env_args(&cdgenv);
    }
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--") {
        args[pos + 1..].to_vec()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_separator_preserves_spaces_in_paths() {
        let value = format!("-t{}js{}/tmp/my project", ARG_SEPARATOR, ARG_SEPARATOR);
        assert_eq!(split_env_args(&value), vec!["-t", "js", "/tmp/my project"]);
    }

    #[test]
    fn test_whitespace_fallback_for_older_cdxgen() {
        assert_eq!(
            split_env_args("-t js /tmp/app"),
            vec!["-t", "js", "/tmp/app"]
        );
    }

    #[test]
    fn test_empty_value() {
        assert!(split_env_args("").is_empty());
    }
}
