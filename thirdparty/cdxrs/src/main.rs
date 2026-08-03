//! cdxrs binary entry point — argument parsing and dispatch ONLY.
//!
//! No logic lives here; every subcommand delegates to `cdxrs::cmd`.

use clap::Parser;

use cdxrs::cli::{Cli, Command};
use cdxrs::error::CdxrsError;
use cdxrs::error::exit_code;
use cdxrs::{CDXRS_VERSION, SUPPORTED_SPEC_VERSIONS, log};

fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Some(Command::Info) => cdxrs::cmd::info::run(&cli.input, &cli.output, cli.max_input_bytes),
        Some(Command::Validate) => {
            cdxrs::cmd::validate::run(&cli.input, &cli.output, cli.max_input_bytes)
        }
        Some(Command::Fetch(args)) => {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error(&format!("failed to create tokio runtime: {e}"));
                    std::process::exit(exit_code::OPERATIONAL_FAILURE);
                }
            };
            runtime.block_on(cdxrs::cmd::fetch::run(
                &cli.input,
                &cli.output,
                cli.max_input_bytes,
                build_fetch_config(args),
            ))
        }
        Some(Command::SchemaVersion) => {
            let versions: Vec<String> = SUPPORTED_SPEC_VERSIONS
                .iter()
                .map(|v| format!("\"{v}\""))
                .collect();
            println!("{{\"supportedSpecVersions\":[{}]}}", versions.join(","));
            Ok(())
        }
        None => {
            // No subcommand: print version and basic usage hint.
            println!("cdxrs {CDXRS_VERSION}");
            println!("Supported spec versions: {}", versions_str());
            println!("Run 'cdxrs --help' for usage.");
            Ok(())
        }
    };

    match result {
        Ok(()) => std::process::exit(exit_code::OK),
        Err(e) => {
            // ValidationFailure is not an operational error: findings are
            // already on stdout. Log at info, not error.
            match &e {
                CdxrsError::ValidationFailure => {
                    log::info("validation failure (findings on stdout)")
                }
                _ => log::error(&e.to_string()),
            }
            std::process::exit(e.exit_code());
        }
    }
}

fn versions_str() -> String {
    SUPPORTED_SPEC_VERSIONS.join(", ")
}

/// Build the FetchConfig from CLI args.
fn build_fetch_config(args: &cdxrs::cli::FetchArgs) -> cdxrs::cmd::fetch::FetchConfig {
    use std::time::Duration;

    let client_config = cdxrs::fetch::client::FetchClientConfig {
        global_concurrency: args.concurrency,
        per_host_concurrency: args.per_host_concurrency,
        connect_timeout: Duration::from_secs(args.connect_timeout),
        read_timeout: Duration::from_secs(args.read_timeout),
        total_timeout: Duration::from_secs(args.total_timeout),
        request_deadline: Duration::from_secs(args.request_deadline),
        max_body_bytes: args.max_body_bytes,
        ..Default::default()
    };
    cdxrs::cmd::fetch::FetchConfig {
        client_config,
        // --offline means "cache only", so it *needs* the cache. Treating it as
        // a reason to disable the cache made the flag guarantee a miss and then
        // go to the network anyway — the exact opposite of what it promises.
        cache_enabled: !args.no_cache,
        cache_ttl_secs: args.cache_ttl,
        offline: args.offline,
    }
}
