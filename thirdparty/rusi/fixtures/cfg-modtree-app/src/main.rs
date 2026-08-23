mod facade;
#[path = "generated/handlers_v2.rs"]
mod handlers;
mod sinks;

// Reached only on Windows; the module file exists but is not part of this
// build.
#[cfg(windows)]
mod platform;

use crate::facade::run_facade_sink;
use crate::sinks::*;

fn main() {
    let secret = std::env::var("TOKEN").unwrap_or_default();
    glob_sink(&secret);
    run_facade_sink(&secret);
    handlers::handle(&secret);
}

/// Behind an enabled feature: collected, and reported with its gate.
#[cfg(feature = "tls")]
pub fn tls_sink(value: &str) {
    let _ = std::process::Command::new("sh").arg(value).status();
}

/// Behind a disabled feature: not part of this build at all.
#[cfg(feature = "ldap")]
pub fn ldap_sink(value: &str) {
    let _ = std::process::Command::new("sh").arg(value).status();
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_only_sink() {
        let _ = std::process::Command::new("sh").status();
    }
}
