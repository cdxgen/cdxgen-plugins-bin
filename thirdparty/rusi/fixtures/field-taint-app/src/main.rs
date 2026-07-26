struct Config {
    cmd: String,
    url: String,
}

fn build_config() -> Config {
    let cmd = std::env::var("CMD").unwrap_or_else(|_| "echo".to_string());
    let url = std::env::var("URL").unwrap_or_else(|_| "http://safe.example.com".to_string());
    Config { cmd, url }
}

fn run_sink(cmd: String) {
    let _ = std::process::Command::new(cmd).status();
}

fn connect_sink(url: String) {
    let _ = std::net::TcpStream::connect(url);
}

struct Mixed {
    // One field receives attacker-controlled data, the other is a literal.
    // Pre-P3.5 the stable backend unioned both fields' taint onto the
    // base binding, producing a spurious env->network-connect slice
    // through `sink(clean)` (a false positive the field-aware read now
    // eliminates).
    tainted: String,
    clean: String,
}

fn main() {
    let config = build_config();
    run_sink(config.cmd);
    connect_sink(config.url);

    let user = std::env::var("USER").unwrap_or_default();
    let mixed = Mixed {
        tainted: user,
        clean: "literal-safe-host".to_string(),
    };
    // `run_sink(mixed.tainted)` should slice (env -> process-exec).
    run_sink(mixed.tainted);
    // `connect_sink(mixed.clean)` should NOT slice (no env -> network-
    // connect through this callsite). This is the negative assertion.
    connect_sink(mixed.clean);
}
