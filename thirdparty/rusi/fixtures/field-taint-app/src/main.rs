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

fn main() {
    let config = build_config();
    run_sink(config.cmd);
    connect_sink(config.url);
}
