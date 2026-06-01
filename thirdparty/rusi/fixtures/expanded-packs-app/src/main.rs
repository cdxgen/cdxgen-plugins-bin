mod io_helpers;
mod net_helpers;

fn main() {
    let output_path = std::env::args().nth(1).unwrap_or_default();
    let input_path = std::env::var("INPUT_FILE").unwrap_or_else(|_| "Cargo.toml".to_string());
    let payload = io_helpers::load_payload(input_path);
    io_helpers::persist_payload(output_path, payload);

    let remote = std::env::var("REMOTE_ADDR").unwrap_or_else(|_| "127.0.0.1:80".to_string());
    net_helpers::connect_to(remote);
}
