use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn main() {
    let env_path = std::env::var("RUSI_STD_PATH").unwrap_or_else(|_| "input.txt".to_string());
    let output_path = std::env::var("RUSI_STD_OUT").unwrap_or_else(|_| "output.txt".to_string());
    let addr = std::env::var("RUSI_STD_ADDR").unwrap_or_else(|_| "127.0.0.1:9".to_string());

    filesystem_flows(env_path.clone(), output_path.clone());
    stdio_flow(output_path.clone());
    network_flows(addr);
    process_env_flow(env_path);
}

fn filesystem_flows(input: String, output: String) {
    let mut base = PathBuf::from(input);
    base.push("child");
    base.set_extension("txt");
    let content = fs::read_to_string(&base).unwrap_or_default();

    let output_path = Path::new(&output).join("report.txt");
    let wrapped = Arc::new(Mutex::new(content));
    let guarded = wrapped.lock().unwrap();
    fs::create_dir_all(output_path.parent().unwrap_or_else(|| Path::new("."))).unwrap();
    fs::write(&output_path, guarded.as_bytes()).unwrap();
    File::create(&output_path).unwrap();
    let _ = OpenOptions::new().write(true).open(&output_path);
}

fn stdio_flow(output: String) {
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    let mut bytes = Vec::new();
    bytes.extend(line.as_bytes());
    bytes.write_all(output.as_bytes()).unwrap();
    fs::write(output, bytes).unwrap();
}

fn network_flows(addr: String) {
    let _ = TcpStream::connect(&addr);
    let _ = TcpListener::bind(&addr);
    if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
        let _ = socket.connect(&addr);
        let _ = socket.send_to(addr.as_bytes(), &addr);
    }
}

fn process_env_flow(path: String) {
    let _ = std::env::set_current_dir(path);
}
