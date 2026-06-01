trait Sink<T> {
    fn submit(&self, value: T);
}

struct FileSink;
struct NetSink;

impl Sink<String> for FileSink {
    fn submit(&self, value: String) {
        let _ = std::fs::write(value, "payload");
    }
}

impl Sink<String> for NetSink {
    fn submit(&self, value: String) {
        let _ = std::net::TcpStream::connect(value);
    }
}

fn run_specific<S: Sink<String>>(sink: &S, value: String) {
    sink.submit(value);
}

fn main() {
    let path = std::env::var("OUT_PATH").unwrap_or_else(|_| "/tmp/generic-specialization-app.txt".to_string());
    let addr = std::env::var("REMOTE_ADDR").unwrap_or_else(|_| "127.0.0.1:80".to_string());
    let file = FileSink;
    let net = NetSink;
    run_specific(&file, path);
    run_specific(&net, addr);
}
