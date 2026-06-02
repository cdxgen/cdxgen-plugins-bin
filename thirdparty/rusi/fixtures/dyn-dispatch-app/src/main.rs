trait Store {
    fn persist(&self, data: String);
}

struct FileStore;
struct NetStore;

impl Store for FileStore {
    fn persist(&self, data: String) {
        let _ = std::fs::write("/tmp/dyn-dispatch-app.txt", data);
    }
}

impl Store for NetStore {
    fn persist(&self, data: String) {
        let _ = std::net::TcpStream::connect(data);
    }
}

fn dispatch(store: &dyn Store, payload: String) {
    store.persist(payload);
}

fn main() {
    let payload = std::env::var("STORE_TARGET").unwrap_or_else(|_| "127.0.0.1:80".to_string());
    let use_network = std::env::var("USE_NETWORK").is_ok();
    if use_network {
        let store = NetStore;
        dispatch(&store, payload);
    } else {
        let store = FileStore;
        dispatch(&store, payload);
    }
}
