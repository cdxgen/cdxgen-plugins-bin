fn main() {
    let value = std::env::var("RUSI_PATH").unwrap_or_default();
    open(value);
}

fn open(path: String) {
    let _ = path;
}
