pub fn load_payload(path: String) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

pub fn persist_payload(path: String, payload: String) {
    let _ = std::fs::write(path, payload);
}
