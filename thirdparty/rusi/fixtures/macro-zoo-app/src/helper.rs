pub fn enc(v: u32) -> String {
    serde_json::to_string(&v).unwrap()
}
