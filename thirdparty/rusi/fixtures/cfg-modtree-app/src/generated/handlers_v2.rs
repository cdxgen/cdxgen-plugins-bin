pub fn handle(value: &str) {
    let _ = std::process::Command::new("sh").arg(value).status();
}
