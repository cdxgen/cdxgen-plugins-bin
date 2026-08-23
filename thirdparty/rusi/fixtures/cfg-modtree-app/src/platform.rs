pub fn windows_only_sink(value: &str) {
    let _ = std::process::Command::new("cmd").arg(value).status();
}
