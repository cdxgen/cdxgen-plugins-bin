pub fn glob_sink(value: &str) {
    let _ = std::process::Command::new("sh").arg(value).status();
}
