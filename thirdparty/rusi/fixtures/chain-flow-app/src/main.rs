fn main() {
    let input = std::env::var("USER_INPUT").unwrap_or_else(|_| "safe".to_string());
    let chain = input.trim().to_lowercase().to_owned();
    let _ = std::process::Command::new(chain).arg("--verbose").status();
}
