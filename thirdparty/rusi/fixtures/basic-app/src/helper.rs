pub fn read_secret() -> String {
    std::env::var("SECRET_CMD").unwrap_or_else(|_| "echo".to_string())
}

pub fn run_command(command: String) {
    let _ = std::process::Command::new(command).arg("hello").status();
}

pub unsafe fn peek_first_byte(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}
