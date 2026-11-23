use std::process::Command;

fn run(program: String) {
    let _ = Command::new(program).status();
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    run(arg);
    unsafe {
        let _ = std::mem::zeroed::<u8>();
    }
}
