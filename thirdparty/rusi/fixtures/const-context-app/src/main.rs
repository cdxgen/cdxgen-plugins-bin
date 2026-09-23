// Const contexts the compiler backend must survive on every supported rustc:
// an array length that calls a const fn (an anon const with its own typeck
// results), an inline const (`DefKind::InlineConst` on older compilers, an
// `AnonConst` on newer ones) and an enum discriminant.
use std::process::Command;

const fn width() -> usize {
    4
}

enum Mode {
    Fast = 1 + 2,
}

fn run_command(arg: String) {
    let _ = Command::new("sh").arg(arg).status();
}

fn main() {
    let buffer = [0u8; width() * 2];
    let padding = const { width() + 1 };
    let secret = std::env::var("CMD").unwrap_or_default();
    run_command(secret);
    let _ = (buffer, padding, Mode::Fast as i32);
}
