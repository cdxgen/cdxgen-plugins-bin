use std::path::PathBuf;
use std::process::Command;

fn main() -> std::io::Result<()> {
    let root = std::env::var("RUSI_WORKSPACE").unwrap_or_else(|_| ".".to_string());
    let target_dir = build_target_dir(root);
    run_cargo(&target_dir)
}

fn build_target_dir(root: String) -> PathBuf {
    let mut path = PathBuf::from(root);
    path.push("target");
    path.push("rusi-embedded-build");
    std::fs::create_dir_all(&path).expect("target dir");
    path
}

fn run_cargo(target_dir: &PathBuf) -> std::io::Result<()> {
    let mut command = Command::new("cargo");
    command.current_dir(target_dir);
    command.env("CARGO_TARGET_DIR", target_dir);
    let _ = command.output()?;
    Ok(())
}
