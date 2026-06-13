fn main() {
    let source = std::env::var("TAINT_SOURCE").unwrap_or_default();
    let hop1 = if source.is_empty() {
        "fallback".to_string()
    } else {
        source
    };
    let hop2 = match hop1.as_str() {
        "fallback" => "default".to_string(),
        other => other.to_string(),
    };
    let hop3 = propagate_with_try(&hop2).unwrap_or_default();
    run_sink(hop3);
}

fn propagate_with_try(input: &str) -> Result<String, std::env::VarError> {
    let res = propagate_secret(input.to_string())?;
    Ok(res)
}

fn propagate_secret(input: String) -> Result<String, std::env::VarError> {
    let res = input;
    Ok(res)
}

fn run_sink(cmd: String) {
    let _ = std::process::Command::new(cmd).status();
}
