fn main() {
    let secret = std::env::var("TOKEN").unwrap_or_default();
    dep_helper_lib::run_command(secret);
}
