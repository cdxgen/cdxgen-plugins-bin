mod helper;

fn main() {
    let secret = helper::read_secret();
    helper::run_command(secret);
}
