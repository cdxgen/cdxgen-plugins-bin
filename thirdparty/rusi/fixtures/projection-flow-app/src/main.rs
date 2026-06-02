use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
struct ClientState {
    command: String,
    remote: String,
}

struct Holder {
    inner: Rc<RefCell<ClientState>>,
}

struct DirectHolder {
    command: String,
}

fn load_holder() -> Holder {
    let command = std::env::var("CMD").unwrap_or_else(|_| "echo".to_string());
    let remote = std::env::var("REMOTE_ADDR").unwrap_or_else(|_| "127.0.0.1:80".to_string());
    Holder {
        inner: Rc::new(RefCell::new(ClientState { command, remote })),
    }
}

fn field_to_return(holder: &Holder) -> String {
    holder.inner.borrow().command.clone()
}

fn propagate_field_write(holder: &Holder, suffix: String) {
    holder.inner.borrow_mut().command = suffix;
}

fn direct_field_to_return(holder: &DirectHolder) -> String {
    holder.command.clone()
}

fn direct_param_to_field_write(holder: &mut DirectHolder, suffix: String) {
    holder.command = suffix;
}

fn wrapper_field_to_return(holder: &DirectHolder) -> String {
    direct_field_to_return(holder)
}

fn wrapper_param_to_field_write(holder: &mut DirectHolder, suffix: String) {
    direct_param_to_field_write(holder, suffix);
}

fn run(holder: &Holder) {
    let command = field_to_return(holder);
    let _ = std::process::Command::new(command).arg("hello").status();
    let remote = holder.inner.borrow().remote.clone();
    let _ = std::net::TcpStream::connect(remote);
}

fn main() {
    let holder = load_holder();
    let replacement = std::env::var("ALT_CMD").unwrap_or_else(|_| "printf".to_string());
    propagate_field_write(&holder, replacement);
    let mut direct = DirectHolder {
        command: std::env::var("DIRECT_CMD").unwrap_or_else(|_| "echo".to_string()),
    };
    let override_direct = std::env::var("DIRECT_OVERRIDE").unwrap_or_else(|_| "printf".to_string());
    wrapper_param_to_field_write(&mut direct, override_direct);
    let direct_command = wrapper_field_to_return(&direct);
    let _ = std::process::Command::new(direct_command).arg("direct").status();
    run(&holder);
}
