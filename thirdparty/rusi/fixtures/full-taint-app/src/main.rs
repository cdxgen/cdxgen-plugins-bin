fn main() {
    let source = std::env::var("TAINT_SOURCE").unwrap_or_default();
    
    // 1. Unsafe code, raw pointer casts, pointer offset and unsafe dereference
    let mut raw_ptr = source.as_ptr();
    let unsafe_hop = unsafe {
        let offset_ptr = raw_ptr.offset(0);
        let deref_char = *offset_ptr;
        deref_char
    };

    // 2. Arc, Mutex wrapper, lock borrow, and RefCell
    let mutex_wrapper = std::sync::Arc::new(std::sync::Mutex::new(source.clone()));
    let locked_hop = mutex_wrapper.lock().unwrap().clone();

    let refcell_wrapper = std::cell::RefCell::new(locked_hop);
    let borrowed_hop = refcell_wrapper.borrow().clone();

    // 3. Channels and concurrent send/recv
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = tx.send(borrowed_hop);
    let channel_hop = rx.recv().unwrap_or_default();

    // 4. Parameter mutation (Out-parameters)
    let mut mutated_string = String::new();
    mutate_parameter(&channel_hop, &mut mutated_string);

    let final_hop = propagate_with_try(&mutated_string).unwrap_or_default();
    run_sink(final_hop);
}

fn mutate_parameter(input: &str, output: &mut String) {
    *output = input.to_string();
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
