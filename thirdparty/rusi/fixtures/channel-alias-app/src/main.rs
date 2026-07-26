// Two channels (tx_safe + tx_unsafe) coexist in the same scope. Pre-P4.2
// the stable backend used a single global `__channel_taint` slot, so an
// `rx_unsafe.recv()` call would inherit taint sent through a different
// channel. P4.2 keys the taint slot on the paired receiver identity so
// unrelated channels stop cross-tainting.

fn main() {
    let user = std::env::var("USER").unwrap_or_default();
    let safe_input = "literal".to_string();

    let (tx_safe, rx_safe) = std::sync::mpsc::channel::<String>();
    let (tx_unsafe, rx_unsafe) = std::sync::mpsc::channel::<String>();

    let _ = tx_safe.send(safe_input);
    let _ = tx_unsafe.send(user);

    // `rx_unsafe.recv()` legitimately carries env taint; the sink slices.
    let received_unsafe = rx_unsafe.recv().unwrap_or_default();
    let _ = std::process::Command::new(received_unsafe).status();

    // `rx_safe.recv()` carries only `safe_input` (literal); the sink must
    // NOT slice through env. Pre-P4.2 this FP'd because both channels
    // shared the global taint slot.
    let received_safe = rx_safe.recv().unwrap_or_default();
    let _ = std::process::Command::new(received_safe).status();
}
