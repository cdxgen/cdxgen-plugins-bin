//! Fixture for the runtime-symbol interposition signals that mirror rustc's
//! `invalid_runtime_symbol_definitions` / `suspicious_runtime_symbol_definitions`
//! lints. Rust 1.98 linted the six core memory/string symbols; Rust 1.99
//! extended the lints to the POSIX symbols std declares in its own FFI blocks
//! (`open`/`read`/`write`/`close`/`exit`, plus `malloc`/`realloc`/`free`).
//!
//! The exported definitions below carry the exact canonical signatures from
//! `std::sys` — spelled with `i32`/`usize`/`isize`, which are what the
//! `c_int`/`c_size_t`/`c_ssize_t` aliases resolve to, keeping the
//! signature comparison lint-clean — so `cargo check` under the embedded
//! compiler backend compiles the fixture without tripping the deny-by-default
//! lint. Only rusi's signal fires.

use core::ffi::c_void;

/// Exported under its own name via `#[unsafe(no_mangle)]`: the direct
/// spelling of replacing the C runtime's `close(2)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    let _ = fd;
    0
}

/// The Rust identifier is innocuous; only the exported symbol collides. This
/// is the shape a dependency smuggles in — nothing in the source says `read`.
#[unsafe(export_name = "read")]
pub unsafe extern "C" fn replacement_read(fd: i32, buf: *mut c_void, count: usize) -> isize {
    let _ = fd;
    let _ = buf;
    count as isize
}

/// A private helper sharing its name with POSIX `open`: the false-positive
/// guard. Not exported, so nothing can be interposed and the compiler's own
/// calls are unaffected.
fn open(path: &str) -> Option<u8> {
    let _ = path;
    None
}

fn main() {
    let _ = open("/etc/hostname");
    let _ = unsafe { close(0) };
    let mut byte = 0u8;
    let _ = unsafe { replacement_read(0, &mut byte as *mut u8 as *mut c_void, 1) };
}
