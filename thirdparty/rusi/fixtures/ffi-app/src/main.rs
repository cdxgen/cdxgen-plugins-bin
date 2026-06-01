use std::ffi::CString;
use std::os::raw::c_char;

#[link(name = "c")]
unsafe extern "C" {
    fn puts(message: *const c_char) -> i32;
}

fn main() {
    let message = std::env::var("NATIVE_MSG").unwrap_or_else(|_| "hello from ffi".to_string());
    let c_message = CString::new(message).unwrap();
    unsafe {
        let _ = puts(c_message.as_ptr());
    }
}
