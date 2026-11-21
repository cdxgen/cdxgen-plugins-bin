//! Macros here are hoisted into the crate root by `#[macro_use] mod
//! hoisted;` in lib.rs, so they are in scope there by bare name.

macro_rules! hoisted_note {
    () => {
        "hoisted"
    };
}
