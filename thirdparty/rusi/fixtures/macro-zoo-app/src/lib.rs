//! Every declarative-macro scoping shape in one crate: textual, hoisted,
//! path-based, and `#[macro_export]`, plus dependency macros and std macros.

// Textual scope: defined at the crate root before the modules that use it,
// invoked below in this file and from the child module `textual`.
macro_rules! root_tag {
    () => {
        "macro-zoo"
    };
}

#[macro_use]
extern crate log;

mod macros;
#[macro_use]
mod hoisted;
// Hoisted through two levels: `outer` and `inner` both carry `#[macro_use]`,
// so `deep_note!` is in scope here, after this line.
#[macro_use]
mod outer;
mod shadow;

pub mod helper;
pub mod textual;

use crate::macros::make_units;
use anyhow::bail;
use log::info;
use log::warn as w;
use maplit::hashmap;

// Path-based scope: the full-path form of `path_scoped!`, which the same
// macro also serves through `use crate::macros::path_scoped;` (not used
// here, to keep the two forms distinct).
pub fn scaled(v: u32) -> String {
    crate::macros::path_scoped!(v)
}

make_units!(Seconds, Minutes);

#[doc(hidden)]
#[macro_export]
macro_rules! __exported {
    ($v:expr) => {
        $crate::helper::enc($v as u32)
    };
}
#[doc(inline)]
pub use __exported as exported;

/// A terminating token-tree muncher: one level per token.
macro_rules! count_tts {
    () => {
        0
    };
    ($head:tt $($rest:tt)*) => {
        1 + count_tts!($($rest)*)
    };
}

/// Recursion with no base case. Defined but never invoked; the expander's
/// depth limit is what stops an invocation of it.
#[allow(unused_macros)]
macro_rules! spin_forever {
    ($($t:tt)*) => {
        spin_forever!($($t)* $($t)*)
    };
}

/// Binds its own `x` so a caller with a tainted `x` must not lose the flow:
/// the caller's binding reaches the write through `$v`, the transcriber's
/// `x` stays a separate variable.
macro_rules! guard_with_local {
    ($v:expr) => {{
        let x = "safe";
        let _checked = x;
        std::fs::write("/tmp/macro-zoo-guard", $v)
    }};
}

pub fn run(s: &Seconds) -> anyhow::Result<String> {
    let secret = std::env::var("MACRO_ZOO_SECRET").unwrap();
    let value = serde_json::json!({ "a": s.0, "secret": secret });
    std::fs::write("/tmp/macro-zoo-value", format!("{value}")).ok();
    info!("value {value:?}");
    trace!("entering run");
    if s.0 == 0 {
        bail!("zero");
    }
    w!("checked");
    let _ = s.danger();
    println!("{}: {} units", root_tag!(), count_tts!(Seconds Minutes));
    let _note = hoisted_note!();
    let _deep = deep();
    let _first = shadow::first();
    let _second = shadow::second();
    Ok(exported!(s.0))
}

/// Uses the macro hoisted through two `#[macro_use]` modules.
pub fn deep() -> String {
    deep_note!()
}

/// An optional part inside a repetition: `beta` has no type and returns `()`.
macro_rules! getters {
    ( $( $name:ident $(: $ty:ty)? ),* $(,)? ) => {
        $( pub fn $name() $(-> $ty)? { Default::default() } )*
    };
}
getters!(alpha: u32, beta, gamma: String);

/// A repetition separated by the two-token separator `::`, and a rule list
/// whose matchers use `[]` and `{}` delimiters.
macro_rules! call_path {
    ( $($seg:ident)::+ ( $arg:expr ) ) => { $($seg)::+($arg) };
}
macro_rules! bracketed {
    [ $v:literal ] => { $v };
    { $v:ident } => { stringify!($v) };
}

/// A block-local definition is visible only in its own block.
pub fn block_local() -> u32 {
    macro_rules! local_five {
        () => {
            5
        };
    }
    local_five!()
}

/// Binds with `if let`, a closure and a `match`, none of which may alias the
/// caller's variables of the same names.
macro_rules! write_checked {
    ($v:expr) => {{
        let maybe = Some("safe");
        if let Some(path) = maybe {
            let write = |data: String| std::fs::write(path, data);
            let _ = write("fixed".to_string());
        }
        match $v {
            data => std::fs::write("/tmp/macro-zoo-checked", data),
        }
    }};
}

pub fn checked_flow() -> std::io::Result<()> {
    let path = std::env::var("MACRO_ZOO_CHECKED").unwrap();
    write_checked!(path)
}

pub fn extra() -> String {
    let _ = dbg!(1 + 1);
    let n = call_path!(crate::helper::enc(7));
    format!("{}{}{}{}", n, alpha(), bracketed![3], bracketed! { word })
}

/// A source read inside a macro while the sink is outside it: the value of an
/// expression-position invocation, one used as an argument, one that a method
/// outside the macro unwraps, and one bound by a statement-position expansion.
macro_rules! read_source {
    () => {
        std::env::var("MACRO_ZOO_SOURCE").unwrap()
    };
}
macro_rules! raw_source {
    () => {
        std::env::var("MACRO_ZOO_SOURCE")
    };
}
macro_rules! bind_source {
    ($v:ident) => {
        let $v = std::env::var("MACRO_ZOO_SOURCE").unwrap();
    };
}

pub fn macro_source_let() -> std::io::Result<std::process::Output> {
    let v = read_source!();
    std::process::Command::new("sh").arg(v).output()
}

pub fn macro_source_argument() -> std::io::Result<std::process::Output> {
    std::process::Command::new("sh").arg(read_source!()).output()
}

pub fn macro_source_unwrapped_outside() -> std::io::Result<std::process::Output> {
    let v = raw_source!().unwrap();
    std::process::Command::new("sh").arg(v).output()
}

pub fn macro_source_bound_by_statement() -> std::io::Result<std::process::Output> {
    bind_source!(v);
    std::process::Command::new("sh").arg(v).output()
}

pub fn hygiene_flow() -> std::io::Result<()> {
    let x = std::env::var("MACRO_ZOO_HYGIENE").unwrap();
    guard_with_local!(x)
}

/// An `unsafe` block a workspace macro writes in its transcriber. The signal
/// for it comes from the macro's expansion and names the macro, not the
/// invoking line.
macro_rules! checked_slot {
    ($v:expr) => {
        unsafe { std::ptr::read($v as *const u32) }
    };
}

pub fn slot_value(v: u32) -> u32 {
    checked_slot!(v)
}

/// A dependency macro whose body is a mapping, not Rust statements: the
/// stable backend reports its body as unanalyzed, the compiler backend
/// expands it, so the stale note must not survive compiler mode.
pub fn zone_map() -> std::collections::HashMap<String, u32> {
    let zone = std::env::var("MACRO_ZOO_ZONE").unwrap();
    let length = zone.len() as u32;
    hashmap! { zone => length }
}

/// The path form of the same dependency macro.
pub fn pair_map() -> std::collections::HashMap<&'static str, u32> {
    maplit::hashmap! { "primary" => 1, "backup" => 2 }
}

/// An `unsafe` block written by hand beside a dependency macro call: the
/// block is the user's own code, so its signal stays and carries no macro
/// origin even though the call next to it was expanded.
pub fn hand_written_unsafe_beside_macro() -> usize {
    info!("counting");
    let text = String::from("checked");
    let length = unsafe { std::ptr::read(&text as *const String) }.len();
    std::mem::forget(text);
    length
}
