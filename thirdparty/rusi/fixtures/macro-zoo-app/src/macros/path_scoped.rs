//! Path-based scope: re-exported by `pub(crate) use path_scoped::*;` in
//! macros/mod.rs, so the macro is an item at `crate::macros::path_scoped`.

macro_rules! path_scoped {
    ($v:expr) => {
        $crate::helper::enc($v as u32)
    };
}

pub(crate) use path_scoped;
