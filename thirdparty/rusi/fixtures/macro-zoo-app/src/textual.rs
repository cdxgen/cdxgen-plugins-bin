//! Child module reachable by the root's textual macro scope.

pub fn tagged() -> String {
    format!("{}: child", root_tag!())
}
