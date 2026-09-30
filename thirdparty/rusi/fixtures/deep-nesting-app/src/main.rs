//! Expressions nested 800 deep, the shape of generated tables and parsers.
//! rustc compiles them; rusi's parse and analysis threads must not overflow
//! their stacks on them. Two modules, so the files are parsed on worker
//! threads rather than the analysis thread.

mod nested;
mod nested_twin;

fn main() {
    nested::run();
    nested_twin::run();
}
