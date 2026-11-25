//! A receiver-typed sink reached through a wrapper whose receiver parameter's
//! type is a type parameter: the wrapper's own summary cannot know the type,
//! and only the caller that passes a `Command` can supply it.

use std::env;
use std::process;

/// The type the built-in process-exec patterns restrict `arg` to.
pub struct Command {
    program: String,
    args: Vec<String>,
}

impl Command {
    pub fn new(program: &str) -> Command {
        Command {
            program: program.to_string(),
            args: Vec::new(),
        }
    }

    pub fn spawn(self) {
        let _ = (self.program, self.args);
    }
}

/// The trait the generic wrapper is written against, named after the method
/// the sink pattern matches: calling `arg` on the type parameter is the only
/// way `forward` can reach the sink, and the stable backend resolves no type
/// for `target` inside `forward`.
pub trait ArgSink {
    fn arg(&mut self, value: &str) -> &mut Self;
}

impl ArgSink for Command {
    fn arg(&mut self, value: &str) -> &mut Command {
        self.args.push(value.to_string());
        self
    }
}

/// The wrapper under test: `target`'s type is the type parameter `T`, so the
/// receiver-typed `arg` sink cannot fire while `forward` is summarized alone.
pub fn forward<'a, T: ArgSink>(target: &'a mut T, value: &str) -> &'a mut T {
    target.arg(value);
    target
}

/// A wrapper over a plain (non-generic) parameter keeps working: its
/// parameter type is annotated and the sink fires without help.
pub fn forward_command<'a>(target: &'a mut Command, value: &str) -> &'a mut Command {
    target.arg(value)
}

fn main() {
    let value = env::var("FORWARDED_VALUE").unwrap_or_default();

    let mut generic = Command::new("sh");
    forward(&mut generic, &value);
    generic.spawn();

    let mut plain = Command::new("sh");
    forward_command(&mut plain, &value);
    plain.spawn();

    let mut direct = Command::new("sh");
    direct.arg(&value);
    direct.spawn();

    process::exit(0);
}
