/// A dependency-side sink: the workspace calls it, so a `--deps` scan should
/// resolve the call instead of reporting it as merely external, and a
/// `security-deps` scan should carry taint through it.
pub fn run_command(command: String) {
    let _ = std::process::Command::new(command).arg("hello").status();
}

pub struct Helper;

impl Helper {
    pub fn new() -> Self {
        Helper
    }

    pub fn forward(&self, command: String) {
        run_command(command);
    }
}

impl Default for Helper {
    fn default() -> Self {
        Self::new()
    }
}
