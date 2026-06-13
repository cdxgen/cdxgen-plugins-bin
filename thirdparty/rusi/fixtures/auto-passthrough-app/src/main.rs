struct Container {
    secret: String,
}

impl Container {
    fn get(&self) -> &str {
        &self.secret
    }

    fn into(self) -> String {
        self.secret
    }
}

fn main() {
    let key = std::env::var("KEY").unwrap_or_else(|_| "default".into());
    let c = Container { secret: key };
    let leaked = c.get().to_owned();
    let _ = std::process::Command::new(leaked).status();
}
