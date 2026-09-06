//! A trait that *cannot* back a trait object, referenced as one anyway.
//!
//! `Plugin` is clearly not object safe: `register` returns `Self` (the caller
//! could not know the return size), `load` is generic (each instantiation
//! would need its own vtable entry), and `consume` takes `self` by value
//! (there is nothing behind the pointer to move). Only `name` is exempt — its
//! `where Self: Sized` bound excludes it from the vtable, exactly as the
//! compiler does. A program containing `&dyn Plugin` therefore does not
//! compile: the shape review actually sees here is generated or hand-mangled
//! code, and the honest output is a diagnostic, not dispatch edges to impls
//! the program cannot call.

pub trait Plugin {
    fn register(&self) -> Self;
    fn load<T>(&self, raw: &str) -> T;
    fn consume(self);
    fn name(&self) -> String
    where
        Self: Sized;
}

pub struct Loader {
    origin: String,
}

impl Plugin for Loader {
    fn register(&self) -> Self {
        Loader {
            origin: self.origin.clone(),
        }
    }

    fn load<T>(&self, _raw: &str) -> T {
        unreachable!("plugin payloads are produced by the host runtime")
    }

    fn consume(self) {
        let _ = self.origin;
    }

    fn name(&self) -> String
    where
        Self: Sized,
    {
        "loader".to_string()
    }
}

/// A trait that *is* object safe, for contrast: dispatch through it must keep
/// working.
pub trait Reporter {
    fn report(&self, line: String);
}

pub struct StderrReporter;

impl Reporter for StderrReporter {
    fn report(&self, line: String) {
        let _ = line;
    }
}

fn boot(plugin: &dyn Plugin) {
    // Neither call may resolve to `Loader`'s impls: a `dyn Plugin` cannot
    // exist, so the site does not compile as written.
    let _ = plugin.name();
    plugin.consume();
}

fn audit(reporter: &dyn Reporter) {
    // The object-safe control: this dispatches to the (single) impl.
    reporter.report("audit".to_string());
}

fn main() {
    let loader = Loader {
        origin: "builtin".to_string(),
    };
    boot(&loader);

    let reporter = StderrReporter;
    audit(&reporter);
}
