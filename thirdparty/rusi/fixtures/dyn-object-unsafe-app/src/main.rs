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

/// The negative half of the object-safety gate: a trait that returns an
/// *associated item* of `Self`, which stays dyn compatible.
///
/// This is the `Iterator` shape — `fn next(&mut self) -> Option<Self::Item>`,
/// and `dyn Iterator<Item = u32>` is the canonical trait object. A reader that
/// tests the return type for the substring `Self` gates this trait out of
/// dispatch and reports a violation that does not exist, deleting real edges.
pub trait Feed {
    type Item;
    fn next_item(&mut self) -> Option<Self::Item>;
    fn origin(&self) -> String;
}

pub struct FileFeed;

impl Feed for FileFeed {
    type Item = String;

    fn next_item(&mut self) -> Option<String> {
        Some("row".to_string())
    }

    fn origin(&self) -> String {
        "file".to_string()
    }
}

/// The other half: a type whose *name* merely contains `Self`. Returning it is
/// not returning `Self`.
pub struct MySelfish;

pub trait Renderer {
    fn render(&self) -> MySelfish;
    fn label(&self) -> String;
}

pub struct HtmlRenderer;

impl Renderer for HtmlRenderer {
    fn render(&self) -> MySelfish {
        MySelfish
    }

    fn label(&self) -> String {
        "html".to_string()
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

fn drain(feed: &mut dyn Feed<Item = String>) -> String {
    // Must dispatch to `FileFeed::origin`: an associated-item return keeps the
    // trait dyn compatible.
    feed.origin()
}

fn show(renderer: &dyn Renderer) -> String {
    // Must dispatch to `HtmlRenderer::label`: `MySelfish` is not `Self`.
    renderer.label()
}

fn main() {
    let loader = Loader {
        origin: "builtin".to_string(),
    };
    boot(&loader);

    let reporter = StderrReporter;
    audit(&reporter);

    let mut feed = FileFeed;
    let _ = drain(&mut feed);
    let _ = show(&HtmlRenderer);
}
