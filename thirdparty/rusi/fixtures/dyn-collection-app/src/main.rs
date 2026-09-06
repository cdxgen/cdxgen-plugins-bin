//! Request handlers stored heterogeneously and dispatched through their trait.
//!
//! `Vec<T>` needs uniform element size, which is exactly what the `Box<dyn
//! Handler>` wide pointer supplies — this is *the* reason trait objects exist,
//! and the shape real plugin registries, middleware stacks, and subscriber
//! lists take. Every dispatch below goes through iteration or indexing of a
//! container of trait objects, never through a directly-typed binding.

use std::env;
use std::fs;
use std::net::TcpStream;

pub trait Handler {
    fn handle(&self, request: String) -> Result<String, String>;
}

pub struct ArchiveHandler {
    directory: String,
}

pub struct ProbeHandler;

impl Handler for ArchiveHandler {
    fn handle(&self, request: String) -> Result<String, String> {
        // The flow the taint pass should recover through collection dispatch:
        // external input, carried as the container element's argument, into a
        // filesystem write.
        fs::write(format!("{}/archive.txt", self.directory), request)
            .map_err(|error| error.to_string())?;
        Ok("archived".to_string())
    }
}

impl Handler for ProbeHandler {
    fn handle(&self, request: String) -> Result<String, String> {
        let mut stream = TcpStream::connect(request).map_err(|error| error.to_string())?;
        use std::io::Write;
        stream
            .write_all(b"probe")
            .map_err(|error| error.to_string())?;
        Ok("probed".to_string())
    }
}

/// The plugin-registry idiom: handlers are unknown at construction time and
/// dispatched uniformly afterwards.
pub struct Registry {
    handlers: Vec<Box<dyn Handler>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            handlers: vec![Box::new(ArchiveHandler {
                directory: "/tmp/dyn-collection-app".to_string(),
            })],
        }
    }

    pub fn register(&mut self, handler: Box<dyn Handler>) {
        self.handlers.push(handler);
    }

    /// Iteration over a container *field* of trait objects.
    pub fn dispatch_all(&self, request: String) {
        for handler in &self.handlers {
            let _ = handler.handle(request.clone());
        }
    }

    /// Indexing a container field: the element dispatches, not the `Vec`.
    pub fn dispatch_first(&self, request: String) {
        if !self.handlers.is_empty() {
            let _ = self.handlers[0].handle(request);
        }
    }
}

/// Iteration over a container *parameter*, through the iterator constructor.
pub fn drain_batch(batch: &Vec<Box<dyn Handler>>) {
    for handler in batch.iter() {
        let _ = handler.handle("batch".to_string());
    }
}

/// A map of handlers: the *values* are the dispatching elements.
pub struct Cluster {
    nodes: std::collections::HashMap<String, Box<dyn Handler>>,
}

impl Cluster {
    /// Tuple-pattern iteration binds the map's value element.
    pub fn fan_out(&self, request: String) {
        for (_name, node) in &self.nodes {
            let _ = node.handle(request.clone());
        }
    }
}

fn main() {
    let request = env::var("HANDLER_REQUEST").unwrap_or_else(|_| "ping".to_string());

    let mut registry = Registry::new();
    registry.register(Box::new(ProbeHandler));
    registry.dispatch_all(request.clone());
    registry.dispatch_first(request.clone());

    let mut batch: Vec<Box<dyn Handler>> = Vec::new();
    batch.push(Box::new(ProbeHandler));
    drain_batch(&batch);

    let mut nodes = std::collections::HashMap::new();
    nodes.insert(
        "primary".to_string(),
        Box::new(ArchiveHandler {
            directory: "/tmp/dyn-collection-app".to_string(),
        }) as Box<dyn Handler>,
    );
    let cluster = Cluster { nodes };
    cluster.fan_out(request);
}
