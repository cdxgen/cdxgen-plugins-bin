//! Storage backends dispatched through *multi-bound* trait objects.
//!
//! The principal trait determines dispatch — `dyn Store + Send + Sync` carries
//! one vtable, `Store`'s — so the auto-trait bounds after `+` change nothing
//! about which impls a call can reach. Real code spells trait objects with
//! those bounds constantly (`Box<dyn Error + Send + Sync>`, `Arc<dyn Store +
//! Send + Sync>` for shared services), so a receiver reducer that stops at the
//! `+` loses the most common `dyn` shapes there are.

use std::env;
use std::fs;

pub trait Store {
    fn persist(&self, data: &str) -> Result<(), String>;
}

/// Audits persisted writes. A single impl, so dispatch here resolves exactly.
pub trait Auditor: Send + Sync {
    fn audited(&self, data: &str);
}

pub struct FileStore {
    root: String,
}

pub struct MemoryStore {
    capacity: usize,
    buffer: std::cell::RefCell<Vec<String>>,
}

pub struct LogAuditor {
    path: String,
}

impl Store for FileStore {
    fn persist(&self, data: &str) -> Result<(), String> {
        // The flow the taint pass should see through `dyn` dispatch: external
        // input reaching a filesystem write.
        fs::write(format!("{}/store.log", self.root), data)
            .map_err(|error| error.to_string())
    }
}

impl Store for MemoryStore {
    fn persist(&self, data: &str) -> Result<(), String> {
        if self.buffer.borrow().len() >= self.capacity {
            return Err("capacity exceeded".to_string());
        }
        self.buffer.borrow_mut().push(data.to_string());
        Ok(())
    }
}

impl Auditor for LogAuditor {
    fn audited(&self, data: &str) {
        let _ = fs::write(&self.path, data);
    }
}

/// The error-plumbing idiom: the principal trait of the object is `Error`,
/// with `Send + Sync` added for thread transferability.
pub type DynResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// A multi-bound trait object parameter — dispatch is `Store`'s vtable's.
pub fn route(store: &(dyn Store + Send + Sync), payload: &str) -> DynResult<()> {
    store.persist(payload)?;
    Ok(())
}

/// A shared multi-bound object behind `Arc`, the tokio-service spelling.
pub fn audit(service: &std::sync::Arc<dyn Auditor + Send + Sync>, data: &str) {
    service.audited(data);
}

/// Builders hand back `Box<dyn Trait + 'static>`; the returned object still
/// dispatches on `Store` alone.
pub fn boxed_store() -> Box<dyn Store + 'static> {
    Box::new(MemoryStore {
        capacity: 16,
        buffer: std::cell::RefCell::new(Vec::new()),
    })
}

fn main() {
    let payload = env::var("STORE_PAYLOAD").unwrap_or_else(|_| "bootstrap".to_string());
    let file_store = FileStore {
        root: "/tmp/dyn-bounds-app".to_string(),
    };
    let _ = route(&file_store, &payload);

    let auditor: std::sync::Arc<dyn Auditor + Send + Sync> =
        std::sync::Arc::new(LogAuditor {
            path: "/tmp/dyn-bounds-app-audit.log".to_string(),
        });
    audit(&auditor, &payload);

    let boxed = boxed_store();
    let _ = boxed.persist(&payload);
}
