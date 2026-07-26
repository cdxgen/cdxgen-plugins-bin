// Two unrelated types both expose a method named `get`. Without
// receiver-type inference the stable backend either dropped the callsite
// entirely (drop-on-ambiguity) or routed it to the wrong bucket. With the
// P1.2 binding-driven filter, `cache.get(...)` resolves to Cache::get and
// `store.get(...)` resolves to Store::get; both edges appear and carry
// provenance=receiver-typed.

struct Cache {
    value: String,
}

impl Cache {
    fn new() -> Self {
        Self {
            value: String::new(),
        }
    }

    fn get(&self, _key: &str) -> String {
        self.value.clone()
    }
}

struct Store {
    cached: String,
}

impl Store {
    fn new() -> Self {
        Self {
            cached: String::new(),
        }
    }

    fn get(&self, _id: usize) -> String {
        self.cached.clone()
    }
}

fn main() {
    let input = std::env::var("USER").unwrap_or_default();
    let cache = Cache::new();
    let store = Store::new();
    let a = cache.get(&input);
    let b = store.get(0usize);
    println!("{a}{b}");
}
