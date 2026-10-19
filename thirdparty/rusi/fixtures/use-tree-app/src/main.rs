//! Every shape of `use` declaration, for the compiler backend's import
//! collection. Older compilers lower a brace list to one HIR item per leaf;
//! newer ones keep the whole tree in one item with relative nested prefixes.
//! Both must report the same leaf imports, and never the braces themselves.
use std::collections::{BTreeMap, HashMap as Map};
use std::env;
use std::fmt::*;
use std::io::{self, Read, Write as _};
use std::sync::{Arc as Shared, atomic::{AtomicUsize, Ordering}};
use std::{fs, path::{Path, PathBuf}};

fn main() {
    let mut ordered: BTreeMap<u8, u8> = BTreeMap::new();
    ordered.insert(1, 1);
    let mut hashed: Map<u8, u8> = Map::new();
    hashed.insert(1, 1);
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);
    let _ = io::stdout().flush();
    let _ = env::var("USE_TREE_APP");
    let _ = fs::metadata(Path::new("Cargo.toml"));
    let _owned = PathBuf::from("Cargo.toml");
    let counter = Shared::new(AtomicUsize::new(0));
    counter.fetch_add(1, Ordering::Relaxed);
    let mut rendered = String::new();
    let _ = write!(rendered, "{}", counter.load(Ordering::Relaxed));
}
