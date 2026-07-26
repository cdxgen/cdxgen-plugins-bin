// Higher-order calls: `Iterator::map` / `Iterator::for_each` take a closure
// argument. The stable backend used to model the closure as an isolated
// function with no in-edge. P1.4 adds a `higher-order` edge from the caller
// to the closure body when a known combinator receives a closure argument.

fn transform(value: &str) -> String {
    format!("[{value}]")
}

fn sink(value: String) {
    let _ = value;
}

fn main() {
    let items = vec!["a", "b", "c"];
    let _planned: Vec<String> = items.iter().map(|x| transform(x)).collect();
    items.iter().for_each(|y| sink(format!("got {y}")));
}
