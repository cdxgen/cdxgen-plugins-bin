pub fn entry() {
    let value = crate::util::compute();
    render(value);
}

fn render(message: String) {
    println!("{message}");
}
