fn handler(req: &mut Request) {
    let response = format!("<h1>{:?}</h1>", req.url.path());
    let sanitized = ammonia::clean(&response);
    let _ = Response::with((status::Ok, sanitized));
}

fn main() {
    handler(todo!());
}
