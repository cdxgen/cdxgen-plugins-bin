use std::fs;

fn handler(req: &mut Request) {
    let reflected = format!("<h1>{:?}</h1>", req.url.path());
    let _ = reflected;
}

fn main() {
    let db_key = fs::read_to_string("/var/tmp/tainted_file.txt").unwrap();
    let tainted_query = format!("SELECT * FROM someTable WHERE key = '{}'", db_key.trim());
    let _ = sqlx::query(&tainted_query).fetch_one(&pool);

    let route = warp::path::param().then(|tainted_param: String| async move {
        let _ = reqwest::Client::new()
            .post(format!("https://{}", tainted_param))
            .send();
        format!("<h1>Hello, {}!</h1>", tainted_param)
    });

    let _ = route;
}
