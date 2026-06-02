#[get("/actix/{name}")]
async fn actix_handler(name: String) {
    format!("<h1>{}</h1>", name)
}

async fn axum_handler(path: axum::extract::Path<String>) {
    format!("<h1>{}</h1>", path.into_inner())
}

#[handler]
async fn poem_handler(query: poem::web::Query<String>) {
    format!("<h1>{}</h1>", query.into_inner())
}

async fn salvo_handler(req: salvo::Request) {
    format!("<h1>{:?}</h1>", req.query("name"))
}

#[get("/rocket/<name>")]
fn rocket_handler(name: String) {
    format!("<h1>{}</h1>", name)
}

async fn tide_handler(req: tide::Request<()>) {
    format!("<h1>{:?}</h1>", req)
}

fn iron_handler(req: &mut iron::Request) {
    format!("<h1>{:?}</h1>", req.url.path())
}

fn gotham_handler(state: gotham::state::State) {
    format!("<h1>{:?}</h1>", state.query("name"))
}

fn rouille_handler(req: &rouille::Request) {
    format!("<h1>{:?}</h1>", req)
}

async fn ntex_handler(path: ntex::web::types::Path<String>) {
    format!("<h1>{}</h1>", path.into_inner())
}

#[endpoint(method = GET, path = "/dropshot/{name}")]
async fn dropshot_handler(name: String) {
    format!("<h1>{}</h1>", name)
}

async fn thruster_handler(ctx: thruster::Context) {
    format!("<h1>{:?}</h1>", ctx)
}

fn nickel_handler(req: nickel::Request<()>) {
    format!("<h1>{:?}</h1>", req)
}

fn hyper_handler(req: hyper::Request<hyper::body::Incoming>) {
    format!("<h1>{:?}</h1>", req.uri().query())
}

async fn main() {
    let route = warp::path::param().then(|name: String| async move {
        format!("<h1>{}</h1>", name)
    });
    let _ = route;
}
