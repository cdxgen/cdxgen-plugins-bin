//! actix-web router-building patterns: attribute macros, web::resource
//! registration, web::scope nesting.

use actix_web::{get, post, web, App, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
}

#[derive(Deserialize)]
pub struct UserListQuery {
    pub limit: Option<i64>,
}

#[get("/actix/{name}")]
pub async fn attribute_handler(name: web::Path<String>) -> HttpResponse {
    let _ = name;
    HttpResponse::Ok().finish()
}

#[post("/actix/echo")]
pub async fn echo(body: web::Json<CreateUserRequest>) -> HttpResponse {
    let _ = body;
    HttpResponse::Ok().finish()
}

pub async fn list_users(_query: web::Query<UserListQuery>) -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub async fn create_user(body: web::Json<CreateUserRequest>) -> HttpResponse {
    let _ = body;
    HttpResponse::Ok().finish()
}

pub fn build_app() -> App<()> {
    App::new()
        .service(attribute_handler)
        .service(echo)
        .service(
            web::scope("/api/v1").service(
                web::resource("/users")
                    .route(web::get().to(list_users))
                    .route(web::post().to(create_user)),
            ),
        )
}
