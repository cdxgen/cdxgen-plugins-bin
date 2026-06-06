//! rocket router-building patterns: attribute macros plus mount via
//! the routes! macro, including handler with request-body binding.

use rocket::{get, post, routes, serde::json::Json};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
}

#[derive(serde::Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
}

#[get("/rocket/users/<id>")]
pub fn get_user(id: i32) -> Json<User> {
    Json(User {
        id,
        username: String::new(),
    })
}

#[post("/rocket/users", data = "<payload>")]
pub fn create_user(payload: Json<CreateUserRequest>) -> Json<User> {
    let _ = payload;
    Json(User {
        id: 1,
        username: String::new(),
    })
}

pub fn build_rocket() {
    let _ = rocket::build().mount("/api", routes![get_user, create_user]);
}
