//! axum router-building patterns: nested routers, function-returned
//! sub-routers, local-binding sub-routers, every extractor kind.

use axum::{
    extract::{Json, Path, Query, State},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AppState;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
}

#[derive(Deserialize)]
pub struct UserListQuery {
    pub limit: Option<i64>,
}

pub async fn list_users(
    State(_state): State<AppState>,
    Query(_params): Query<UserListQuery>,
) -> Json<Vec<User>> {
    Json(Vec::new())
}

pub async fn get_user(
    State(_state): State<AppState>,
    Path(_id): Path<i32>,
) -> Result<Json<User>, axum::http::StatusCode> {
    Err(axum::http::StatusCode::NOT_FOUND)
}

pub async fn create_user(
    State(_state): State<AppState>,
    Json(_payload): Json<CreateUserRequest>,
) -> Json<User> {
    Json(User {
        id: 1,
        username: String::new(),
    })
}

pub async fn health() -> &'static str {
    "ok"
}

pub fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/:id", get(get_user))
}

pub fn build_app() -> Router {
    let api = Router::new().nest("/users", user_routes());
    Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api)
        .with_state(AppState)
}
