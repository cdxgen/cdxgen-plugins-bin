//! Fixture exercising the api-discovery pass across three frameworks.
//!
//! Rusi only parses these modules — it never tries to compile them — so
//! the framework crates can be referenced freely without being declared
//! as Cargo dependencies. Each module is isolated so it can use its
//! framework's natural attribute-macro syntax without symbol collisions.

mod axum_routes;
mod actix_routes;
mod rocket_routes;

fn main() {}
