// P4.3 argument-scoped sanitizer semantics. The sanitizer pattern pack
// matches `bind`/`push_bind`/`params` and previously cleared the *whole*
// call's taint, which was fine for the bound parameter itself but would
// also clear taint on an adjacent concatenated SQL string if the two
// shared a callsite. This fixture asserts that:
//   - `sqlx::query(&tainted_concatenated)` still slices (the bind on a
//     different query does NOT suppress this flow); AND
//   - `sqlx::query("literal").bind(tainted_value)` does NOT slice
//     (the bind genuinely sanitizes the bound parameter).

fn main() {
    let user = std::env::var("USER").unwrap_or_default();

    // Tainted concatenated string -> direct sink. Must slice.
    let concatenated = format!("SELECT * FROM users WHERE name = '{}'", user);
    let _ = sqlx::query(&concatenated).fetch_one(&pool);

    // Tainted value bound as a parameter to a literal query. Must NOT slice
    // (parameterized queries are safe; bind is a real sanitizer here).
    let _ = sqlx::query("SELECT * FROM users WHERE name = $1")
        .bind(&user)
        .fetch_one(&pool);
}
