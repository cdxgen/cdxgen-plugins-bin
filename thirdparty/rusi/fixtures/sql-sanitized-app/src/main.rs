fn sqlx_bound() {
    let value = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = sqlx::query("SELECT * FROM widgets WHERE id = $1")
        .bind(value.trim())
        .fetch_one(&pool);
}

fn diesel_bound() {
    let value = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = diesel::dsl::sql_query("SELECT * FROM widgets WHERE id = ?")
        .bind::<diesel::sql_types::Text, _>(value.trim())
        .load(&mut conn);
}

fn main() {}
