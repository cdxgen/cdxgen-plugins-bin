fn sqlx_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = sqlx::query(&sql).fetch_one(&pool);
}

fn diesel_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = diesel::dsl::sql_query(&sql).load(&mut conn);
}

fn postgres_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = client.query(&sql, &[]);
}

fn tokio_postgres_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = client.query_one(&sql, &[]);
}

fn rusqlite_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = conn.execute(&sql, ());
}

fn mysql_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = conn.query_drop(&sql);
}

fn mysql_async_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = conn.exec(&sql, ());
}

fn tiberius_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = client.simple_query(&sql);
}

fn sea_orm_flow() {
    let sql = std::fs::read_to_string("/tmp/query.sql").unwrap();
    let _ = db.execute_unprepared(&sql);
}

fn main() {}
