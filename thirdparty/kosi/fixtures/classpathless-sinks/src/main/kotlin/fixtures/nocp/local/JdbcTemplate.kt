package fixtures.nocp.local

/** A workspace class that shares Spring's simple name and nothing else. */
class JdbcTemplate {
    fun queryForList(sql: String): List<String> = listOf(sql.length.toString())
}
