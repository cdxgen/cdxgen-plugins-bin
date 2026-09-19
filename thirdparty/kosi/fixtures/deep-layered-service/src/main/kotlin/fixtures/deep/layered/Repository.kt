package fixtures.deep.layered

interface OrderRepository {
    fun query(sql: String): String?
}

class JdbcOrderRepository : OrderRepository {
    override fun query(sql: String): String? {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:test")
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT * FROM orders WHERE customer = '" + sql + "'")
        return if (rs.next()) rs.getString(1) else null
    }
}

class AuditOrderRepository : OrderRepository {
    override fun query(sql: String): String? {
        // A sibling implementation that logs instead of sinking: dispatch
    // must not smear the JDBC finding onto it.
        return "audited"
    }
}

class CacheOrderRepository : OrderRepository {
    override fun query(sql: String): String? {
        return "cached"
    }
}
