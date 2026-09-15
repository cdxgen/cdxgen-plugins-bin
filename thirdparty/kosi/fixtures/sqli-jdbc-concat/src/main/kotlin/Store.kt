// Negative half first: executeUpdate and prepareStatement are nearby but
// unused; the corpus must notice if the engine invents them.
// kosi:want-not usage name=~executeUpdate
// kosi:want-not usage name=Connection.prepareStatement
// kosi:want-not diagnostic code=parse-error
//
// Positive half.
// kosi:want usage name=DriverManager.getConnection
// kosi:want usage name=~executeQuery
// kosi:want declaration name=findUser kind=method
// kosi:want declaration name=store kind=class
package fixtures.store

import java.sql.DriverManager

class store {
    fun findUser(id: String): String? {
        val conn = DriverManager.getConnection("jdbc:h2:mem:test")
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'")
        return if (rs.next()) rs.getString(1) else null
    }
}
