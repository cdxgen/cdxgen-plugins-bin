// Two star imports: each names one candidate for `JdbcTemplate`, and only
// the one the pack knows becomes a claim.
package fixtures.nocp.starred

import org.springframework.jdbc.core.*
import org.springframework.jdbc.core.namedparam.*

fun byStarImport(template: JdbcTemplate): List<Map<String, Any>> {
    val id = readLine() ?: ""
    return template.queryForList("select * from users where id = $id")
}
