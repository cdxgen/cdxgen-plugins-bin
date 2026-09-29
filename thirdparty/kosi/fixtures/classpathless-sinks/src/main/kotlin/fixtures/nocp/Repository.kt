// A run without the project's jars — cdxgen's default Kotlin tier — cannot
// resolve a framework class, so its calls lower unresolved. The file's
// imports still name them: a parameter, property, local or constructor typed
// `JdbcTemplate` under `import org.springframework.jdbc.core.JdbcTemplate`
// makes `queryForList` the pack's sink, and `call-import-resolved` says so.
// An unresolved class the pack does not name (MyBatis's SqlSession) moves
// taint by the unknown-call default, and `taint-unresolved-call` names it:
// the classpath-less blind spot, made visible.
// kosi:want-not flow source=untrusted-input sink=sql-query fn=fixtures.nocp.Repository.ownJdbcTemplate mode=endpoint
// kosi:want-not flow source=untrusted-input sink=sql-query fn=fixtures.nocp.Repository.constantSql mode=endpoint
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=sql-query fn=fixtures.nocp.Repository.byParameter mode=endpoint
// kosi:want flow source=untrusted-input sink=sql-query fn=fixtures.nocp.Repository.byProperty mode=endpoint
// kosi:want flow source=untrusted-input sink=sql-query fn=fixtures.nocp.Repository.byLocal mode=endpoint
// kosi:want flow source=untrusted-input sink=sql-query fn=fixtures.nocp.Repository.byConstructorCall mode=endpoint
// kosi:want flow source=untrusted-input sink=sql-query fn=fixtures.nocp.Repository.byThisProperty mode=endpoint
// kosi:want flow source=untrusted-input sink=ssrf fn=fixtures.nocp.Repository.byRestTemplate mode=endpoint
// kosi:want flow source=untrusted-input sink=ssrf fn=fixtures.nocp.Repository.byUnresolvedConstructor mode=endpoint
// kosi:want flow source=untrusted-input sink=nosql-query fn=fixtures.nocp.Repository.byStaticCall mode=endpoint
// kosi:want flow source=untrusted-input sink=sql-query fn=fixtures.nocp.starred.byStarImport mode=endpoint
// kosi:want diagnostic code=call-import-resolved mode=endpoint
// kosi:want diagnostic code=taint-unresolved-call mode=endpoint
package fixtures.nocp

import org.apache.http.client.methods.HttpGet
import org.apache.ibatis.session.SqlSession
import org.bson.Document
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.client.RestTemplate

class Repository(private val jdbc: JdbcTemplate, private val session: SqlSession) {
    private val rest: RestTemplate = RestTemplate()

    fun byParameter(template: JdbcTemplate): List<Map<String, Any>> {
        val id = readLine() ?: ""
        return template.queryForList("select * from users where id = $id")
    }

    fun byProperty(): List<Map<String, Any>> {
        val id = readLine() ?: ""
        return jdbc.queryForList("select * from users where id = $id")
    }

    fun byLocal(): List<Map<String, Any>> {
        val id = readLine() ?: ""
        val template = JdbcTemplate()
        return template.queryForList("select * from users where id = $id")
    }

    fun byConstructorCall(): List<Map<String, Any>> {
        val id = readLine() ?: ""
        return JdbcTemplate().queryForList("select * from users where id = $id")
    }

    fun byThisProperty(): Int {
        val id = readLine() ?: ""
        return this.jdbc.update("delete from users where id = $id")
    }

    fun byRestTemplate(): String? {
        val url = readLine() ?: ""
        return rest.getForObject(url, String::class.java)
    }

    fun byUnresolvedConstructor(): Any {
        val url = readLine() ?: ""
        return HttpGet(url)
    }

    fun byStaticCall(): Any {
        val json = readLine() ?: "{}"
        return Document.parse(json)
    }

    fun byMyBatis(): List<Any> {
        val id = readLine() ?: ""
        return session.selectList("users.byId", id)
    }

    fun constantSql(): List<Map<String, Any>> {
        val id = readLine() ?: ""
        println(id)
        return jdbc.queryForList("select * from users")
    }

    // A same-named class from another package is not Spring's: its call is
    // named `fixtures.nocp.local.JdbcTemplate.queryForList`, which no pack
    // entry matches.
    fun ownJdbcTemplate(template: fixtures.nocp.local.JdbcTemplate): Any {
        val id = readLine() ?: ""
        return template.queryForList("select * from users where id = $id")
    }
}
