// The Koin 2.x spelling of the same provider, in its own file so the two
// generations' `single` extensions never compete at one import site.
// kosi:want flow source=untrusted-input sink=sql-query fn=~RealHealthApi.ping known-fail=syntax:1
package fixtures.di

import org.koin.dsl.module
import org.koin.dsl.single
import org.springframework.stereotype.Service

interface HealthApi {
    fun ping(payload: String): String
}

class RealHealthApi : HealthApi {
    override fun ping(payload: String): String {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:health")
        conn.createStatement().executeQuery("SELECT * FROM health WHERE p = '" + payload + "'")
        return payload
    }
}

val healthModule = module {
    single<HealthApi> { RealHealthApi() }
}

// Unprovided sibling with a sink, for the same reason as FakeUserApi: the
// 2.x spelling's narrowing is only observable against a second candidate.
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~StubHealthApi.ping
class StubHealthApi : HealthApi {
    override fun ping(payload: String): String {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:stub")
        conn.createStatement().executeQuery("SELECT * FROM health WHERE p = '" + payload + "'")
        return payload
    }
}

@Service
class HealthEntry(private val api: HealthApi) {
    fun handle() {
        val raw = readLine() ?: ""
        api.ping(raw)
    }
}
