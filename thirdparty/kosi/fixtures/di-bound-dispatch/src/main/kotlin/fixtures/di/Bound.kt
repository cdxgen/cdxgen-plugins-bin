// P25 §2 — the target that is only one: DI is dispatch evidence.
//
// The service boundary of every Spring, Micronaut, Hilt or CDI application
// has this shape: an interface with several implementations, none of them
// ever constructed by user code, because the CONTAINER constructs the one
// its annotation names. RTA, which keeps only candidates whose owner is
// instantiated, therefore dropped every candidate and the interface call
// resolved to nothing — the taint died at the boundary with no diagnostic,
// which is a false negative in the shape that matters most.
//
// A stereotype is a construction site the framework performs. With that,
// the bound implementation is live, the flow is found, and because the
// OTHER implementations are not bound, the site narrows to one target and
// the edge says `di-binding` — narrowing that rests on an annotation, named
// as such, distinct from narrowing that rests on a `new`.
//
// Negative half first: the two unbound implementations must not carry the
// finding — a container that binds `JdbcStore` does not run `LoggingStore`,
// and a smear across the hierarchy would publish both.
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~LoggingStore
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~InMemoryStore
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the bound implementation, reached through the interface.
// kosi:want flow source=untrusted-input sink=sql-query fn=~JdbcStore.save known-fail=syntax:1
//
// The `di-binding` NARROWING REASON is asserted by DiDispatchTest rather
// than by an edge want: under `--roots exported` every public class is a
// possible root, so the graph rightly treats all three implementations as
// live and the label cannot appear in that slot. The place the binding
// actually decided something is the flow engine's dispatch, and that is
// where the test looks.
package fixtures.di

import org.springframework.stereotype.Component
import org.springframework.stereotype.Service

interface AuditStore {
    fun save(record: String)
}

// The BOUND implementation: the container constructs this one.
@Component
class JdbcStore : AuditStore {
    override fun save(record: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:audit")
        conn.createStatement().executeQuery("INSERT INTO audit VALUES ('" + record + "')")
    }
}

// Two siblings with no stereotype: real implementations of the interface
// that this application never wires. They are what a CHA-only answer would
// smear the finding across.
class LoggingStore : AuditStore {
    override fun save(record: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:log")
        conn.createStatement().executeQuery("INSERT INTO log VALUES ('" + record + "')")
    }
}

class InMemoryStore : AuditStore {
    private val rows = mutableListOf<String>()

    override fun save(record: String) {
        rows.add(record)
    }
}

// Constructor injection: the service names the INTERFACE and never the
// implementation, which is the whole point of the container and the reason
// the implementation is unreachable without the stereotype.
@Service
class AuditService(private val store: AuditStore) {
    fun record(raw: String) {
        store.save(raw)
    }
}

@Service
class AuditEntry(private val service: AuditService) {
    fun handle() {
        val raw = readLine() ?: ""
        service.record(raw)
    }
}
