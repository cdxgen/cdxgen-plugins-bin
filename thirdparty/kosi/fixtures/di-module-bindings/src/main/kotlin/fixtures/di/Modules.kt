// P26 §2 — finish the container: the binding is a mapping, written in a
// module, and it is dispatch evidence exactly as a stereotype is.
//
// P25 read the ANNOTATED half of the wiring (a stereotype is a construction
// site the framework performs). What a real app uses as much is the BINDING
// METHOD — `@Binds` never constructs anything, `@Bean`/`@Provides` often
// return a parameter instead of constructing, and Koin's provider lambdas
// construct inside a lambda the container invokes. Four spellings, one
// question: which implementation runs?
//
// Positive halves (each must land on the BOUND implementation only):
// kosi:want flow source=untrusted-input sink=sql-query fn=~JdbcAuditStore.save known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~StripeGateway.charge known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~RealUserApi.fetch known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~SlackNotifier.notify known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~EmailNotifier.notify known-fail=syntax:1
//
// Negative halves (the unbound siblings must stay clean — a container that
// binds one implementation does not run its siblings):
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~NoopAuditStore.save
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~FakeUserApi.fetch
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~SandboxGateway.charge
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~PagerNotifier.notify
// kosi:want-not diagnostic code=parse-error
//
// The TWO-BINDINGS shape (Notifier) is the phase's answer to "what do you
// publish when the container manages two implementations of one interface":
// BOTH findings, a dispatch width of 2, and the narrowing reason
// `di-binding` — asserted by DiBindingFormsTest, which can state the width
// and the label in a way a corpus annotation cannot.
package fixtures.di

import dagger.Binds
import dagger.Module
import org.koin.core.module.module
import org.koin.core.module.dsl.single
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Service

// ---- @Binds: the binding never constructs --------------------------------
//
// No `JdbcAuditStore()` appears anywhere in this program. The parameter TYPE
// is the entire construction evidence, which is why a stereotype-only reader
// never saw it.

interface AuditStore {
    fun save(record: String)
}

class JdbcAuditStore : AuditStore {
    override fun save(record: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:audit")
        conn.createStatement().executeQuery("INSERT INTO audit VALUES ('" + record + "')")
    }
}

class NoopAuditStore : AuditStore {
    // The sink is deliberate: a sibling whose body CANNOT sink makes the
    // want-not vacuous — under the pre-P26 smear this finding appears, and
    // only a sibling that would sink can show that.
    override fun save(record: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:noop")
        conn.createStatement().executeQuery("INSERT INTO noop VALUES ('" + record + "')")
    }
}

@Module
abstract class AuditModule {
    @Binds
    abstract fun bindAuditStore(impl: JdbcAuditStore): AuditStore
}

// ---- @Bean returning a parameter: the @Inject-constructor idiom ----------

interface PaymentGateway {
    fun charge(token: String)
}

class StripeGateway : PaymentGateway {
    override fun charge(token: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:pay")
        conn.createStatement().executeQuery("INSERT INTO charges VALUES ('" + token + "')")
    }
}

class SandboxGateway : PaymentGateway {
    override fun charge(token: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:sandbox")
        conn.createStatement().executeQuery("INSERT INTO charges VALUES ('" + token + "')")
    }
}

@Configuration
class PaymentConfig {
    // The body constructs nothing: it hands back a parameter the container
    // constructed elsewhere (the implementation's own constructor is
    // `@Inject`-annotated in the shape this stands in for).
    @Bean
    fun paymentGateway(impl: StripeGateway): PaymentGateway = impl
}

// ---- Koin's provider lambdas ----------------------------------------------
//
// `single<UserApi> { RealUserApi() }` — the construction is inside a lambda
// the container invokes; the interface is the call's type argument, which no
// table carries, but the implementation in the lambda body is the half
// dispatch needs.

interface UserApi {
    fun fetch(id: String): String
}

class RealUserApi : UserApi {
    override fun fetch(id: String): String {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:users")
        conn.createStatement().executeQuery("SELECT * FROM users WHERE id = '" + id + "'")
        return id
    }
}

val userModule = module {
    single<UserApi> { RealUserApi() }
}

// A second implementation the module never provides. Its sink is deliberate
// (a clean body would make the want-not vacuous): if the provider lambda is
// not read as a construction site, nothing narrows UserApi and this class's
// finding appears as the smear.
class FakeUserApi : UserApi {
    override fun fetch(id: String): String {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:fake")
        conn.createStatement().executeQuery("SELECT * FROM users WHERE id = '" + id + "'")
        return id
    }
}

// ---- Two bindings, one interface -----------------------------------------
//
// SlackNotifier and EmailNotifier are both bound (two @Bean methods, both
// constructing); PagerNotifier is a third implementation nothing wires. The
// honest output is a finding on EACH bound implementation and none on the
// pager: the site dispatches to width 2, narrowed by the bindings.

interface Notifier {
    fun notify(message: String)
}

class SlackNotifier : Notifier {
    override fun notify(message: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:slack")
        conn.createStatement().executeQuery("INSERT INTO outbox VALUES ('" + message + "')")
    }
}

class EmailNotifier : Notifier {
    override fun notify(message: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:mail")
        conn.createStatement().executeQuery("INSERT INTO outbox VALUES ('" + message + "')")
    }
}

class PagerNotifier : Notifier {
    override fun notify(message: String) {
        val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:pager")
        conn.createStatement().executeQuery("INSERT INTO outbox VALUES ('" + message + "')")
    }
}

@Configuration
class NotifierConfig {
    @Bean
    fun slackNotifier(): Notifier = SlackNotifier()

    @Bean
    fun emailNotifier(): Notifier = EmailNotifier()
}

// ---- The service boundary that exercises all four -------------------------

@Service
class ModulesApp(
    private val audit: AuditStore,
    private val payment: PaymentGateway,
    private val api: UserApi,
    private val notifier: Notifier,
) {
    fun handle() {
        val raw = readLine() ?: ""
        audit.save(raw)
        payment.charge(raw)
        api.fetch(raw)
        notifier.notify(raw)
    }
}
