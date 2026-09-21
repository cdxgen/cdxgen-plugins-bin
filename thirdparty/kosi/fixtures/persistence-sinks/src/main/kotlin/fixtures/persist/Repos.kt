// — persistence as sinks.
//
// The repository interface is where a real Kotlin service's value EXITS: a
// Spring Data repository method (a DERIVED query name or @Query) is executed
// by the framework's generated proxy — there is no body to walk, and the
// interface is USER code, so no sink pattern can name its FQN. The pack's
// interfaceSinks rows match what the DECLARATION carries instead: the
// repository base it extends, or the @Dao/@Query annotations. Room DAOs are
// the same shape on Android; Exposed's Transaction.exec is a plain call.
//
// Positive halves:
// kosi:want flow source=untrusted-input sink=sql-query fn=~derivedQueryFlow known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~annotatedQueryFlow known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~roomQueryFlow known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~exposedFlow known-fail=syntax:1
//
// Negative halves:
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~plainInterfaceFlow
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~cleanArgsNoFlow
// kosi:want-not diagnostic code=parse-error
package fixtures.persist

import androidx.room.Dao
import androidx.room.Query
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.repository.PagingAndSortingRepository
import org.springframework.data.repository.Repository
import org.springframework.data.jpa.repository.Query as SpringQuery

data class User(val name: String, val lastName: String)

interface UserRepo : JpaRepository<User, Long> {
    // A DERIVED query: the method name IS the query declaration; the
    // framework derives and executes it. kosi does not derive the SQL, and
    // the finding says so by its shape (the callee, not a query string).
    fun findByLastName(lastName: String): List<User>

    @SpringQuery("SELECT u FROM User u WHERE u.name = :name")
    fun byName(name: String): User
}

@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE name = :name")
    fun byName(name: String): List<User>
}

// The ROOT base spelled directly: `Repository` with a derived method.
interface CountRepo : Repository<User, Long> {
    fun countByLastName(lastName: String): Long
}

// The paging base, a third real spelling of the same capability.
interface PagedRepo : PagingAndSortingRepository<User, Long> {
    fun findByName(name: String): List<User>
}

// The NEGATIVE interface: same method-name shape, no repository base, no
// annotations — a plain user interface whose call must not be a sink.
interface Greeter {
    fun findByLastName(lastName: String): String
}

fun derivedQueryFlow(repo: UserRepo) {
    val raw = readLine() ?: ""
    repo.findByLastName(raw)
}

fun annotatedQueryFlow(repo: UserRepo) {
    val raw = readLine() ?: ""
    repo.byName(raw)
}

fun roomQueryFlow(dao: UserDao) {
    val raw = readLine() ?: ""
    dao.byName(raw)
}

fun plainInterfaceFlow(greeter: Greeter) {
    val raw = readLine() ?: ""
    greeter.findByLastName(raw)
}

fun cleanArgsNoFlow(repo: UserRepo) {
    repo.findByLastName("constant")
}

// kosi:want flow source=untrusted-input sink=sql-query fn=~rootBaseFlow known-fail=syntax:1
fun rootBaseFlow(repo: CountRepo) {
    val raw = readLine() ?: ""
    repo.countByLastName(raw)
}

fun exposedFlow(tx: org.jetbrains.exposed.sql.Transaction) {
    val raw = readLine() ?: ""
    tx.exec("UPDATE users SET name = '" + raw + "'")
}

// kosi:want flow source=untrusted-input sink=sql-query fn=~pagingBaseFlow known-fail=syntax:1
fun pagingBaseFlow(repo: PagedRepo) {
    val raw = readLine() ?: ""
    repo.findByName(raw)
}
