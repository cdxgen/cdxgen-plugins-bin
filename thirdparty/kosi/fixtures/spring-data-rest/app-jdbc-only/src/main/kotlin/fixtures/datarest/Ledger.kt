// No Spring Data REST in this module: a CrudRepository here serves no HTTP
// route. The corpus measured 37 spurious repository endpoints from
// data-jdbc/data-jpa modules before the dependency gate.
//
// kosi:want-not endpoint framework=spring-mvc path=/ledgers
// kosi:want-not endpoint framework=spring-mvc path=/ledgers/{id}
package fixtures.datarest

import org.springframework.data.repository.CrudRepository

class Ledger(val id: Long = 0)

interface LedgerRepository : CrudRepository<Ledger, Long>
