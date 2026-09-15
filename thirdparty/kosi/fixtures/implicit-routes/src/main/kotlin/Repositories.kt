// Routes that exist with NO handler anywhere in this source.
//
// Spring Data REST exposes every repository interface as a collection
// resource named after the entity, with the full verb set, without anyone
// writing a controller. Spring Boot Actuator and springdoc publish their
// trees because the artifact is on the classpath. These are among the most
// probed paths on any Spring deployment, and a scanner that only reads
// handlers reports none of them — it reports an attack surface that is
// missing exactly the parts an attacker looks for first.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Repository-implied collections, pluralised the regular way.
// kosi:want endpoint framework=spring-mvc path=/orders mode=resolved
// kosi:want endpoint framework=spring-mvc path=/categories mode=resolved
//
// Dependency-implied trees. Actuator's base path is its own config key, so
// `/ops/health` is the served URL and `/actuator/health` is not.
// kosi:want endpoint framework=spring-actuator path=/ops/health mode=resolved
// kosi:want endpoint framework=springdoc path=/v3/api-docs mode=resolved
// kosi:want-not endpoint framework=spring-actuator path=/actuator/health
//
// A plain interface is not a repository.
// kosi:want-not endpoint framework=spring-mvc path=/settings
package fixtures.implicitroutes

import org.springframework.data.repository.CrudRepository

class Order(val id: Long = 0)
class Category(val id: Long = 0)

/** Exposed at `/orders` by Spring Data REST. */
interface OrderRepository : CrudRepository<Order, Long> {
    override fun findById(id: Long): Order?
}

/** Consonant + y pluralises to `-ies`, as Spring's own inflector does. */
interface CategoryRepository : CrudRepository<Category, Long> {
    override fun findById(id: Long): Category?
}

/** The near-miss: not a repository, so not a route. */
interface SettingsRepository {
    fun load(): String
}
