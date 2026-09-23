// Spring Data REST under a base path from config, beside a plain MVC
// controller that is NOT under it. Before: the @RepositoryRestController
// matched no class marker (it is a @Component, not a @Controller), and the
// repository published one `/orders` route with PUT and DELETE on the
// collection and the hidden delete still served.
//
// kosi:want endpoint framework=spring-mvc path=/svc/api/data/orders/{id}/cancel method=POST pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/svc/ping method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/svc/api/data/orders method=POST mode=resolved
// kosi:want endpoint framework=spring-mvc path=/svc/api/data/orders method=HEAD mode=resolved
// kosi:want endpoint framework=spring-mvc path=/svc/api/data/orders/{id} method=PATCH mode=resolved
// kosi:want endpoint framework=spring-mvc path=/svc/api/data/orders/search/findByStatus method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/svc/api/data/orders/search/by-customer method=GET mode=resolved
//
// Negative half: delete(T) is exported=false, so the item serves no
// DELETE; PUT is never a collection verb; a plain @RestController is not
// under the data-rest base; a hidden query method has no search route.
// kosi:want-not endpoint framework=spring-mvc path=/svc/api/data/orders/{id} method=DELETE
// kosi:want-not endpoint framework=spring-mvc path=/svc/api/data/orders method=PUT
// kosi:want-not endpoint framework=spring-mvc path=/svc/api/data/ping
// kosi:want-not endpoint framework=spring-mvc path=/svc/api/data/orders/search/findByToken
// kosi:want-not endpoint framework=spring-mvc path=/orders
// kosi:want-not diagnostic code=repository-crud-unknown
// kosi:want-not diagnostic code=parse-error
package fixtures.datarest

import org.springframework.data.repository.PagingAndSortingRepository
import org.springframework.data.rest.core.annotation.RestResource
import org.springframework.data.rest.webmvc.RepositoryRestController
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

class Order(val id: Long = 0, val status: String = "")

interface OrderRepository : PagingAndSortingRepository<Order, Long> {
    @RestResource(exported = false)
    override fun delete(entity: Order)

    fun findByStatus(status: String): List<Order>

    @RestResource(path = "by-customer")
    fun findByCustomer(customer: String): List<Order>

    @RestResource(exported = false)
    fun findByToken(token: String): List<Order>
}

@RepositoryRestController
class OrderCommands {
    @RequestMapping(value = ["/orders/{id}/cancel"], method = [RequestMethod.POST])
    fun cancel(@PathVariable id: Long): String = "cancelled $id"
}

@RestController
class PlainApi {
    @GetMapping("/ping")
    fun ping(): String = "pong"
}
