// A paging-only repository under spring-data-commons 3: it HAS findAll and
// nothing else, so Spring Data REST serves the collection GET/HEAD and no
// write verb and no item route. Publishing POST/PUT/DELETE here describes a
// read-only resource as writable. A CrudRepository beside it keeps them.
//
// kosi:want endpoint framework=spring-mvc path=/widgets method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/gadgets method=POST mode=resolved
// kosi:want endpoint framework=spring-mvc path=/gadgets/{id} method=DELETE mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/widgets method=POST
// kosi:want-not endpoint framework=spring-mvc path=/widgets/{id}
// kosi:want-not diagnostic code=repository-crud-unknown
package fixtures.datacommons

import org.springframework.data.repository.CrudRepository
import org.springframework.data.repository.PagingAndSortingRepository

class Widget(val id: Long = 0)
interface WidgetRepository : PagingAndSortingRepository<Widget, Long>

class Gadget(val id: Long = 0)
interface GadgetRepository : CrudRepository<Gadget, Long>
