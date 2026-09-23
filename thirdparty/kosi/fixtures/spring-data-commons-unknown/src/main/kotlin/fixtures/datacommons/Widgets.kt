// The same paging-only repository with NO spring-data-commons coordinate on
// the classpath: the generation is unknown, so only the routes every
// generation serves are published, and the run says so.
//
// kosi:want endpoint framework=spring-mvc path=/widgets method=GET mode=resolved
// kosi:want diagnostic code=repository-crud-unknown mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/widgets method=POST
// kosi:want-not endpoint framework=spring-mvc path=/widgets/{id}
package fixtures.datacommons

import org.springframework.data.repository.PagingAndSortingRepository

class Widget(val id: Long = 0)
interface WidgetRepository : PagingAndSortingRepository<Widget, Long>
