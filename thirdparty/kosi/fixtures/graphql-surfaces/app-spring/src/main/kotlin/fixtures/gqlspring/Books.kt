// Spring GraphQL with every optional surface switched on in config: the
// WebSocket transport (off until spring.graphql.websocket.path is set),
// GraphiQL and the schema printer (both off by default). @BatchMapping is
// a field fetcher served at the one GraphQL endpoint like any other.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=graphql path=/graphql method=POST fn=~BookController.book mode=resolved
// kosi:want endpoint framework=graphql path=/graphql method=POST fn=~BookController.authors mode=resolved
// kosi:want endpoint framework=graphql path=/graphql-ws method=GET fn=~BookController.bookAdded mode=resolved
// kosi:want endpoint framework=graphql path=/graphql-ws method=GET fn=~BookController.book mode=resolved
// kosi:want endpoint framework=graphql path=/graphiql method=GET mode=resolved
// kosi:want endpoint framework=graphql path=/graphql/schema method=GET mode=resolved
package fixtures.gqlspring

import org.springframework.graphql.data.method.annotation.Argument
import org.springframework.graphql.data.method.annotation.BatchMapping
import org.springframework.graphql.data.method.annotation.QueryMapping
import org.springframework.graphql.data.method.annotation.SubscriptionMapping
import org.springframework.stereotype.Controller

class Book(val id: String)
class Author(val name: String)

@Controller
class BookController {
    @QueryMapping
    fun book(@Argument id: String): Book = Book(id)

    @BatchMapping
    fun authors(books: List<Book>): Map<Book, Author> = emptyMap()

    @SubscriptionMapping
    fun bookAdded(): Book = Book("x")
}
