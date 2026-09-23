package fixtures.deploy.gqlhttppath

import org.springframework.graphql.data.method.annotation.QueryMapping
import org.springframework.stereotype.Controller

@Controller
class Graph {
    @QueryMapping
    fun book(): String = "b"
}
