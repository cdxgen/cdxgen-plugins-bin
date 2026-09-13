// Positive half: JAX-RS resources - the class-level @Path is the marker and
// the prefix, the method annotations carry the verb.
// kosi:want endpoint framework=quarkus path=/widgets fn=~WidgetResource.list method=GET mode=resolved
// kosi:want endpoint framework=quarkus path=/widgets fn=~WidgetResource.add method=POST mode=resolved
// kosi:want-not endpoint framework=quarkus fn=~NoMethodsResource mode=resolved
// kosi:want-not endpoint framework=quarkus path=~/gadgets mode=resolved
package fixtures.quarkus

import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path

@Path("/widgets")
class WidgetResource {
    @GET
    fun list(): List<String> = listOf("w1")

    @POST
    fun add(name: String): String = name
}

// @Path("/gadgets") with no resource methods publishes nothing, and a
// commented-out @GET stays commented:
// @GET
// fun ghost(): String = "nope"
class NoMethodsResource
