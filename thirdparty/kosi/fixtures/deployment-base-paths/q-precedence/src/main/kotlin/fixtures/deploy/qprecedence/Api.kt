package fixtures.deploy.qprecedence

import jakarta.ws.rs.ApplicationPath
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path

@Path("/q")
class Res {
    @GET
    @Path("/x")
    fun x(): String = "x"
}

// The property wins over the annotation (quarkus.io/guides/rest).
@ApplicationPath("/annotation")
class App
