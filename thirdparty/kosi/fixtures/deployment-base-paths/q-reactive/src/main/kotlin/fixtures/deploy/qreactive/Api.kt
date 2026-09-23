package fixtures.deploy.qreactive

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path

@Path("/q")
class Res {
    @GET
    @Path("/x")
    fun x(): String = "x"
}
