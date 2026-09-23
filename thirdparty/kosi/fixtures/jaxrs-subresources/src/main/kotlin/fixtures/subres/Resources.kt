// JAX-RS sub-resource locators (Jakarta RESTful Web Services 3.1 §3.4.1):
// a resource method with @Path and NO request method designator is a
// LOCATOR. The object it returns handles the rest of the request, so its
// methods are served under the locator's path, and the returned class
// needs no @Path of its own. Locators chain.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=quarkus path=/customers method=GET fn=~CustomerResource.list mode=resolved
// kosi:want endpoint framework=quarkus path=/customers/{id} method=GET fn=~CustomerSub.get mode=resolved
// kosi:want endpoint framework=quarkus path=/customers/{id} method=DELETE fn=~CustomerSub.remove mode=resolved
// kosi:want endpoint framework=quarkus path=/customers/{id}/orders method=GET fn=~OrderSub.all mode=resolved
// kosi:want endpoint framework=quarkus path=/customers/{id}/orders/{orderId}/cancel method=POST fn=~OrderSub.cancel mode=resolved
//
// Negative half: a locator is not itself an endpoint; a located class is
// never served at the root; a class nothing locates is not served at all.
// kosi:want-not endpoint framework=quarkus fn=~CustomerResource.customer
// kosi:want-not endpoint framework=quarkus fn=~CustomerSub.orders
// kosi:want-not endpoint framework=quarkus path=/orders
// kosi:want-not endpoint framework=quarkus path=/
// kosi:want-not endpoint framework=quarkus fn=~Orphan.lonely
//
// A root resource that a locator also returns is served at both.
// kosi:want endpoint framework=quarkus path=/invoices method=GET fn=~InvoiceResource.all mode=resolved
// kosi:want endpoint framework=quarkus path=/customers/{id}/invoices method=GET fn=~InvoiceResource.all mode=resolved
package fixtures.subres

import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam

@Path("/customers")
class CustomerResource {
    @GET
    fun list(): String = "[]"

    @Path("{id}")
    fun customer(@PathParam("id") id: String): CustomerSub = CustomerSub(id)
}

class CustomerSub(private val id: String) {
    @GET
    fun get(): String = id

    @DELETE
    fun remove(): String = id

    @Path("orders")
    fun orders(): OrderSub = OrderSub()

    @Path("invoices")
    fun invoices(): InvoiceResource = InvoiceResource()
}

class OrderSub {
    @GET
    fun all(): String = "[]"

    @POST
    @Path("{orderId}/cancel")
    fun cancel(@PathParam("orderId") orderId: String): String = orderId
}

@Path("/invoices")
class InvoiceResource {
    @GET
    fun all(): String = "[]"
}

// Never located by anything: its methods are not served anywhere.
class Orphan {
    @GET
    fun lonely(): String = "x"
}
