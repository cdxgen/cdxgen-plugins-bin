// The javax generation of JAX-RS routing: GET and PATCH (added the
// PATCH twin — jakarta shipped it, javax did not), the parameter binding
// annotations, and the media annotations.
package javax.ws.rs

annotation class GET
annotation class PATCH
annotation class Path(val value: String)
annotation class QueryParam(val value: String)
annotation class PathParam(val value: String)
annotation class BeanParam
annotation class Consumes(val value: String)
annotation class Produces(val value: String)
