// The jakarta generation of JAX-RS media annotations: the media types sit
// in the annotation's positional VALUE argument, not in named ones — the
// second of the two shapes P14 reads.
package jakarta.ws.rs

annotation class GET
annotation class Path(val value: String)
annotation class Consumes(val value: Array<String>)
annotation class Produces(val value: Array<String>)
