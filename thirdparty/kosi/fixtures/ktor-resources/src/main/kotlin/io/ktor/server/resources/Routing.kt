// Ktor's typed-routing builders, at their real fully-qualified names. The
// path is NOT an argument here: it comes from the type argument's class.
package io.ktor.server.resources

class Route

inline fun <reified T> Route.get(noinline body: (T) -> Unit) {}
inline fun <reified T> Route.post(noinline body: (T) -> Unit) {}
