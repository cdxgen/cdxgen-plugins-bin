// javalin 6/7 by shape: ApiBuilder's STATIC builders (Java statics, spelled
// as @JvmStatic here), each verb with and without a path; path(..) nests.
package io.javalin.apibuilder

import io.javalin.http.Handler

object ApiBuilder {
    @JvmStatic fun path(path: String, endpointGroup: () -> Unit) {}
    @JvmStatic fun get(path: String, handler: Handler) {}
    @JvmStatic fun post(path: String, handler: Handler) {}
    @JvmStatic fun put(path: String, handler: Handler) {}
    @JvmStatic fun patch(path: String, handler: Handler) {}
    @JvmStatic fun delete(path: String, handler: Handler) {}
    @JvmStatic fun head(path: String, handler: Handler) {}
}
