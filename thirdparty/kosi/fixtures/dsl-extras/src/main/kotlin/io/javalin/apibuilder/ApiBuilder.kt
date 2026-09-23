package io.javalin.apibuilder

interface CrudHandler

object ApiBuilder {
    @JvmStatic fun path(path: String, endpointGroup: () -> Unit) {}
    @JvmStatic fun crud(path: String, crudHandler: CrudHandler) {}
    @JvmStatic fun ws(path: String, ws: (Any) -> Unit) {}
    @JvmStatic fun sse(path: String, client: (Any) -> Unit) {}
}
