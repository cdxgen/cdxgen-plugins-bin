// ratpack.io/manual/current/handlers.html: "a handler is just a function that
// acts on a handling context" — `void handle(Context context)`. The context is
// the framework's own collaborator; request data comes through getRequest().
package ratpack.core.handling

import ratpack.core.http.Request

interface Context {
    fun getRequest(): Request
    fun render(o: Any?)
}

interface Handler {
    fun handle(context: Context)
}
