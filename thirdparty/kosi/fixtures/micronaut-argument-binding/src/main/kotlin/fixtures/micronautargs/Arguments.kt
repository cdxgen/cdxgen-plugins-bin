// P27 §2 — micronaut's ARGUMENT BINDING rule, one handler per framework-supplied type.
//
// From docs.micronaut.io HTTP guide, Simple Request Binding, verbatim:
//
//   "If there is a @Body and request allows the body, bind the body to it. If the request can have a body and no @Body is defined then try to parse the body (either JSON or form data) and bind the method arguments from the body."
//
// kosi had this framework as handlerInput=annotated, which seeds NOTHING for
// a handler that binds without annotations. Each want-not below is one
// framework-supplied type: drop its pack entry and that handler reports.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_io_micronaut_http_HttpRequest
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_io_micronaut_http_HttpResponse
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_io_micronaut_http_BasicAuth
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_io_micronaut_security_authentication_Authentication
// kosi:want flow source=untrusted-input sink=process-exec fn=~unannotatedIsBound mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~unannotatedSimpleIsBound mode=endpoint
package fixtures.micronautargs

/** What the framework binds from the request. */
class Command {
    var value: String = ""
}

@io.micronaut.http.annotation.Controller("/api")
class ArgumentApi {

    @io.micronaut.http.annotation.Get
    fun ctx_io_micronaut_http_HttpRequest(arg: io.micronaut.http.HttpRequest): Process =
        ProcessBuilder(arg.toString()).start()

    @io.micronaut.http.annotation.Get
    fun ctx_io_micronaut_http_HttpResponse(arg: io.micronaut.http.HttpResponse): Process =
        ProcessBuilder(arg.toString()).start()

    @io.micronaut.http.annotation.Get
    fun ctx_io_micronaut_http_BasicAuth(arg: io.micronaut.http.BasicAuth): Process =
        ProcessBuilder(arg.toString()).start()

    @io.micronaut.http.annotation.Get
    fun ctx_io_micronaut_security_authentication_Authentication(arg: io.micronaut.security.authentication.Authentication): Process =
        ProcessBuilder(arg.toString()).start()

    /**
     * The rule this fixture exists for: an unannotated parameter is bound
     * from the request, so it carries attacker input.
     */
    @io.micronaut.http.annotation.Post
    fun unannotatedIsBound(payload: Command): Process = ProcessBuilder(payload.value).start()

    /** A simple type binds as a scalar, and is input just the same. */
    @io.micronaut.http.annotation.Get
    fun unannotatedSimpleIsBound(term: String): Process = ProcessBuilder(term).start()
}
