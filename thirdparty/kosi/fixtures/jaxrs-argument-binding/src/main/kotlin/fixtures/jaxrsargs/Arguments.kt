// P27 §2 — quarkus's ARGUMENT BINDING rule, one handler per framework-supplied type.
//
// From Jakarta RESTful Web Services 3.1 specification, §3.3.2.1, verbatim:
//
//   "The value of a parameter not annotated with @FormParam or any of the annotations listed in Fields and Bean Properties, called the entity parameter, is mapped from the request entity body. Resource methods MUST have at most one entity parameter."
//
// kosi had this framework as handlerInput=annotated, which seeds NOTHING for
// a handler that binds without annotations. Each want-not below is one
// framework-supplied type: drop its pack entry and that handler reports.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_core_UriInfo
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_core_HttpHeaders
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_core_SecurityContext
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_core_Request
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_core_Application
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_core_Configuration
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_ext_Providers
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_container_ResourceContext
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_sse_Sse
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_ws_rs_sse_SseEventSink
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_core_UriInfo
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_core_HttpHeaders
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_core_SecurityContext
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_core_Request
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_core_Application
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_core_Configuration
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_ext_Providers
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_javax_ws_rs_container_ResourceContext
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_jakarta_ws_rs_core_Context
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_javax_ws_rs_core_Context
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_jakarta_ws_rs_container_Suspended
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_javax_ws_rs_container_Suspended
// kosi:want flow source=untrusted-input sink=process-exec fn=~unannotatedIsBound mode=endpoint
package fixtures.jaxrsargs

/** What the framework binds from the request. */
class Command {
    var value: String = ""
}

@jakarta.ws.rs.Path("/api")
class ArgumentApi {

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_core_UriInfo(arg: jakarta.ws.rs.core.UriInfo): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_core_HttpHeaders(arg: jakarta.ws.rs.core.HttpHeaders): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_core_SecurityContext(arg: jakarta.ws.rs.core.SecurityContext): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_core_Request(arg: jakarta.ws.rs.core.Request): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_core_Application(arg: jakarta.ws.rs.core.Application): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_core_Configuration(arg: jakarta.ws.rs.core.Configuration): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_ext_Providers(arg: jakarta.ws.rs.ext.Providers): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_container_ResourceContext(arg: jakarta.ws.rs.container.ResourceContext): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_sse_Sse(arg: jakarta.ws.rs.sse.Sse): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_jakarta_ws_rs_sse_SseEventSink(arg: jakarta.ws.rs.sse.SseEventSink): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_core_UriInfo(arg: javax.ws.rs.core.UriInfo): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_core_HttpHeaders(arg: javax.ws.rs.core.HttpHeaders): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_core_SecurityContext(arg: javax.ws.rs.core.SecurityContext): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_core_Request(arg: javax.ws.rs.core.Request): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_core_Application(arg: javax.ws.rs.core.Application): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_core_Configuration(arg: javax.ws.rs.core.Configuration): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_ext_Providers(arg: javax.ws.rs.ext.Providers): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ctx_javax_ws_rs_container_ResourceContext(arg: javax.ws.rs.container.ResourceContext): Process =
        ProcessBuilder(arg.toString()).start()

    @jakarta.ws.rs.GET
    fun ann_jakarta_ws_rs_core_Context(@jakarta.ws.rs.core.Context arg: String): Process = ProcessBuilder(arg).start()

    @jakarta.ws.rs.GET
    fun ann_javax_ws_rs_core_Context(@javax.ws.rs.core.Context arg: String): Process = ProcessBuilder(arg).start()

    @jakarta.ws.rs.GET
    fun ann_jakarta_ws_rs_container_Suspended(@jakarta.ws.rs.container.Suspended arg: String): Process = ProcessBuilder(arg).start()

    @jakarta.ws.rs.GET
    fun ann_javax_ws_rs_container_Suspended(@javax.ws.rs.container.Suspended arg: String): Process = ProcessBuilder(arg).start()

    /**
     * The rule this fixture exists for: an unannotated parameter is bound
     * from the request, so it carries attacker input.
     */
    @jakarta.ws.rs.POST
    fun unannotatedIsBound(payload: Command): Process = ProcessBuilder(payload.value).start()
}
