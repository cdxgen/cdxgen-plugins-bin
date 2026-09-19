package io.cdxgen.kosi.models

import io.cdxgen.kosi.schema.JsonReader

/**
 * The framework registry (P7) and its loader. Everything the endpoint,
 * service and URL detectors match against lives here as DATA — the detectors
 * in kosi-endpoints hard-code no framework, exactly like the taint engine
 * hard-codes no category. A framework this pack does not name is invisible
 * by construction; adding one is a data change plus its fixtures.
 */
data class MappingAnnotation(
    val pattern: String,
    val methods: List<String>,
    /** A nesting route-shaper (`route("/x") { .. }`) contributes its path to descendants and publishes no endpoint itself. */
    val nesting: Boolean = false,
)

/** One framework's detection data. [kind] is `annotation`, `dsl`, `supertype` or `manifest`. */
data class FrameworkModel(
    val id: String,
    val kind: String,
    val classMarkers: List<String> = emptyList(),
    val mappingAnnotations: List<MappingAnnotation> = emptyList(),
    val pathPrefixAnnotations: List<String> = emptyList(),
    val dslFunctions: List<MappingAnnotation> = emptyList(),
    val bindFunctions: List<MappingAnnotation> = emptyList(),
    val supertypeMarkers: List<String> = emptyList(),
    val supertypeSuffixes: List<String> = emptyList(),
    val manifestComponents: List<String> = emptyList(),
    /**
     * Which annotated parameters of a handler carry attacker input, and what
     * KIND of input. Without this the taint engine can only seed EVERY
     * parameter of an endpoint handler — tainting the injected repository
     * and the authenticated principal beside the query string — and the
     * report cannot say whether a finding entered through the path, the
     * query, a header or the body.
     */
    val parameterAnnotations: List<ParameterAnnotation> = emptyList(),
    /**
     * HOW this framework hands input to a handler. The three shapes need
     * three different seedings, and treating them alike is the difference
     * between reading a framework and pattern-matching it:
     *
     *  - `annotated` - the signature names its transports (`@RequestParam`,
     *    `@PathVariable`, `@QueryParam`). Seed exactly the annotated
     *    parameters; an unannotated one is an injected collaborator.
     *  - `context` - the handler receives a REQUEST CONTEXT
     *    (`HttpServletRequest`, Javalin's `Context`, Ktor's
     *    `ApplicationCall`, Vert.x's `RoutingContext`). The context is not
     *    itself data: input comes out of it through reader methods the
     *    security pack models as sources. Seeding the context taints
     *    everything reachable from it - including the RESPONSE object a
     *    servlet handler is handed in the same signature.
     *  - `annotated-or-bound` - the signature names SOME transports, and
     *    everything else that is not a framework collaborator is bound from
     *    the request anyway (Spring MVC's command objects). Seed the
     *    annotated parameters by their transport, and every unannotated
     *    parameter whose type is not in [contextParameterTypes].
     *  - `all` - the handler's parameter IS the payload (a gRPC request
     *    message, a Lambda event, an Android lifecycle Bundle). This is the
     *    default, so a framework that says nothing keeps its behaviour.
     */
    val handlerInput: String = HANDLER_INPUT_ALL,
    /**
     * P27 §2: the types a handler parameter may have that are NOT request
     * data — the framework's own collaborators, handed to the method beside
     * the input (`Model`, `BindingResult`, `HttpServletRequest`,
     * `WebDataBinder`, `Principal`, `RedirectAttributes`, a model `Map`).
     *
     * This exists because `annotated` is the wrong rule for Spring MVC and
     * measuring said so. Spring binds an UNANNOTATED, non-context parameter
     * from the request — the implicit `@ModelAttribute` command object, the
     * form-handling idiom the framework's own sample application is written
     * in. Seeding only annotated parameters found three flows in
     * spring-petclinic and missed every `processCreationForm`,
     * `processUpdateForm` and `processFindForm` in it: six handlers whose
     * entire input was invisible.
     *
     * The rule a framework declares with [HANDLER_INPUT_ANNOTATED_OR_BOUND]
     * is therefore "annotated parameters by their transport, plus every
     * other parameter whose type is not named here". Listing the context
     * types rather than guessing at the data ones keeps the failure
     * direction right: a type we forgot to list produces a finding to
     * triage, not a silence.
     */
    val contextParameterTypes: List<String> = emptyList(),
    /**
     * P27 §2: annotations that mean "the framework supplies this parameter",
     * as opposed to binding it from the request.
     *
     * Needed because the presence of SOME annotation says nothing: Spring
     * binds `@Valid owner: Owner` from the form exactly as it binds a bare
     * `owner: Owner` — `@Valid` asks for validation, not for injection. A
     * rule that read "annotated, but not with a transport, therefore
     * injected" dropped every validated command object in
     * spring-petclinic, which is most of them.
     *
     * So only these annotations exclude a parameter, and the type list does
     * the rest.
     */
    val nonInputAnnotations: List<String> = emptyList(),
    /**
     * P27 §2: the types Spring calls SIMPLE, from `BeanUtils.isSimpleValueType`
     * — "a primitive or primitive wrapper, an Enum, a String or other
     * CharSequence, a Number, a Date, a Temporal, a UUID, a URI, a URL, a
     * Locale, or a Class".
     *
     * The distinction is in the framework's own fallback rule and it decides
     * the TRANSPORT: an unannotated simple type is resolved as a
     * `@RequestParam` (a scalar out of the query string), anything else as a
     * `@ModelAttribute` (a command object whose FIELDS carry the form). Both
     * are request data; only the second is field-bearing.
     */
    val simpleParameterTypes: List<String> = emptyList(),
    /**
     * Frameworks whose ROUTE is declared on the class and whose handlers are
     * named by convention: `@WebServlet("/run")` on the class, `doGet` and
     * `doPost` as the methods. Nothing about that shape fits
     * [mappingAnnotations], which expects the mapping on the function — a
     * servlet modelled that way detects no endpoint at all.
     */
    val classMappingAnnotations: List<String> = emptyList(),
    /** Handler method name -> the HTTP methods it serves (`doGet` -> GET). */
    val handlerMethodNames: List<HandlerMethodName> = emptyList(),
    /**
     * Annotations that carry a route path on a TYPE rather than at a call
     * site: Ktor's `@Resource("/articles/{id}")`. A typed route
     * (`get<Article> { }`) has no path argument at all, so without this the
     * route resolves to nothing.
     */
    val resourceAnnotations: List<String> = emptyList(),
    /**
     * Annotations that declare the application's base path in CODE rather
     * than in configuration: JAX-RS's `@ApplicationPath("/api")` on an
     * `Application` subclass. The context path is not always a config key,
     * and a route reported without it is a wrong URL.
     */
    val applicationPathAnnotations: List<String> = emptyList(),
    /**
     * Dependency coordinates (`group:artifact` fragments) whose mere
     * PRESENCE publishes routes. Spring Boot Actuator serves the actuator
     * tree and springdoc serves `/v3/api-docs` with no handler anywhere in the
     * application's source: a scanner that only reads source reports an
     * attack surface that is missing its most commonly probed paths.
     */
    val dependencyMarkers: List<String> = emptyList(),
    /** Routes published when a [dependencyMarkers] entry is present. */
    val implicitRoutes: List<ImplicitRoute> = emptyList(),
    /**
     * Base-path config keys for [implicitRoutes] (Actuator's own
     * `management.endpoints.web.base-path` is not the server context path).
     */
    val implicitBasePathKeys: List<String> = emptyList(),
    /**
     * The base path implicit routes sit under when no config key sets one.
     * Actuator's `management.endpoints.web.base-path` REPLACES `/actuator`
     * rather than prefixing it, so its routes are modelled relative to the
     * base and the base is substituted, not prepended.
     */
    val implicitBasePathDefault: String = "",
    /**
     * Supertypes that make a declaration an implicitly-routed RESOURCE:
     * Spring Data REST exposes every `CrudRepository` as a collection
     * endpoint, named after the entity, with no handler in source.
     */
    val repositorySupertypes: List<String> = emptyList(),
    /** HTTP methods a repository collection serves. */
    val repositoryMethods: List<String> = emptyList(),
    /**
     * How a `context` handler reads its input, and WHICH TRANSPORT each
     * reader names.
     *
     * [handlerInput] `context` says the payload is not the parameter but
     * something read out of it; it does not say what was read. An annotated
     * framework publishes `{id}` as a path parameter and `q` as a query
     * parameter because [ParameterAnnotation.kind] names the transport — and
     * Ktor, Javalin, Vert.x, Spark and the servlet API, which between them
     * are most of the Kotlin server surface, published NEITHER: every
     * context framework's endpoint carried an empty `pathParameters` and an
     * empty `queryParameters`, because the reader is a call in the body
     * rather than an annotation on the signature.
     *
     * The reader's literal key argument is that name, and it is sitting in
     * the KIR: `ctx.pathParam("id")`, `call.parameters["id"]`,
     * `request.getParameter("q")`. Folding it through the same
     * [io.cdxgen.kosi.kir.KirValueFolder] the route paths use gives a
     * context handler the same parameter inventory an annotated one has.
     */
    val contextReaders: List<ContextReader> = emptyList(),
    /**
     * Annotations that name the media types a handler accepts and produces:
     * Spring's `@RequestMapping(consumes = [...], produces = [...])` and
     * JAX-RS's `@Consumes`/`@Produces`. P14: `consumes`/`produces` were
     * `emptyList()` on every endpoint kosi had ever emitted, for every
     * framework — the information sat in annotations the detector already
     * read, and nothing looked at it.
     */
    val mediaAnnotations: List<MediaAnnotation> = emptyList(),
    /**
     * Annotations that declare a handler's authentication requirement:
     * `@PreAuthorize`, `@RolesAllowed`, `@Secured`. The reported
     * `authentication` list names the matched annotation and its value — an
     * endpoint nobody protects is the fact an attacker wants first.
     */
    val authenticationAnnotations: List<AuthAnnotation> = emptyList(),
    /**
     * DSL nesting calls that wrap a route tree in authentication (Ktor's
     * `authenticate("basic") { get { .. } }`). Unlike an annotation, the
     * requirement sits on the ENCLOSING call, so it is collected by walking
     * the lambda-nesting chain the route prefixes already use.
     */
    val authenticationDsl: List<String> = emptyList(),
    /**
     * P15: chained DSL calls that declare media on the ROUTE OBJECT between
     * the route call and its handler — Vert.x's
     * `router.get("/x").produces("application/json").handler { .. }`. The
     * value is the call's first (folded) argument.
     */
    val mediaDsl: List<MediaDsl> = emptyList(),
    /**
     * P15: the chained DSL call that attaches the real handler to a route
     * object (Vert.x's `Route.handler { .. }`) — for route builders whose
     * route call takes only the path.
     */
    val handlerDsl: List<String> = emptyList(),
    /**
     * P19 §4: a call that MOUNTS one router under another — Vert.x 5's
     * `Route.subRouter(router)`. The route object it is called ON carries
     * the prefix every route declared on the mounted router publishes
     * under. Distinct from a nesting `route("/x") { }` (a LAMBDA-shaped
     * prefix, walked by the lambda links): a mount's sub-router is a VALUE
     * (the call's first argument), so the prefix walk keys on the register
     * the routes are declared against.
     */
    val mountFunctions: List<String> = emptyList(),
    /**
     * P15: route-builder calls whose arguments from this index on name the
     * REQUIRED ROLES (Javalin's `get("/x", handler, Role.ADMIN)` — the
     * vararg `RouteRole...` tail). The handler is the last argument BEFORE
     * the roles begin.
     */
    val roleArgumentStart: Int = -1,
    /**
     * P17: the DSL call that opens a CONTRACT BLOCK whose lambda sets a
     * block-wide security requirement (http4k's
     * `contract { security = ApiKeySecurity(..); routes += .. }`). Every
     * route declared inside the block inherits the requirement, and a
     * route's own [routeMetaDsl] security overrides it — the precedence the
     * framework itself applies (`meta.security ?: security ?: NoOp`).
     */
    val contractDsl: List<String> = emptyList(),
    /**
     * P17: the infix that attaches a route META lambda to a path (http4k's
     * `"/x" meta { security = BasicAuthSecurity(..) } bindContract GET to h`).
     * The lambda's own `security` assignment is the route's requirement.
     */
    val routeMetaDsl: List<String> = emptyList(),
    /**
     * P17: SECURITY implementation constructors — a declaration site that
     * assigns one of these to `security` names its scheme. Only shapes the
     * framework itself applies at RUN TIME are modelled (http4k applies
     * `RouteMeta.security`'s filter per request; its meta `produces`/
     * `consumes` feed the OpenAPI renderer and are NOT runtime gates, so
     * they stay an honest empty).
     */
    val securityConstructors: List<String> = emptyList(),
    /**
     * P17: static factories whose result, passed to the chained handler
     * attach, IS the route's authentication requirement (Vert.x's
     * `route.handler(BasicAuthHandler.create(auth))` — an
     * `AuthenticationHandler`, which IS a `Handler<RoutingContext>`, so it
     * rides the same attach call as a real handler and the chain continues
     * past it).
     */
    val authHandlerFactories: List<String> = emptyList(),
)

/**
 * One request-context reader: the callee, the transport it names, and where
 * the parameter's name is.
 *
 * Two shapes, because the two idioms lower differently:
 *
 *  - [nameArgument] >= 0 — the name is that argument of the call itself
 *    (`ctx.pathParam("id")`, `request.getParameter("q")`).
 *  - [indexed] — the call yields a PARAMETER MAP and the name is the index
 *    of the get that follows (`call.parameters["id"]`). Ktor's whole reader
 *    surface is this shape.
 *
 * [kind] `merged` is Ktor's `call.parameters`, which holds the path and
 * query parameters TOGETHER. Guessing either way would be wrong, so the
 * transport is decided against the route's own template: a name the route
 * declares as `{name}` is a path parameter, and a name it does not declare
 * can only have arrived in the query string.
 */
data class ContextReader(
    val pattern: String,
    val kind: String,
    val nameArgument: Int = -1,
    val indexed: Boolean = false,
)

/**
 * One media-type annotation: the framework annotation's FQN, whether it
 * names [consumes][KIND_CONSUMES] or [produces][KIND_PRODUCES], and where
 * the media types sit in the annotation. [argument] `""` (the default)
 * reads the annotation's positional `value` arguments — JAX-RS's
 * `@Consumes("application/json")`; any other string names the argument —
 * Spring's `@RequestMapping(consumes = [...])`.
 */
data class MediaAnnotation(
    val pattern: String,
    val kind: String,
    val argument: String = "",
)

/** Media kinds, shared by [MediaAnnotation.kind]. */
const val KIND_CONSUMES: String = "consumes"
const val KIND_PRODUCES: String = "produces"

/**
 * One authentication annotation: the framework annotation's FQN plus the
 * scheme name reported in `authentication[]` (the annotation's own simple
 * name, e.g. `@PreAuthorize`).
 */
data class AuthAnnotation(
    val pattern: String,
    val scheme: String,
)

/**
 * P15: chained DSL calls that declare a route's media on the ROUTE OBJECT
 * after the route call itself — Vert.x's
 * `router.get("/x").produces("application/json").handler { .. }`. The media
 * is not an annotation and not an argument of the route call; it is a call
 * in the receiver chain between the route and the handler.
 */
data class MediaDsl(
    val pattern: String,
    val kind: String,
)

/** Transport slots, shared by [ContextReader.kind] and [ParameterAnnotation.kind]. */
const val TRANSPORT_PATH: String = "path"
const val TRANSPORT_QUERY: String = "query"
const val TRANSPORT_MERGED: String = "merged"

/** One route that exists because a dependency is on the classpath. */
data class ImplicitRoute(val path: String, val methods: List<String>)

/** One convention-named handler: the method name and what it serves. */
data class HandlerMethodName(val name: String, val methods: List<String>)

/** Handler-input shapes; see [FrameworkModel.handlerInput]. */
const val HANDLER_INPUT_ANNOTATED: String = "annotated"

/** P27 §2: annotated transports PLUS every non-context parameter. */
const val HANDLER_INPUT_ANNOTATED_OR_BOUND: String = "annotated-or-bound"
const val HANDLER_INPUT_CONTEXT: String = "context"
const val HANDLER_INPUT_ALL: String = "all"

/**
 * One handler-parameter annotation: the framework annotation's FQN, the
 * taint category it introduces, and the transport slot it names (`path`,
 * `query`, `header`, `cookie`, `body`, `form`) for the report.
 */
data class ParameterAnnotation(
    val pattern: String,
    val category: String,
    val kind: String,
)

/**
 * P26 §1.2: an OUTBOUND INTERFACE — Retrofit and Feign declare remote calls
 * as annotated methods on an interface the library implements at runtime.
 * There is no body to walk and no call-site URL argument: the ANNOTATED
 * METHOD IS THE CALL, and the path is the annotation's value (resolved to
 * the declaration's annotation VALUES where the pipeline carries them).
 */
data class OutboundInterfaceModel(
    val framework: String,
    val methodAnnotations: List<String>,
    val protocol: String,
    val clientLibrary: String,
)

/** One outbound client call shape: callee pattern plus where the URL argument sits. */
data class OutboundModel(
    val pattern: String,
    val kind: String,
    val protocol: String,
    val clientLibrary: String,
    /** Argument index of the URL/value (-1 = this call shape names no URL). */
    val urlArgument: Int,
)

/** A config/env reader whose literal key argument names a config-table entry. */
data class ConfigReaderModel(
    val pattern: String,
    val argument: Int,
)

data class EndpointsPack(
    val name: String,
    val frameworks: List<FrameworkModel>,
    val outbound: List<OutboundModel>,
    /** P26 §1.2: annotated-interface outbound declarations (Retrofit, Feign). */
    val outboundInterfaces: List<OutboundInterfaceModel> = emptyList(),
    val configReaders: List<ConfigReaderModel>,
) {
    /** The closed framework vocabulary annotation validation reads. */
    val frameworkIds: Set<String> get() = frameworks.map { it.id }.toSet()
}

object EndpointModels {

    const val ENDPOINTS_PACK_RESOURCE = "/models/endpoints-pack-v0.json"

    fun loadBuiltin(): EndpointsPack = loadResource(ENDPOINTS_PACK_RESOURCE)

    fun loadResource(resource: String): EndpointsPack {
        val text = EndpointModels::class.java.getResourceAsStream(resource)
            ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
            ?: throw IllegalStateException("builtin endpoints pack missing: $resource")
        return parse(text)
    }

    fun parse(text: String): EndpointsPack {
        val root = JsonReader.parse(text).asObject()
        val frameworks = root.arr("frameworks")?.objects()?.map { f ->
            fun mappings(key: String): List<MappingAnnotation> = f.arr(key)?.objects()?.map { m ->
                MappingAnnotation(
                    pattern = require(m.str("pattern"), "frameworks[].${key}[].pattern"),
                    methods = m.arr("methods")?.strings() ?: emptyList(),
                    nesting = m.bool("nesting") ?: false,
                )
            } ?: emptyList()
            FrameworkModel(
                id = require(f.str("id"), "frameworks[].id"),
                kind = require(f.str("kind"), "frameworks[${f.str("id")}].kind"),
                classMarkers = f.arr("classMarkers")?.strings() ?: emptyList(),
                mappingAnnotations = mappings("mappingAnnotations"),
                pathPrefixAnnotations = f.arr("pathPrefixAnnotations")?.strings() ?: emptyList(),
                dslFunctions = mappings("dslFunctions"),
                bindFunctions = mappings("bindFunctions"),
                supertypeMarkers = f.arr("supertypeMarkers")?.strings() ?: emptyList(),
                supertypeSuffixes = f.arr("supertypeSuffixes")?.strings() ?: emptyList(),
                manifestComponents = f.arr("manifestComponents")?.strings() ?: emptyList(),
                parameterAnnotations = f.arr("parameterAnnotations")?.objects()?.map { a ->
                    ParameterAnnotation(
                        pattern = require(a.str("pattern"), "frameworks[].parameterAnnotations[].pattern"),
                        category = require(a.str("category"), "frameworks[].parameterAnnotations[].category"),
                        kind = require(a.str("kind"), "frameworks[].parameterAnnotations[].kind"),
                    )
                } ?: emptyList(),
                handlerInput = f.str("handlerInput") ?: HANDLER_INPUT_ALL,
                contextParameterTypes = f.arr("contextParameterTypes")?.strings() ?: emptyList(),
                nonInputAnnotations = f.arr("nonInputAnnotations")?.strings() ?: emptyList(),
                simpleParameterTypes = f.arr("simpleParameterTypes")?.strings() ?: emptyList(),
                classMappingAnnotations = f.arr("classMappingAnnotations")?.strings() ?: emptyList(),
                resourceAnnotations = f.arr("resourceAnnotations")?.strings() ?: emptyList(),
                applicationPathAnnotations = f.arr("applicationPathAnnotations")?.strings() ?: emptyList(),
                dependencyMarkers = f.arr("dependencyMarkers")?.strings() ?: emptyList(),
                implicitRoutes = f.arr("implicitRoutes")?.objects()?.map { r ->
                    ImplicitRoute(
                        path = require(r.str("path"), "frameworks[].implicitRoutes[].path"),
                        methods = r.arr("methods")?.strings() ?: emptyList(),
                    )
                } ?: emptyList(),
                implicitBasePathKeys = f.arr("implicitBasePathKeys")?.strings() ?: emptyList(),
                implicitBasePathDefault = f.str("implicitBasePathDefault") ?: "",
                repositorySupertypes = f.arr("repositorySupertypes")?.strings() ?: emptyList(),
                repositoryMethods = f.arr("repositoryMethods")?.strings() ?: emptyList(),
                contextReaders = f.arr("contextReaders")?.objects()?.map { c ->
                    ContextReader(
                        pattern = require(c.str("pattern"), "frameworks[].contextReaders[].pattern"),
                        kind = require(c.str("kind"), "frameworks[].contextReaders[].kind"),
                        nameArgument = c.long("nameArgument")?.toInt() ?: -1,
                        indexed = c.bool("indexed") ?: false,
                    )
                } ?: emptyList(),
                mediaAnnotations = f.arr("mediaAnnotations")?.objects()?.map { m ->
                    MediaAnnotation(
                        pattern = require(m.str("pattern"), "frameworks[].mediaAnnotations[].pattern"),
                        kind = require(m.str("kind"), "frameworks[].mediaAnnotations[].kind"),
                        argument = m.str("argument") ?: "",
                    )
                } ?: emptyList(),
                authenticationAnnotations = f.arr("authenticationAnnotations")?.objects()?.map { a ->
                    AuthAnnotation(
                        pattern = require(a.str("pattern"), "frameworks[].authenticationAnnotations[].pattern"),
                        scheme = require(a.str("scheme"), "frameworks[].authenticationAnnotations[].scheme"),
                    )
                } ?: emptyList(),
                authenticationDsl = f.arr("authenticationDsl")?.strings() ?: emptyList(),
                mediaDsl = f.arr("mediaDsl")?.objects()?.map { m ->
                    MediaDsl(
                        pattern = require(m.str("pattern"), "frameworks[].mediaDsl[].pattern"),
                        kind = require(m.str("kind"), "frameworks[].mediaDsl[].kind"),
                    )
                } ?: emptyList(),
                handlerDsl = f.arr("handlerDsl")?.strings() ?: emptyList(),
                mountFunctions = f.arr("mountFunctions")?.strings() ?: emptyList(),
                roleArgumentStart = f.long("roleArgumentStart")?.toInt() ?: -1,
                contractDsl = f.arr("contractDsl")?.strings() ?: emptyList(),
                routeMetaDsl = f.arr("routeMetaDsl")?.strings() ?: emptyList(),
                securityConstructors = f.arr("securityConstructors")?.strings() ?: emptyList(),
                authHandlerFactories = f.arr("authHandlerFactories")?.strings() ?: emptyList(),
                handlerMethodNames = f.arr("handlerMethodNames")?.objects()?.map { h ->
                    HandlerMethodName(
                        name = require(h.str("name"), "frameworks[].handlerMethodNames[].name"),
                        methods = h.arr("methods")?.strings() ?: emptyList(),
                    )
                } ?: emptyList(),
            )
        } ?: emptyList()
        val outbound = root.arr("outbound")?.objects()?.map { o ->
            OutboundModel(
                pattern = require(o.str("pattern"), "outbound[].pattern"),
                kind = require(o.str("kind"), "outbound[].kind"),
                protocol = require(o.str("protocol"), "outbound[].protocol"),
                clientLibrary = require(o.str("clientLibrary"), "outbound[].clientLibrary"),
                urlArgument = o.long("urlArgument")?.toInt() ?: -1,
            )
        } ?: emptyList()
        val configReaders = root.arr("configReaders")?.objects()?.map { c ->
            ConfigReaderModel(
                pattern = require(c.str("pattern"), "configReaders[].pattern"),
                argument = c.long("argument")?.toInt() ?: 0,
            )
        } ?: emptyList()
        return EndpointsPack(
            name = root.str("name") ?: "endpoints-pack",
            frameworks = frameworks,
            outbound = outbound,
            outboundInterfaces = root.arr("outboundInterfaces")?.objects()?.map { o ->
                OutboundInterfaceModel(
                    framework = require(o.str("framework"), "outboundInterfaces[].framework"),
                    methodAnnotations = o.arr("methodAnnotations")?.strings() ?: emptyList(),
                    protocol = require(o.str("protocol"), "outboundInterfaces[].protocol"),
                    clientLibrary = require(o.str("clientLibrary"), "outboundInterfaces[].clientLibrary"),
                )
            } ?: emptyList(),
            configReaders = configReaders,
        )
    }

    private fun require(value: String?, where: String): String =
        value ?: throw IllegalStateException("endpoints pack: missing $where")
}
