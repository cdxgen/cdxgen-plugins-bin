package io.cdxgen.kosi.models

import io.cdxgen.kosi.schema.JsonReader

/**
 * The framework registry and its loader. Everything the endpoint,
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
    /**
     * The annotation argument that NARROWS [methods] on the site:
     * `@RequestMapping(method = [RequestMethod.POST])` serves POST although
     * the annotation's own [methods] is empty. Null when the annotation's
     * methods are fixed by its name (`@GetMapping`).
     */
    val methodArgument: String? = null,
    /**
     * The framework serves EVERY HTTP method here when the site narrows
     * none: `@RequestMapping` without `method`, Vert.x `router.route(..)`,
     * Ratpack `chain.path(..)`. Distinct from an empty [methods] kosi
     * could not resolve.
     */
    val anyMethod: Boolean = false,
    /**
     * A [nesting] shaper whose first argument is a PATH segment its
     * descendants sit under (Ktor `route`, Javalin `path`, Ratpack
     * `prefix`); false for a shaper that selects by something else (Ktor
     * `accept("application/json")` selects by media type).
     */
    val nestingPath: Boolean = false,
    /**
     * A [nesting] SELECTOR's argument index that names the HTTP method its
     * descendants serve (Ktor `method(HttpMethod.Put) { }` = 0,
     * `route(path, HttpMethod.Post) { }` = 1, when that overload is used).
     */
    val nestingMethodArgument: Int = -1,
)

/** One route a repository resource serves; see [FrameworkModel.repositoryRoutes]. */
data class RepositoryRoute(
    /** Relative to the resource: `""` is the collection, `/{id}` the item. */
    val path: String,
    val method: String,
    /** Repository methods that back the route; hidden when every one is unexported. */
    val backedBy: List<String>,
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
     * The types a handler parameter may have that are NOT request
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
     * Annotations that mean "the framework supplies this parameter",
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
     * The types Spring calls SIMPLE, from `BeanUtils.isSimpleValueType`
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
    /**
     * The annotation arguments a route PATH may be written under, in
     * precedence order. Spring declares `value` and `path` as `String[]`
     * aliases, so `@GetMapping("/x")`, `@GetMapping(value = ["/x"])` and
     * `@GetMapping(path = ["/x"])` are the same route; one array may name
     * several paths, each its own endpoint. Applies to [mappingAnnotations],
     * [pathPrefixAnnotations] and [classMappingAnnotations] alike. Empty
     * means `value` alone, the annotation convention.
     */
    val pathArguments: List<String> = emptyList(),
    /**
     * JVM internal names of the PREDICATE type a DSL's same-named overloads
     * return (Spring's router `GET("/x")` / `path("/v2")` build a
     * RequestPredicate and register nothing); such a call is no route.
     */
    val dslPredicateTypes: List<String> = emptyList(),
    /**
     * An annotation that carries a handler METHOD's own path apart from its
     * verb annotation — JAX-RS `@GET @Path("/{id}")`. Joined after the
     * class prefix.
     */
    val methodPathAnnotations: List<String> = emptyList(),
    /**
     * The config keys that set the DEPLOYMENT base path this framework's
     * routes are served under, as ordered groups: keys within a group are
     * alternatives, groups compose (see `Endpoints.deploymentBasePath`).
     */
    val basePathKeys: List<List<String>> = emptyList(),
    /**
     * What carries this framework's endpoints when it is not HTTP:
     * `messaging` (Kafka/JMS/STOMP listeners, schedulers), `grpc`,
     * `android`, `function` (a cloud function's event trigger). Empty is
     * HTTP. A consumer building an HTTP API description reads this to keep
     * non-HTTP handlers out of `paths` without dropping them.
     */
    val transport: String = "",
    /**
     * Frameworks whose every handler is served at ONE path: Spring for
     * GraphQL answers every query and mutation at `POST /graphql`
     * (`spring.graphql.http.path`; Boot 2.7's `spring.graphql.path`).
     */
    val servedAtKeys: List<String> = emptyList(),
    val servedAtDefault: String? = null,
    val servedAtMethods: List<String> = emptyList(),
    /**
     * Cloud-function HTTP triggers (Azure's `@HttpTrigger`): a function
     * with a parameter carrying one is HTTP, served at
     * `/<routePrefix>/<route or function name>` with the trigger's
     * `methods` (all when none); a function without one is event-triggered
     * and not HTTP. [functionRoutePrefixDefault] is the host's default
     * prefix, overridden by `host.json` at [functionRoutePrefixHostKey].
     */
    val functionHttpTriggers: List<String> = emptyList(),
    val functionRoutePrefixDefault: String = "",
    val functionRoutePrefixHostKey: String = "",
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
    /**
     * The routes a repository resource serves and the repository method
     * backing each (Spring Data REST reference, "Repository resources"):
     * the collection serves GET/HEAD via `findAll` and POST via `save`; the
     * item `/{id}` serves GET/HEAD via `findById`, PUT/PATCH via `save` and
     * DELETE via `delete`. A route whose backing method the repository
     * declares with `exported = false` is not served. Replaces a flat verb
     * list that published PUT and DELETE on the COLLECTION and no item route.
     */
    val repositoryRoutes: List<RepositoryRoute> = emptyList(),
    /**
     * Annotations on a repository TYPE that rename or hide its resource
     * (`@RepositoryRestResource(path = "orders", exported = false)`).
     */
    val repositoryResourceAnnotations: List<String> = emptyList(),
    /**
     * Annotations on a repository METHOD that hide the routes it backs or
     * rename its search resource (`@RestResource(exported = false)`).
     */
    val repositoryMethodAnnotations: List<String> = emptyList(),
    /**
     * Methods a repository declares that are CRUD plumbing, never search
     * resources: every other abstract member the repository declares is a
     * query method, served at `/{collection}/search/{name}`.
     */
    val repositoryCrudMethods: List<String> = emptyList(),
    /**
     * Repository supertypes that carry the CRUD methods only in older
     * generations: spring-data-commons 3.0 split `PagingAndSortingRepository`
     * off `CrudRepository`, leaving it [repositoryPagingMethods] alone. Below spring-data-commons major
     * [repositoryPagingCrudBelowMajor] they still bring the full CRUD set.
     */
    val repositoryPagingSupertypes: List<String> = emptyList(),
    val repositoryPagingMethods: List<String> = emptyList(),
    val repositoryPagingCrudBelowMajor: Int = 0,
    /** `group:artifact` whose major version decides [repositoryPagingCrudBelowMajor]. */
    val repositoryGenerationArtifact: String? = null,
    /**
     * Artifact names whose presence in a module's build makes its
     * repositories HTTP resources (Spring Data REST's starter/webmvc).
     */
    val repositoryDependencyMarkers: List<String> = emptyList(),
    /**
     * Class markers whose handlers — and every repository resource — are
     * served under the Spring Data REST BASE PATH:
     * `@BasePathAwareController` and `@RepositoryRestController` (which is
     * meta-annotated with it). Neither is a `@Controller`, which is why the
     * base-path-aware handlers were invisible to [classMarkers] matching.
     */
    val dataRestBasePathMarkers: List<String> = emptyList(),
    /** Config keys that set that base path (`spring.data.rest.base-path`). */
    val dataRestBasePathKeys: List<String> = emptyList(),
    /**
     * Calls that set it in code (`RepositoryRestConfiguration.setBasePath`),
     * which Spring applies after the properties — a folded call argument
     * wins over the key.
     */
    val dataRestBasePathSetters: List<String> = emptyList(),
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
     * JAX-RS's `@Consumes`/`@Produces`. `consumes`/`produces` were
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
     * Chained DSL calls that declare media on the ROUTE OBJECT between
     * the route call and its handler — Vert.x's
     * `router.get("/x").produces("application/json").handler { .. }`. The
     * value is the call's first (folded) argument.
     */
    val mediaDsl: List<MediaDsl> = emptyList(),
    /**
     * The chained DSL call that attaches the real handler to a route
     * object (Vert.x's `Route.handler { .. }`) — for route builders whose
     * route call takes only the path.
     */
    val handlerDsl: List<String> = emptyList(),
    /**
     * A call that MOUNTS one router under another — Vert.x 5's
     * `Route.subRouter(router)`. The route object it is called ON carries
     * the prefix every route declared on the mounted router publishes
     * under. Distinct from a nesting `route("/x") { }` (a LAMBDA-shaped
     * prefix, walked by the lambda links): a mount's sub-router is a VALUE
     * (the call's first argument), so the prefix walk keys on the register
     * the routes are declared against.
     */
    val mountFunctions: List<String> = emptyList(),
    /**
     * Route-builder calls whose arguments from this index on name the
     * REQUIRED ROLES (Javalin's `get("/x", handler, Role.ADMIN)` — the
     * vararg `RouteRole...` tail). The handler is the last argument BEFORE
     * the roles begin.
     */
    val roleArgumentStart: Int = -1,
    /**
     * The DSL call that opens a CONTRACT BLOCK whose lambda sets a
     * block-wide security requirement (http4k's
     * `contract { security = ApiKeySecurity(..); routes += .. }`). Every
     * route declared inside the block inherits the requirement, and a
     * route's own [routeMetaDsl] security overrides it — the precedence the
     * framework itself applies (`meta.security ?: security ?: NoOp`).
     */
    val contractDsl: List<String> = emptyList(),
    /**
     * The infix that attaches a route META lambda to a path (http4k's
     * `"/x" meta { security = BasicAuthSecurity(..) } bindContract GET to h`).
     * The lambda's own `security` assignment is the route's requirement.
     */
    val routeMetaDsl: List<String> = emptyList(),
    /**
     * SECURITY implementation constructors — a declaration site that
     * assigns one of these to `security` names its scheme. Only shapes the
     * framework itself applies at RUN TIME are modelled (http4k applies
     * `RouteMeta.security`'s filter per request; its meta `produces`/
     * `consumes` feed the OpenAPI renderer and are NOT runtime gates, so
     * they stay an honest empty).
     */
    val securityConstructors: List<String> = emptyList(),
    /**
     * Static factories whose result, passed to the chained handler
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
 * Chained DSL calls that declare a route's media on the ROUTE OBJECT
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
data class HandlerMethodName(val name: String, val methods: List<String>, val anyMethod: Boolean = false)

/** Handler-input shapes; see [FrameworkModel.handlerInput]. */
const val HANDLER_INPUT_ANNOTATED: String = "annotated"

/** Annotated transports PLUS every non-context parameter. */
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
 * An OUTBOUND INTERFACE — Retrofit and Feign declare remote calls
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
    /** Annotated-interface outbound declarations (Retrofit, Feign). */
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
                    methodArgument = m.str("methodArgument"),
                    anyMethod = m.bool("anyMethod") ?: false,
                    nestingPath = m.bool("nestingPath") ?: false,
                    nestingMethodArgument = m.long("nestingMethodArgument")?.toInt() ?: -1,
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
                pathArguments = f.arr("pathArguments")?.strings() ?: emptyList(),
                dslPredicateTypes = f.arr("dslPredicateTypes")?.strings() ?: emptyList(),
                methodPathAnnotations = f.arr("methodPathAnnotations")?.strings() ?: emptyList(),
                basePathKeys = f.arr("basePathKeys")?.items?.map { group ->
                    (group as? io.cdxgen.kosi.schema.JsonArr)?.items?.mapNotNull { (it as? io.cdxgen.kosi.schema.JsonStr)?.value }.orEmpty()
                } ?: emptyList(),
                transport = f.str("transport") ?: "",
                servedAtKeys = f.arr("servedAtKeys")?.strings() ?: emptyList(),
                servedAtDefault = f.str("servedAtDefault"),
                servedAtMethods = f.arr("servedAtMethods")?.strings() ?: emptyList(),
                functionHttpTriggers = f.arr("functionHttpTriggers")?.strings() ?: emptyList(),
                functionRoutePrefixDefault = f.str("functionRoutePrefixDefault") ?: "",
                functionRoutePrefixHostKey = f.str("functionRoutePrefixHostKey") ?: "",
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
                repositoryRoutes = f.arr("repositoryRoutes")?.objects()?.map { r ->
                    RepositoryRoute(
                        path = r.str("path") ?: "",
                        method = require(r.str("method"), "frameworks[].repositoryRoutes[].method"),
                        backedBy = r.arr("backedBy")?.strings() ?: emptyList(),
                    )
                } ?: emptyList(),
                repositoryResourceAnnotations = f.arr("repositoryResourceAnnotations")?.strings() ?: emptyList(),
                repositoryMethodAnnotations = f.arr("repositoryMethodAnnotations")?.strings() ?: emptyList(),
                repositoryCrudMethods = f.arr("repositoryCrudMethods")?.strings() ?: emptyList(),
                repositoryPagingSupertypes = f.arr("repositoryPagingSupertypes")?.strings() ?: emptyList(),
                repositoryPagingMethods = f.arr("repositoryPagingMethods")?.strings() ?: emptyList(),
                repositoryPagingCrudBelowMajor = f.long("repositoryPagingCrudBelowMajor")?.toInt() ?: 0,
                repositoryGenerationArtifact = f.str("repositoryGenerationArtifact"),
                repositoryDependencyMarkers = f.arr("repositoryDependencyMarkers")?.strings() ?: emptyList(),
                dataRestBasePathMarkers = f.arr("dataRestBasePathMarkers")?.strings() ?: emptyList(),
                dataRestBasePathKeys = f.arr("dataRestBasePathKeys")?.strings() ?: emptyList(),
                dataRestBasePathSetters = f.arr("dataRestBasePathSetters")?.strings() ?: emptyList(),
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
                        anyMethod = h.bool("anyMethod") ?: false,
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
