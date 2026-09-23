package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.kir.KirAssign
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIndexGet
import io.cdxgen.kosi.models.TRANSPORT_MERGED
import io.cdxgen.kosi.models.TRANSPORT_PATH
import io.cdxgen.kosi.models.TRANSPORT_QUERY
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.kir.KirValueFolder
import io.cdxgen.kosi.models.EndpointsPack
import io.cdxgen.kosi.models.FrameworkModel
import io.cdxgen.kosi.models.MappingAnnotation
import io.cdxgen.kosi.schema.Position

/**
 * Inbound endpoint detection: one detector over the KIR + the resolved
 * declaration annotations, driven by the shipped framework registry DATA.
 * Four detection kinds, each publishing its `foundBy`:
 *
 *  - `annotation` — a function annotated with a mapping annotation at its
 *    RESOLVED fqn (Spring MVC/WebFlux, Micronaut, Quarkus/JAX-RS);
 *  - `dsl` — a call to a routing DSL function, the handler resolved to the
 *    extracted lambda body and nested route prefixes composed (Ktor,
 *    WebFlux functional router), and http4k's `"/path" bind METHOD to handler`;
 *  - `annotation` over a supertype shape — gRPC service impls: every concrete
 *    method of a class whose supertype is a generated `*ImplBase`;
 *  - `manifest` — Android components with intent filters, exported flags,
 *    permissions and deep links, resolved to a lifecycle handler.
 *
 * The framework match is on RESOLVED type identity: a homonym annotation
 * declared in a different package (the framework-handlers fixture's
 * negative) never matches, because the pack patterns carry the framework's
 * own package segments.
 */
object EndpointDetector {

    /**
     * A declaration annotation the resolved front end carried: fqn + first
     * constant value, plus every NAMED argument's constants — the channel
     * `@RequestMapping(consumes = [...], produces = [...])` needs, where the
     * argument's name is the only difference between the two lists.
     */
    data class DeclAnnotation(
        val fqn: String,
        val value: String?,
        val line: Int,
        val namedValues: Map<String, List<String>> = emptyMap(),
        /**
         * The file the annotated declaration lives in. A canonical name is
         * NOT unique across a multi-module build — digital-restaurant has
         * thirteen `com.drestaurant.web.CommandController`s, one per app —
         * and without the file their `@RequestMapping` prefixes pool under
         * one key and a handler takes another module's route.
         */
        val file: String? = null,
    )

    /**
     * [annotations] declared in [file]: the same-named declaration in another
     * module is another declaration. The KIR carries the absolute
     * virtual-file path and the declaration drafts the root-relative one, so
     * the two agree when one ends with the other on a segment boundary.
     */
    internal fun declaredIn(annotations: List<DeclAnnotation>, file: String?): List<DeclAnnotation> =
        if (file == null) annotations else annotations.filter { it.file == null || sameFile(it.file, file) }

    private fun sameFile(a: String, b: String): Boolean {
        val x = a.replace('\\', '/')
        val y = b.replace('\\', '/')
        return x == y || x.endsWith("/" + y.trimStart('/')) || y.endsWith("/" + x.trimStart('/'))
    }

    class Input(
        val module: KirModule,
        /** Canonical name of the declaration -> its annotations (with values). */
        val annotationValues: Map<String, List<DeclAnnotation>>,
        val folder: KirValueFolder,
        /** Extracted-lambda links: lambda canonical -> (parent function, creating call). */
        val lambdaLinks: Map<String, LambdaLink>,
        /**
         * File -> the two-segment package roots its imports name
         * (`io.javalin`, `io.ktor`). An UNRESOLVED route call is attributed
         * to a framework its own file imports — the same evidence a resolved
         * symbol gives, one file at a time.
         */
        val importRootsByFile: Map<String, Set<String>> = emptyMap(),
    ) {
        internal fun importRootsOf(file: String): Set<String> =
            importRootsByFile.entries.firstOrNull { (k, _) -> declaredIn(listOf(DeclAnnotation("", null, 0, file = k)), file).isNotEmpty() }
                ?.value.orEmpty()

        /**
         * Call names that open a NESTED route scope, from the pack's
         * `nesting` rows (Ktor `route`, Javalin `path`, Ratpack `prefix`);
         * set by [detect].
         */
        internal var nestingNames: Set<String> = setOf("route", "path")

        /** The nesting rows' FQN patterns: a RESOLVED creation call matches by type identity. */
        internal var nestingPatterns: List<String> = emptyList()

        /** Abstract members an implementation inherited its mapping from; see [detect]. */
        internal val inheritedMappings: MutableSet<String> = mutableSetOf()

        private val callers: Map<String, List<String>> by lazy {
            val out = HashMap<String, MutableSet<String>>()
            for (f in module.functions) {
                for (block in f.body?.blocks.orEmpty()) {
                    for (ins in block.instructions) {
                        val callee = (ins as? KirCall)?.callee?.fqn ?: continue
                        out.getOrPut(callee) { sortedSetOf() }.add(f.canonicalName)
                    }
                }
            }
            out.mapValues { it.value.toList() }
        }

        /** Functions whose bodies call [canonical], sorted. */
        internal fun callersOf(canonical: String): List<String> = callers[canonical].orEmpty()
    }

    data class LambdaLink(
        val parentFunction: String,
        /** The call in the parent whose argument list contains the lambda register. */
        val creationCall: KirIns,
    )

    /** The name a call (resolved or dynamic) was made under. */
    internal fun callName(ins: KirIns): String? = when (ins) {
        is KirCall -> ins.callee.fqn.substringAfterLast('.')
        is KirDynamicCall -> ins.name
        else -> null
    }

    /**
     * The reserved pseudo-framework an endpoint carries when the ROUTE is
     * real but no framework's package is demonstrably present to attribute
     * it to. A consumer can tell "found a route, could not name the
     * framework" from both "found nothing" and any wrong attribution.
     */
    const val UNATTRIBUTED_FRAMEWORK: String = "unattributed"

    data class Candidate(
        val framework: String,
        val httpMethods: List<String>,
        val pathTemplate: String,
        val pathParameters: List<String>,
        val handlerSymbol: String,
        /** Query-string parameters the handler demonstrably reads (see [transportParameters]). */
        val queryParameters: List<String> = emptyList(),
        val foundBy: String,
        val position: Position?,
        val exported: Boolean?,
        val permissions: List<String>?,
        val deepLinkHosts: List<String>?,
        /** Media types the handler's annotations name it as accepting. */
        val consumes: List<String> = emptyList(),
        /** Media types the handler's annotations name it as producing. */
        val produces: List<String> = emptyList(),
        /** Authentication requirements, from annotations or the enclosing DSL. */
        val authentication: List<String> = emptyList(),
        /**
         * Whether the detector could VERIFY that this endpoint's
         * component was read. Null means "the question does not arise" —
         * an annotation or DSL candidate exists BECAUSE a declaration was
         * read, so it is substantiated by construction. Only the manifest
         * branch, which names a class the analysed tree may not hold, has
         * to answer it.
         */
        val substantiated: Boolean? = null,
        /**
         * Served under the Spring Data REST base path: a handler of a
         * `@BasePathAwareController`/`@RepositoryRestController`, or a
         * repository resource. The base is resolved per module and composed
         * after detection.
         */
        val dataRestBase: Boolean = false,
        /**
         * Why [pathTemplate] is known to be INCOMPLETE — a base path the
         * deployment sets but kosi could not prove (two config files in one
         * module disagree, or a setter argument did not fold). The template
         * is then relative to that unproven base, and says so.
         */
        val pathUnresolved: String? = null,
        /** Serves every HTTP method; [httpMethods] is then empty by design, not unresolved. */
        val anyMethod: Boolean = false,
        /** Not HTTP: the framework's [io.cdxgen.kosi.models.FrameworkModel.transport], or `function` for an event-triggered cloud function. */
        val transport: String? = null,
        /** An enclosing method selector exists but its verb did not resolve: never "any method". */
        val methodSelectorUnresolved: Boolean = false,
    )

    fun detect(input: Input, pack: EndpointsPack = io.cdxgen.kosi.models.EndpointModels.loadBuiltin()): List<Candidate> {
        input.nestingNames = pack.frameworks.flatMap { f ->
            f.dslFunctions.filter { it.nesting && it.nestingPath }.map { it.pattern.substringAfterLast('.') }
        }.toSet()
        input.nestingPatterns = pack.frameworks.flatMap { f ->
            f.dslFunctions.filter { it.nesting && it.nestingPath }.map { it.pattern }
        }
        val byKey = linkedMapOf<String, Candidate>()
        fun add(candidate: Candidate) {
            // The file is part of identity: one canonical handler declared in
            // two app modules serving the same route is two endpoints.
            // The verbs are part of identity too: `get<Login> { }` and
            // `post<Login> { }` in one file are two endpoints even when no
            // handler symbol tells them apart.
            val key = candidate.framework + "\u0000" + candidate.handlerSymbol + "\u0000" + candidate.pathTemplate +
                "\u0000" + candidate.position?.filename.orEmpty() + "\u0000" + candidate.httpMethods.sorted().joinToString(",")
            if (key !in byKey) byKey[key] = candidate
        }
        val functions = input.module.functions.sortedWith(
            compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }),
        )
        // Which framework packages this module demonstrably uses, from every
        // RESOLVED callee it names. Unresolved route calls are attributed
        // with this rather than with the pack's list order.
        val resolvedPackages: Set<String> = buildSet {
            for (fn in input.module.functions) {
                for (block in fn.body?.blocks.orEmpty()) {
                    for (ins in block.instructions) {
                        val fqn = (ins as? KirCall)?.callee?.fqn ?: continue
                        val segments = fqn.split('.')
                        if (segments.size >= 2) add(segments.take(2).joinToString("."))
                    }
                }
            }
        }
        for (fn in functions) {
            detectAnnotated(fn, input, pack, ::add)
            detectGrpc(fn, pack, ::add)
            detectDsl(fn, input, pack, resolvedPackages, ::add)
        }
        // A handler class a mount call linked to a route is that route's
        // handler; its route-less supertype candidate is not a second endpoint.
        // An abstract member an implementation inherited from is published
        // THERE; the KIR does not always record the reverse override edge.
        val bodyless = functions.filter { it.body == null }.mapTo(HashSet()) { it.canonicalName }
        byKey.values.removeAll { it.handlerSymbol in input.inheritedMappings && it.handlerSymbol in bodyless }
        val mounted = mountedHandlers(byKey.values)
        byKey.values.removeAll { it.foundBy != "dsl" && it.pathUnresolved != null && it.pathTemplate.isEmpty() && it.handlerSymbol in mounted }
        return byKey.values.sortedWith(
            compareBy({ it.framework }, { it.pathTemplate }, { it.handlerSymbol }, { it.position?.filename.orEmpty() }),
        )
    }

    // ---- annotation kind (Spring MVC/WebFlux, Micronaut, Quarkus/JAX-RS) ----

    private fun detectAnnotated(
        fn: KirFunction,
        input: Input,
        pack: EndpointsPack,
        add: (Candidate) -> Unit,
    ) {
        if (fn.syntheticCause != null) return
        fun isMapping(ann: DeclAnnotation) = pack.frameworks.any { f ->
            f.kind == "annotation" && f.mappingAnnotations.any { matches(ann.fqn, it.pattern) }
        }
        // An abstract member that an analysed class implements is the
        // implementation's endpoint, published there with the inherited
        // mapping below — never a second, bodyless one.
        if (fn.body == null && fn.overriddenBy.isNotEmpty()) return
        val own = declaredIn(input.annotationValues[fn.canonicalName].orEmpty(), fn.file)
        // INHERITED mappings: a member with no mapping of its own takes the
        // one on the member it overrides — JAX-RS ("inherited by a
        // corresponding sub-class or implementation class method provided
        // that the method ... do not have any JAX-RS annotations of their
        // own") and Spring's interface controllers (the OpenAPI-generator
        // `interface UsersApi` shape) alike. The class prefix and marker come
        // from the overridden member's owner when the implementation's class
        // declares none.
        val inheritedFrom = if (own.none(::isMapping)) {
            fn.overrides.firstOrNull { o -> input.annotationValues[o].orEmpty().any(::isMapping) }
        } else {
            null
        }
        if (inheritedFrom != null) input.inheritedMappings.add(inheritedFrom)
        val annotations = if (inheritedFrom != null) input.annotationValues[inheritedFrom].orEmpty() else own
        val ownerCanonical = fn.canonicalName.substringBeforeLast('.')
        val ownDeclAnnotations = declaredIn(input.annotationValues[ownerCanonical].orEmpty(), fn.file)
        val inheritedOwner = inheritedFrom?.substringBeforeLast('.')
        val inheritedOwnerAnnotations = inheritedOwner?.let { input.annotationValues[it].orEmpty() }.orEmpty()
        // The KIR carries RESOLVED owner annotations only; the declaration
        // table also carries import-resolved ones (see Analyzer).
        val ownerAnnotations = (fn.ownerAnnotations + ownDeclAnnotations.map { it.fqn } + inheritedOwnerAnnotations.map { it.fqn }).distinct()
        val ownerDeclAnnotations = ownDeclAnnotations + inheritedOwnerAnnotations

        // Class-declared routes with convention-named handlers: the servlet
        // shape, where `@WebServlet("/run")` sits on the class and `doGet`
        // is the handler. The mapping-on-the-function rule below cannot see
        // these at all.
        for (framework in pack.frameworks) {
            if (framework.classMappingAnnotations.isEmpty() || framework.handlerMethodNames.isEmpty()) continue
            val simpleName = fn.canonicalName.substringAfterLast('.')
            val handler = framework.handlerMethodNames.firstOrNull { it.name == simpleName } ?: continue
            val classMapping = ownerDeclAnnotations.firstOrNull { ann ->
                framework.classMappingAnnotations.any { matches(ann.fqn, it) }
            } ?: continue
            for (path in pathsOf(classMapping, framework.pathArguments)) {
                add(
                    Candidate(
                        framework = framework.id,
                        httpMethods = handler.methods,
                        anyMethod = handler.methods.isEmpty() && handler.anyMethod,
                        pathTemplate = normalizePath(path),
                        pathParameters = pathParametersOf(path),
                        handlerSymbol = fn.canonicalName,
                        foundBy = "annotation",
                        position = Position(fn.file, fn.line, fn.line),
                        exported = true,
                        permissions = emptyList(),
                        deepLinkHosts = emptyList(),
                    ),
                )
            }
        }
        if (annotations.isEmpty()) return

        for (framework in pack.frameworks) {
            if (framework.kind != "annotation") continue
            for (mapping in framework.mappingAnnotations) {
                val matched = annotations.firstOrNull { matches(it.fqn, mapping.pattern) } ?: continue
                // A marker-bearing framework requires the marker on the
                // enclosing class: the mapping annotation alone is not a
                // published endpoint. (@Path is Quarkus's own marker.)
                if (framework.classMarkers.isNotEmpty()) {
                    val hasMarker = ownerAnnotations.any { owner ->
                        framework.classMarkers.any { matches(owner, it) }
                    }
                    if (!hasMarker) continue
                }
                val prefixes = ownerDeclAnnotations
                    .firstOrNull { ann -> framework.pathPrefixAnnotations.any { matches(ann.fqn, it) } }
                    ?.let { pathsOf(it, framework.pathArguments) }
                    ?: listOf("")
                val methods = methodsOf(matched, mapping)
                val dataRestBase = ownerAnnotations.any { owner ->
                    framework.dataRestBasePathMarkers.any { matches(owner, it) }
                }
                // One endpoint per (prefix, path) pair: Spring serves the
                // cross product of a class-level and a method-level array.
                for (prefix in prefixes) {
                    // JAX-RS spells a method's own path on a SEPARATE
                    // annotation (`@GET @Path("/{id}")`): the verb carries
                    // none, and "the URI template of the resource class"
                    // concatenates with "the URI template of the method".
                    val methodPath = framework.methodPathAnnotations.takeIf { it.isNotEmpty() }?.let { patterns ->
                        annotations.firstOrNull { ann -> patterns.any { matches(ann.fqn, it) } }
                    }
                    val rawPaths = methodPath?.let { pathsOf(it, framework.pathArguments) } ?: pathsOf(matched, framework.pathArguments)
                    for (rawPath in rawPaths) {
                        // Spring, JAX-RS and Micronaut all prepend the missing
                        // slash: `@GetMapping("vets.json")` serves `/vets.json`.
                        val path = joinPaths(prefix, rawPath).let { if (it.isNotEmpty() && !it.startsWith("/")) "/$it" else it }
                        add(
                            Candidate(
                                framework = framework.id,
                                httpMethods = methods,
                                pathTemplate = normalizePath(path),
                                pathParameters = pathParametersOf(path),
                                handlerSymbol = fn.canonicalName,
                                foundBy = "annotation",
                                position = Position(fn.file, fn.line, fn.line),
                                exported = null,
                                permissions = null,
                                deepLinkHosts = null,
                                dataRestBase = dataRestBase,
                                anyMethod = methods.isEmpty() && mapping.anyMethod,
                                queryParameters = uriTemplateQueryParameters(path),
                            ),
                        )
                    }
                }
                return
            }
        }
    }

    /**
     * The route paths one mapping annotation declares. The first of
     * [arguments] that carries constants wins, every element of it a path:
     * `value`/`path` are `String[]` on the real Spring annotations, so the
     * front end publishes them ONLY through [DeclAnnotation.namedValues] —
     * [DeclAnnotation.value] holds a first SCALAR constant and is null for
     * every real `@GetMapping`. An annotation whose arguments carry constants
     * but no path argument (`@GetMapping(produces = [..])`) declares the
     * empty path; [DeclAnnotation.value] is consulted only when no argument
     * folded to a constant at all (an interpolated template the syntax tier
     * keeps as text), which is what it meant before.
     */
    internal fun pathsOf(annotation: DeclAnnotation, arguments: List<String>): List<String> {
        for (argument in arguments.ifEmpty { DEFAULT_PATH_ARGUMENTS }) {
            val declared = annotation.namedValues[argument].orEmpty()
            if (declared.isNotEmpty()) return declared.map { it.trim().removeSurrounding("\"") }.distinct()
        }
        if (annotation.namedValues.isNotEmpty()) return listOf("")
        return listOf(annotation.value?.trim()?.removeSurrounding("\"").orEmpty())
    }

    private val DEFAULT_PATH_ARGUMENTS = listOf("value")

    private val HTTP_METHODS = setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE")

    /**
     * The HTTP methods a mapping site serves: the site's own
     * [MappingAnnotation.methodArgument] (`method = [RequestMethod.POST]`,
     * arriving as `POST` or a qualified `RequestMethod.POST`) when it names
     * any, else the annotation's fixed [MappingAnnotation.methods]. A value
     * that is not an HTTP method is dropped, never guessed at.
     */
    internal fun methodsOf(annotation: DeclAnnotation, mapping: MappingAnnotation): List<String> {
        val argument = mapping.methodArgument ?: return mapping.methods
        val declared = annotation.namedValues[argument].orEmpty()
            .map { it.substringAfterLast('.').uppercase() }
            .filter { it in HTTP_METHODS || (mapping.customVerbs && it.matches(Regex("[A-Z][A-Z0-9_-]*"))) }
            .distinct()
        return declared.ifEmpty { mapping.methods }
    }

    // ---- dsl kind (Ktor routing, WebFlux router, http4k bind) ---------------

    /**
     * The two-segment package roots a framework's DSL patterns name
     * (`io.ktor.server.routing.get` -> `io.ktor`): the evidence that decides
     * which framework an UNRESOLVED route call belongs to.
     */
    private fun FrameworkModel.dslPackages(): Set<String> =
        dslFunctions.mapNotNullTo(mutableSetOf()) { mapping ->
            mapping.pattern.split('.').take(2).takeIf { it.size == 2 }?.joinToString(".")
        }

    private fun detectDsl(
        fn: KirFunction,
        input: Input,
        pack: EndpointsPack,
        resolvedPackages: Set<String>,
        add: (Candidate) -> Unit,
    ) {
        val body = fn.body ?: return
        for (block in body.blocks) {
            for ((index, ins) in block.instructions.withIndex()) {
                when (ins) {
                    is KirCall -> {
                        val framework = pack.frameworks.firstOrNull { f ->
                            f.dslFunctions.any { matches(ins.callee.fqn, it.pattern) } ||
                                f.bindFunctions.any { matchesCallName(ins, it.pattern) }
                        } ?: continue
                        val mapping = framework.dslFunctions.firstOrNull { matches(ins.callee.fqn, it.pattern) }
                        if (mapping != null) {
                            if (mapping.nesting) continue
                            detectRouteCall(fn, block, index, ins, framework, mapping.methods, input, anyMethodAdd(mapping, add))
                        } else {
                            detectBindCall(fn, block, index, ins, framework, input, add)
                        }
                    }

                    // An UNRESOLVED extension lowers as a dynamic call that
                    // keeps only its name. It stands for a DSL route when it
                    // carries the route SHAPE - a path value plus a lambda -
                    // which is how `routing { get("/x") { .. } }` lowers when
                    // the receiver type never resolved. A RESOLVED homonym
                    // (the legacy fixture's own `get`) is a KirCall whose
                    // fqn the suffix rule rejects, so resolved type identity
                    // still wins over name matching.
                    is KirDynamicCall -> {
                        // Name-only matching cannot tell `get` from `get`:
                        // Ktor, Javalin, Spark and Vert.x all have one. The
                        // framework a route is ATTRIBUTED to must be
                        // EVIDENCED — some resolved symbol in this module
                        // names that framework's package — and when nothing
                        // does, the route is published under the reserved
                        // pseudo-framework `unattributed` rather than handed
                        // to whichever framework sat first in the pack.
                        // Showed the wrong-framework answer in production: a
                        // Ktor 1.x app's routes reported as Vert.x. A miss
                        // is never a WRONG answer.
                        val importRoots = input.importRootsOf(fn.file)
                        val byName = pack.frameworks.filter { f ->
                            f.dslFunctions.any { it.pattern.substringAfterLast('.') == ins.name && !it.nesting } &&
                                (hasRouteShape(fn, ins, input) ||
                                    // A handler INSTANCE (`get("/signin", VueComponent(..), ANYONE)`)
                                    // only where the file imports the framework: `put("k", Foo())`
                                    // anywhere else is a map write.
                                    (f.dslPackages().any { it in importRoots } && hasInstanceRouteShape(fn, block, index, ins, input)))
                        }
                        if (byName.isEmpty()) continue
                        // A framework the module demonstrably uses spells this
                        // name as a NESTING builder (Ktor's `route("/x") { }`):
                        // the call is that prefix, never a route of another
                        // framework that happens to share the name.
                        val fileRoots = input.importRootsOf(fn.file)
                        fun evidencedHere(f: FrameworkModel) = f.dslPackages().any { it in resolvedPackages || it in fileRoots }
                        val nestingHere = pack.frameworks.any { f ->
                            f.dslFunctions.any { it.nesting && it.pattern.substringAfterLast('.') == ins.name } && evidencedHere(f)
                        }
                        if (nestingHere && byName.none(::evidencedHere)) continue
                        val evidenced = byName.firstOrNull(::evidencedHere)
                        if (evidenced != null) {
                            val mapping = evidenced.dslFunctions.firstOrNull {
                                it.pattern.substringAfterLast('.') == ins.name && !it.nesting
                            } ?: continue
                            detectRouteCall(fn, block, index, ins, evidenced, mapping.methods, input, anyMethodAdd(mapping, add))
                        } else {
                            // No framework's package is demonstrably present:
                            // publish the ROUTE (the path and handler are
                            // real) with no framework claim. The verb is
                            // published only when EVERY candidate builder of
                            // this name agrees on it (`get` is GET in Ktor,
                            // Javalin, Spark and Vert.x alike): then it names
                            // no framework. Any disagreement keeps none.
                            val consensus = byName.map { f ->
                                f.dslFunctions.first { it.pattern.substringAfterLast('.') == ins.name && !it.nesting }.methods
                            }.distinct().singleOrNull().orEmpty()
                            detectRouteCall(fn, block, index, ins, null, consensus, input, add)
                        }
                    }

                    else -> {}
                }
            }
        }
    }


    private fun detectRouteCall(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirIns,
        framework: FrameworkModel?,
        methods: List<String>,
        input: Input,
        add: (Candidate) -> Unit,
    ) {
        // An overload that BUILDS a predicate (`GET("/x")`, `path("/v2")` in
        // the router DSL, returning RequestPredicate) registers no route.
        val descriptor = (ins as? KirCall)?.callee?.descriptor
        if (descriptor != null && framework?.dslPredicateTypes?.any { descriptor.endsWith(")L$it;") } == true) return
        val baseArgs = when (ins) {
            is KirCall -> ins.args
            is KirDynamicCall -> ins.args
            else -> emptyList()
        }
        // `"/status" { }` — `String.invoke(handler)`: the route's path is
        // the extension RECEIVER, which leads the argument list here.
        val invokeReceiver = (ins as? KirCall)?.takeIf { callName(it) == "invoke" }?.receiver
        var callArgs = if (invokeReceiver != null) listOf(invokeReceiver) + baseArgs else baseArgs
        // `router.route(HttpMethod.POST, "/x")`: a LEADING HttpMethod value is
        // the verb and the path follows it.
        var leadingMethod: String? = null
        if (callArgs.size >= 2) {
            val first = fn.body?.blocks?.asSequence()?.flatMap { it.instructions.asSequence() }
                ?.filterIsInstance<io.cdxgen.kosi.kir.KirFieldGet>()?.firstOrNull { it.result == callArgs[0] }
            val name = (first?.path?.elements?.lastOrNull() as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name?.uppercase()
            val owner = first?.let { fg ->
                fn.body?.blocks?.asSequence()?.flatMap { it.instructions.asSequence() }
                    ?.filterIsInstance<io.cdxgen.kosi.kir.KirFieldGet>()?.firstOrNull { it.result == fg.receiver }
            }
            val ownerName = (owner?.path?.elements?.lastOrNull() as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name
            if (name != null && name in HTTP_METHODS && (ownerName == "HttpMethod" || ownerName == null)) {
                leadingMethod = name
                callArgs = callArgs.drop(1)
            }
        }
        // A REGEX route (`getWithRegex("^/api/.*")`) names no URL template:
        // it is kept, with the regex, rather than published as a path.
        val regexRow = framework?.dslFunctions?.firstOrNull { row ->
            row.pathIsRegex && ((ins as? KirCall)?.let { matches(it.callee.fqn, row.pattern) } ?: (callName(ins) == row.pattern.substringAfterLast('.')))
        }
        if (regexRow != null) {
            val regex = callArgs.firstOrNull()?.let { input.folder.valueAt(fn, block, index, it)?.value } ?: "<unfolded>"
            add(
                Candidate(
                    framework = framework.id, httpMethods = regexRow.methods, pathTemplate = "", pathParameters = emptyList(),
                    handlerSymbol = fn.canonicalName, foundBy = "dsl", position = Position(fn.file, fn.line, fn.line),
                    exported = null, permissions = null, deepLinkHosts = null,
                    pathUnresolved = "regex route: matches the regex $regex, which no URL template expresses",
                ),
            )
            return
        }
        // A method-less terminal (Ktor `handle { }`) takes its verb from the
        // nearest enclosing SELECTOR — `method(HttpMethod.Put) { }`,
        // `route(path, HttpMethod.Post) { }`. A selector whose value the
        // program picks at run time (a loop over methods) resolves nothing:
        // the route is then neither a claimed verb nor "any method".
        var effectiveMethods = if (leadingMethod != null) listOf(leadingMethod) else methods
        var routeAdd: (Candidate) -> Unit = if (leadingMethod != null) { c -> add(c.copy(httpMethods = listOf(leadingMethod), anyMethod = false)) } else add
        if (effectiveMethods.isEmpty() && framework != null) {
            when (val selected = enclosingMethodSelector(fn, framework, input)) {
                null -> Unit
                SELECTOR_UNRESOLVED -> routeAdd = { c -> add(c.copy(anyMethod = false, methodSelectorUnresolved = true)) }
                else -> {
                    effectiveMethods = listOf(selected)
                    routeAdd = { c -> add(c.copy(anyMethod = false, httpMethods = listOf(selected))) }
                }
            }
        }
        val mounted = mountedPrefix(fn, (ins as? KirCall)?.receiver ?: (ins as? KirDynamicCall)?.receiver, framework, input)
        for (outer in prefixChains(fn.canonicalName, input)) {
            detectRouteCallAt(fn, block, index, ins, framework, effectiveMethods, input, routeAdd, callArgs, joinPaths(outer, mounted))
        }
    }

    private fun detectRouteCallAt(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirIns,
        framework: FrameworkModel?,
        methods: List<String>,
        input: Input,
        add: (Candidate) -> Unit,
        callArgs: List<String>,
        prefix: String,
    ) {

        // A TYPED route names its path on a class, not at the call site:
        // `get<Article> { }` with `@Resource("/articles/{id}")` on
        // `Article`. The path argument this function otherwise reads simply
        // does not exist, so such a route used to resolve to nothing.
        val typeArguments = (ins as? KirCall)?.typeArguments
            ?: (ins as? KirDynamicCall)?.typeArguments?.mapNotNull { short -> resourceTypeNamed(short, framework, input) }.orEmpty()
        if (framework?.resourceAnnotations?.isNotEmpty() == true && typeArguments.isNotEmpty()) {
            val resourcePath = resourcePathOf(typeArguments.first(), framework, input)
            if (resourcePath != null) {
                val handler = handlerOfRegs(fn, callArgs, input)
                    ?: callArgs.singleOrNull()?.let { LambdaResolver.resolve(fn, it, input) }
                publish(add, framework, methods, joinPaths(prefix, resourcePath), handler ?: "", fn, "dsl")
                return
            }
        }

        val pathReg = callArgs.firstOrNull() ?: return

        // `get(UserController::getAllUserIds, Role.ANYONE)` — Javalin's
        // ApiBuilder spells a path-less route with the HANDLER first: the
        // route is the enclosing `path(..)`, never the handler's name.
        if (callArgs.size >= 2 && isFunctionValue(fn, pathReg, input)) {
            val handler = LambdaResolver.resolve(fn, pathReg, input).orEmpty()
            publish(add, framework, methods, joinPaths(prefix, "").ifEmpty { "/" }, handler, fn, "dsl")
            return
        }

        // `route("/hello") { get { .. } }` — the verb builder takes ONLY a
        // lambda, and the route's path is entirely the enclosing prefix.
        // Reading the first argument as a path here folds the LAMBDA
        // register, which resolves to nothing, and the route was published
        // with the register's own name as a path segment (`/hello/t7`) — a
        // URL that exists nowhere, on the most common Ktor nesting idiom.
        if (callArgs.size == 1) {
            val only = LambdaResolver.resolve(fn, pathReg, input)
            if (only != null && input.module.functions.any { it.canonicalName == only }) {
                val path = joinPaths(prefix, "").ifEmpty { "/" }
                publish(add, framework, methods, path, only, fn, "dsl")
                return
            }
        }
        val folded = input.folder.valueAt(fn, block, index, pathReg)
        // A PROVABLE null path argument is not an unresolvable one: ktor 2's
        // own builder spells it (`get(path: String? = null, body)`,
        // RoutingRoot.kt — the no-argument overload of the same generation),
        // and a null path selects the route at its ENCLOSING level, exactly
        // as the lambda-only route above. Before the typed constants
        // this compiled to the string "null" and published a route at
        // "/null"; after it, the register fallback would have published the
        // register's own name as a URL. Neither is a path.
        if (folded?.status == KirValueFolder.ValueStatus.NULL) {
            val path = joinPaths(prefix, "").ifEmpty { "/" }
            // With the framework in hand: a role-tail builder's handler is
            // the argument BEFORE the roles, and resolving the LAST one
            // publishes the ROLE register as the handler (the defect,
            // which this arm reintroduced by dropping the argument).
            publish(add, framework, methods, path, handlerOfRegs(fn, callArgs, input, framework) ?: "", fn, "dsl")
            return
        }
        val foldedPath = folded?.value
        val boundMethod: String? = when (ins) {
            is KirCall -> boundMethodName(fn, block, index, ins)
            else -> null
        }
        if (foldedPath == null) {
            // An unresolvable path is UNRESOLVED evidence, not a silently
            // dropped endpoint: the raw register rendering is the template.
            publish(add, framework, boundMethod?.let { listOf(it) } ?: methods, joinPaths(prefix, rawOf(fn, block, index, pathReg)), fn.canonicalName, fn, "dsl")
            return
        }
        // Vert.x builds routes as a CHAIN —
        // `router.get("/x").produces("application/json").handler { .. }` —
        // so the media declarations and the real handler sit on calls that
        // CONSUME this call's result. Javalin declares auth as the route
        // call's trailing role arguments. Both are read here, where the
        // route call is in hand; frameworks without the pack channels keep
        // the plain candidate.
        val chained = chainedRouteFacts(fn, block, index, ins, framework, input)
        val roles = roleArguments(fn, block, index, ins, framework, input)
        val handler = chained.handler ?: handlerOfRegs(fn, callArgs, input, framework)
        publish(
            add,
            framework,
            boundMethod?.let { listOf(it) } ?: methods,
            joinPaths(prefix, foldedPath),
            handler ?: "",
            fn,
            "dsl",
            consumes = chained.consumes,
            produces = chained.produces,
            authentication = roles + chained.authentication,
        )
    }

    /**
     * Media and handler declared on the ROUTE OBJECT'S receiver chain
     * (Vert.x): the route call's result flows through `.produces(..)` /
     * `.consumes(..)` calls before `.handler { .. }` attaches the real
     * handler. The walk follows the receiver chain one call at a time — a
     * `.produces` result is the input of the NEXT chained call — and stops
     * at the first call that consumes the chain without producing a route
     * (the handler attach). An attach whose argument is an
     * authentication handler FACTORY result (Vert.x's
     * `handler(BasicAuthHandler.create(auth))`) is an authentication
     * declaration, not the real handler — it is recorded and the chain
     * CONTINUES, because `Route.handler` returns the route.
     */
    private class ChainedRouteFacts(
        val handler: String?,
        val consumes: List<String>,
        val produces: List<String>,
        val authentication: List<String>,
    )

    private fun chainedRouteFacts(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirIns,
        framework: FrameworkModel?,
        input: Input,
    ): ChainedRouteFacts {
        if (framework == null || (framework.mediaDsl.isEmpty() && framework.handlerDsl.isEmpty() && framework.authHandlerFactories.isEmpty())) {
            return ChainedRouteFacts(null, emptyList(), emptyList(), emptyList())
        }
        val result = (ins as? KirCall)?.result ?: return ChainedRouteFacts(null, emptyList(), emptyList(), emptyList())
        var consumes = mutableListOf<String>()
        var produces = mutableListOf<String>()
        var authentication = mutableListOf<String>()
        var handler: String? = null
        var current = result
        var hops = 0
        while (hops < 8) {
            hops++
            val rest = block.instructions.drop(index + 1)
            val nextIndex = rest.indexOfFirst { it is KirCall && it.receiver == current }
            if (nextIndex < 0) break
            val next = rest[nextIndex] as KirCall
            val nextAt = index + 1 + nextIndex
            val media = framework.mediaDsl.firstOrNull { matches(next.callee.fqn, it.pattern) }
            if (media != null) {
                // Folded at the MEDIA CALL's own index: the constant it
                // reads is defined between the route call and here, and the
                // folder scans backwards from the index it is given.
                input.folder.valueAt(fn, block, nextAt, next.args.firstOrNull() ?: "")?.value
                    ?.let { value -> if (media.kind == io.cdxgen.kosi.models.KIND_CONSUMES) consumes.add(value) else produces.add(value) }
                current = next.result ?: break
                continue
            }
            if (framework.handlerDsl.any { matches(next.callee.fqn, it) }) {
                val authScheme = authHandlerSchemeOf(fn, block, nextAt, next, framework)
                if (authScheme != null) {
                    authentication.add("auth-handler($authScheme)")
                    current = next.result ?: break
                    continue
                }
                handler = chainedHandlerOf(fn, block, nextAt, next, input)
                break
            }
            break
        }
        return ChainedRouteFacts(handler, consumes, produces, authentication)
    }

    /**
     * The scheme a chained handler attach DECLARED, when the attached value
     * is the result of one of the framework's authentication-handler
     * factories (Vert.x's `BasicAuthHandler.create(auth)`): the call that
     * produced the argument names the scheme, and — unlike the comment
     * believed — the KIR attributes it to exactly one route, because the
     * factory result is attached through this route's own chain.
     */
    private fun authHandlerSchemeOf(
        fn: KirFunction,
        block: KirBlock,
        at: Int,
        call: KirCall,
        framework: FrameworkModel,
    ): String? {
        if (framework.authHandlerFactories.isEmpty()) return null
        val attached = call.args.firstOrNull() ?: return null
        for (i in at - 1 downTo 0) {
            val candidate = block.instructions.getOrNull(i) ?: continue
            if (candidate is KirCall && candidate.result == attached) {
                // A Kotlin companion factory renders an extra `Companion`
                // segment (`BasicAuthHandler.Companion.create`) where the
                // Java interface static the pack pattern was sourced from
                // does not; the segment is a resolution artifact, not part
                // of the API's shape, so it is transparent here.
                val fqn = candidate.callee.fqn.split('.').filterNot { it == "Companion" }.joinToString(".")
                val pattern = framework.authHandlerFactories.firstOrNull { matches(fqn, it) }
                    ?: return null
                // `io.vertx.ext.web.handler.BasicAuthHandler.create` ->
                // `BasicAuthHandler`: the owner of the matched factory.
                return pattern.split('.').dropLast(1).lastOrNull()
            }
        }
        return null
    }

    /**
     * The handler a chained `.handler(x)` call attaches: `x` is either the
     * lambda itself or — Vert.x's common SAM-constructor shape — the result
     * of wrapping one (`Handler<RoutingContext> { .. }` lowers to a call
     * whose argument IS the lambda register). The wrapper is seen through
     * so the published handler names the lambda's own function.
     */
    private fun chainedHandlerOf(
        fn: KirFunction,
        block: KirBlock,
        at: Int,
        call: KirCall,
        input: Input,
    ): String? {
        val direct = call.args.firstOrNull()?.let { reg -> LambdaResolver.resolve(fn, reg, input) }
        if (direct != null) return direct
        val wrapped = call.args.firstOrNull() ?: return null
        for (i in at - 1 downTo 0) {
            val candidate = block.instructions.getOrNull(i) ?: continue
            if (candidate is KirCall && candidate.result == wrapped) {
                return candidate.args.firstOrNull()?.let { reg -> LambdaResolver.resolve(fn, reg, input) }
            }
        }
        return null
    }

    /**
     * The route call's trailing ROLE arguments (Javalin's
     * `get("/x", handler, Role.ADMIN)`): from [FrameworkModel.roleArgumentStart]
     * on, every argument names a required role — a folded constant or an
     * enum entry read from its fieldget, the same read
     * [boundMethodName] uses. The handler itself is the argument just
     * before the roles begin, which [handlerOfRegs] cannot know.
     */
    private fun roleArguments(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirIns,
        framework: FrameworkModel?,
        input: Input,
    ): List<String> {
        val start = framework?.roleArgumentStart ?: -1
        if (start < 0) return emptyList()
        val args = when (ins) {
            is KirCall -> ins.args
            is KirDynamicCall -> ins.args
            else -> return emptyList()
        }
        if (args.size <= start) return emptyList()
        val roles = mutableListOf<String>()
        for (reg in args.drop(start)) {
            val folded = input.folder.valueAt(fn, block, index, reg)?.value
            if (folded != null) {
                roles.add(folded)
                continue
            }
            // An enum entry (`Role.ADMIN`) lowers as a fieldget: the field
            // name is the role.
            for (i in index - 1 downTo 0) {
                val candidate = block.instructions.getOrNull(i) ?: continue
                if (candidate is io.cdxgen.kosi.kir.KirFieldGet && candidate.result == reg) {
                    (candidate.path.elements.lastOrNull() as? io.cdxgen.kosi.kir.AccessPath.Element.Field)
                        ?.let { roles.add(it.name) }
                    break
                }
            }
        }
        return if (roles.isEmpty()) emptyList() else listOf("role(${roles.joinToString(",")})")
    }

    /** The route shape: a path-valued first argument plus a lambda last argument. */
    /**
     * An unresolved call has the ROUTE SHAPE when one of its arguments is a
     * function value the module defines — a lambda, or a reference
     * (`UserController::getAllUserIds`) — and, with a single argument, when
     * a type argument names the route (`get<ViewKweet> { }`). The handler is
     * not always last: Javalin's `get(handler, Role.ANYONE)` ends in roles.
     */
    private fun hasRouteShape(fn: KirFunction, ins: KirDynamicCall, input: Input): Boolean {
        if (ins.args.isEmpty()) return false
        if (ins.args.size < 2 && ins.typeArguments.isEmpty() && !isFunctionValue(fn, ins.args.single(), input)) return false
        return ins.args.any { isFunctionValue(fn, it, input) }
    }

    /** A string path first, then an argument some constructor-shaped call produced. */
    private fun hasInstanceRouteShape(fn: KirFunction, block: KirBlock, index: Int, ins: KirDynamicCall, input: Input): Boolean {
        if (ins.args.size < 2) return false
        if (input.folder.valueAt(fn, block, index, ins.args[0])?.value == null) return false
        val produced = block.instructions.take(index)
        return ins.args.drop(1).any { reg ->
            produced.any { p ->
                (p is KirCall && p.result == reg && p.callee.kind == io.cdxgen.kosi.kir.CallKind.CONSTRUCTOR) ||
                    (p is io.cdxgen.kosi.kir.KirNew && p.result == reg) ||
                    (p is KirDynamicCall && p.result == reg && p.name.firstOrNull()?.isUpperCase() == true)
            }
        }
    }

    private fun isFunctionValue(fn: KirFunction, register: String, input: Input): Boolean {
        val handler = LambdaResolver.resolve(fn, register, input) ?: return false
        return input.module.functions.any { it.canonicalName == handler }
    }

    private fun boundMethodName(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirCall,
    ): String? {
        val args = ins.args
        if (args.size < 2) return null
        val methodReg = args[args.size - 2]
        for (i in index - 1 downTo 0) {
            val candidate = block.instructions.getOrNull(i) ?: continue
            if (candidate is io.cdxgen.kosi.kir.KirFieldGet && candidate.result == methodReg) {
                return (candidate.path.elements.lastOrNull() as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name
            }
        }
        return null
    }

    /**
     * http4k: `"/path" bind GET to { ... }` — receiver is the path, the `to`
     * side the handler. The CONTRACT spelling
     * `"/path" meta { security = .. } bindContract GET to { .. }` puts a
     * META call between the path and the bind; the bind's receiver is then
     * the meta call's result, the path is the META call's receiver, and the
     * meta lambda's own `security` assignment is the route's requirement.
     * The CONTRACT BLOCK's `security` (the lambda of the `contract { .. }`
     * call this route is declared inside) applies when the route's meta
     * declares none — the precedence the framework itself applies
     * (`it.meta.security?.filter ?: security?.filter ?: Filter.NoOp`,
     * ContractRouteMatcher.kt:121 at 6.59.0.0).
     */
    private fun detectBindCall(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirCall,
        framework: FrameworkModel,
        input: Input,
        add: (Candidate) -> Unit,
    ) {
        val receiver = ins.receiver ?: return
        var authentication: List<String> = emptyList()
        val path: String
        val metaCall = producerOf(block, index, receiver)
        // An INFIX call lowers as `kotlin.<name>` (the callee resolves, but
        // the named-operator lowering keeps only the operation reference), so
        // the meta infix is matched on its last segment — the same convention
        // [matchesCallName] uses for the bind itself.
        if (metaCall != null && framework.routeMetaDsl.any { metaCall.callee.fqn.substringAfterLast('.') == it.substringAfterLast('.') }) {
            val metaReceiver = metaCall.receiver
            path = metaReceiver?.let { input.folder.valueAt(fn, block, index, it)?.value ?: rawOf(fn, block, index, it) }
                ?: rawOf(fn, block, index, receiver)
            val metaSecurity = metaCall.args.firstOrNull()
                ?.let { LambdaResolver.resolve(fn, it, input) }
                ?.let { lambda -> securityAssignmentOf(lambda, input, framework) }
            if (metaSecurity != null) authentication = listOf("meta-security($metaSecurity)")
        } else {
            val folded = input.folder.valueAt(fn, block, index, receiver)
            path = folded?.value ?: rawOf(fn, block, index, receiver)
        }
        if (authentication.isEmpty()) {
            val blockSecurity = contractBlockSecurity(fn, framework, input)
            if (blockSecurity != null) authentication = listOf("contract-security($blockSecurity)")
        }
        // The handler lives on the `to` call whose receiver is this bind's
        // result, and the method constant is the bind's argument.
        val handler = bindHandler(fn, ins.result, input)
        val method = ins.args.firstOrNull()?.let { methodReg ->
            block.instructions.firstOrNull {
                it is io.cdxgen.kosi.kir.KirFieldGet && it.result == methodReg
            }?.let {
                (it as io.cdxgen.kosi.kir.KirFieldGet).path.elements.lastOrNull()
                    ?.let { e -> (e as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name }
            }
        }
        publish(add, framework, listOfNotNull(method), path, handler ?: "", fn, "dsl", authentication = authentication)
    }

    /** True when [register] is last written before [index] by a null literal. */
    private fun loadsNull(block: KirBlock, index: Int, register: String): Boolean {
        for (i in index - 1 downTo 0) {
            val candidate = block.instructions.getOrNull(i) ?: continue
            if (candidate is io.cdxgen.kosi.kir.KirLoad && candidate.result == register) {
                return candidate.constant is io.cdxgen.kosi.kir.KirConstant.Null
            }
            if (candidate is KirCall && candidate.result == register) return false
        }
        return false
    }

    /** The last call before [index] in [block] whose result is [register]. */
    private fun producerOf(block: KirBlock, index: Int, register: String): KirCall? {
        for (i in index - 1 downTo 0) {
            val candidate = block.instructions.getOrNull(i) ?: continue
            if (candidate is KirCall && candidate.result == register) return candidate
        }
        return null
    }

    /**
     * The SECURITY SCHEME a declaration-site lambda assigns, when it assigns
     * a modelled security constructor to the DSL's `security` property —
     * `security = BasicAuthSecurity("realm", creds)` lowers as a field set
     * whose value register is the constructor call's result. Both real
     * http4k sites assign a property literally named `security`
     * (`ContractBuilder.security`, `RouteMetaDsl.security`), so the field
     * name is the model's, matched here rather than guessed from the KIR.
     *
     * the residual, closed: an assignment whose producer matches
     * NO modelled constructor used to return null here, and the caller fell
     * back to the CONTRACT BLOCK's scheme — naming the wrong requirement
     * with confidence, because the framework's own elvis
     * (`meta.security ?: security`) ignores the block whenever meta declares
     * ANY security. A lambda that assigns `security` at all therefore never
     * yields null: the unmodelled producer's own name is reported (the code
     * declares it; the pack merely does not model it), "unknown" when the
     * producer is not even a call.
     *
     * With ONE exception, which is the elvis read literally: `security =
     * null` assigns nothing. `meta.security?.filter ?: security?.filter`
     * takes the block's arm for a null meta value exactly as it does for an
     * absent one, so an explicit null is not an unknown requirement — it is
     * the absence of a per-route requirement, and the block still applies.
     * Reporting "unknown" there would be the own mistake in its other
     * direction: confident about a site the framework is not confused by.
     */
    private fun securityAssignmentOf(
        lambdaCanonical: String,
        input: Input,
        framework: FrameworkModel,
    ): String? {
        if (framework.securityConstructors.isEmpty()) return null
        val lambda = input.module.functions.firstOrNull { it.canonicalName == lambdaCanonical } ?: return null
        for (block in lambda.body?.blocks.orEmpty()) {
            for ((at, ins) in block.instructions.withIndex()) {
                if (ins !is io.cdxgen.kosi.kir.KirFieldSet) continue
                val field = ins.path.elements.lastOrNull() as? io.cdxgen.kosi.kir.AccessPath.Element.Field ?: continue
                if (field.name != "security") continue
                if (loadsNull(block, at, ins.value)) continue
                val ctor = producerOf(block, at, ins.value) ?: return "unknown"
                val modelled = framework.securityConstructors.firstOrNull { matches(ctor.callee.fqn, it) }
                return modelled?.substringAfterLast('.') ?: ctor.callee.fqn.substringAfterLast('.')
            }
        }
        return null
    }

    /**
     * The security the CONTRACT BLOCK declares, when [fn] IS the lambda of
     * one of the framework's contract-builder calls: the block's own
     * `security = <scheme>(..)` assignment, read from the same function the
     * routes are declared in.
     */
    private fun contractBlockSecurity(
        fn: KirFunction,
        framework: FrameworkModel,
        input: Input,
    ): String? {
        if (framework.contractDsl.isEmpty()) return null
        val link = input.lambdaLinks[fn.canonicalName] ?: return null
        val call = link.creationCall as? KirCall ?: return null
        if (framework.contractDsl.none { matches(call.callee.fqn, it) }) return null
        return securityAssignmentOf(fn.canonicalName, input, framework)
    }

    private fun bindHandler(fn: KirFunction, bindResult: String?, input: Input): String? {
        if (bindResult == null) return null
        for (block in fn.body?.blocks.orEmpty()) {
            for (ins in block.instructions) {
                if (ins is KirCall && ins.receiver == bindResult && ins.callee.fqn.substringAfterLast('.') == "to") {
                    return ins.args.lastOrNull()?.let { reg -> LambdaResolver.resolve(fn, reg, input) }
                }
            }
        }
        return null
    }

    /**
     * The handler register: the LAST argument, or — when the framework's
     * route builder carries trailing ROLE arguments (Javalin) — the one
     * just before the roles begin.
     */
    private fun handlerOfRegs(
        fn: KirFunction,
        args: List<String>,
        input: Input,
        framework: FrameworkModel? = null,
    ): String? {
        if (args.size < 2) return null
        val start = framework?.roleArgumentStart ?: -1
        val handlerReg = if (start in 1..args.lastIndex) args[start - 1] else args.last()
        return LambdaResolver.resolve(fn, handlerReg, input) ?: constructedHandlerOf(fn, handlerReg, input, framework)
    }

    /**
     * A handler passed as an INSTANCE — Ratpack's `chain.get("x", MyHandler())`
     * — rather than a lambda: the register's producer is a constructor call,
     * and the handler is that class's method the framework dispatches to
     * ([FrameworkModel.handlerMethodNames]).
     */
    private fun constructedHandlerOf(fn: KirFunction, register: String, input: Input, framework: FrameworkModel?): String? {
        val names = framework?.handlerMethodNames?.map { it.name }.orEmpty()
        if (names.isEmpty()) return null
        val producer = fn.body?.blocks?.asSequence()?.flatMap { it.instructions.asSequence() }
            ?.filterIsInstance<KirCall>()
            ?.firstOrNull {
                it.result == register &&
                    (it.callee.kind == io.cdxgen.kosi.kir.CallKind.CONSTRUCTOR || it.callee.fqn.endsWith(".<init>"))
            } ?: return null
        val type = producer.callee.fqn.removeSuffix(".<init>")
        return names.asSequence().map { "$type.$it" }.firstOrNull { name ->
            input.module.functions.any { it.canonicalName == name }
        }
    }

    /** Marks a route whose DSL call serves every method (and bound none) as [Candidate.anyMethod]. */
    private fun anyMethodAdd(mapping: MappingAnnotation, add: (Candidate) -> Unit): (Candidate) -> Unit =
        if (!mapping.anyMethod) add else { candidate ->
            add(if (candidate.httpMethods.isEmpty() && !candidate.methodSelectorUnresolved) candidate.copy(anyMethod = true) else candidate)
        }

    /** A typed route's SHORT type name to the `@Resource` class it names, when exactly one analysed class matches. */
    private fun resourceTypeNamed(short: String, framework: FrameworkModel?, input: Input): String? {
        if (framework == null || framework.resourceAnnotations.isEmpty()) return null
        val matches = input.annotationValues.entries.filter { (canonical, anns) ->
            canonical.substringAfterLast('.') == short &&
                anns.any { ann -> framework.resourceAnnotations.any { matches(ann.fqn, it) } }
        }
        return matches.singleOrNull()?.key
    }

    private const val SELECTOR_UNRESOLVED = "\u0000unresolved"

    /**
     * The verb the nearest enclosing METHOD SELECTOR names: a nesting row
     * with a [MappingAnnotation.nestingMethodArgument] whose creation call
     * carries that argument. Null when no selector encloses the route;
     * [SELECTOR_UNRESOLVED] when one does but its value does not fold to a
     * verb (`HttpMethod.Post` lowers as a field read ending in `Post`).
     */
    private fun enclosingMethodSelector(fn: KirFunction, framework: FrameworkModel, input: Input): String? {
        val selectors = framework.dslFunctions.filter { it.nesting && it.nestingMethodArgument >= 0 }
        if (selectors.isEmpty()) return null
        var current: String? = fn.canonicalName
        var hops = 0
        while (current != null && hops++ < 8) {
            val link = input.lambdaLinks[current] ?: return null
            val call = link.creationCall as? KirCall
            val row = call?.let { c -> selectors.firstOrNull { matches(c.callee.fqn, it.pattern) } }
            if (call != null && row != null && call.args.size > row.nestingMethodArgument + 1) {
                val parent = input.module.functions.firstOrNull { it.canonicalName == link.parentFunction } ?: return SELECTOR_UNRESOLVED
                val register = call.args[row.nestingMethodArgument]
                val read = parent.body?.blocks?.asSequence()?.flatMap { it.instructions.asSequence() }
                    ?.filterIsInstance<io.cdxgen.kosi.kir.KirFieldGet>()?.firstOrNull { it.result == register }
                val name = (read?.path?.elements?.lastOrNull() as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name?.uppercase()
                return name?.takeIf { it in HTTP_METHODS } ?: SELECTOR_UNRESOLVED
            }
            current = link.parentFunction
        }
        return null
    }

    /** Handler classes a DSL mount call links to a route; their unmounted supertype candidate is superseded. */
    internal fun mountedHandlers(candidates: Collection<Candidate>): Set<String> =
        candidates.filter { it.foundBy == "dsl" }.mapTo(HashSet()) { it.handlerSymbol }

    private fun publish(
        add: (Candidate) -> Unit,
        framework: FrameworkModel?,
        methods: List<String>,
        path: String,
        handler: String,
        at: KirFunction,
        foundBy: String,
        consumes: List<String> = emptyList(),
        produces: List<String> = emptyList(),
        authentication: List<String> = emptyList(),
    ) {
        // A relative DSL path is served from the root of its scope: Ratpack's
        // `chain.get("search", ..)` and Ktor's `get("hello")` are `/search`
        // and `/hello`.
        val path = if (path.isNotEmpty() && !path.startsWith("/")) "/$path" else path
        add(
            Candidate(
                // Null framework = the route SHAPE matched but no framework
                // could be evidenced (see detectDsl): the reserved
                // pseudo-framework `unattributed` says so in the report
                // instead of naming whichever framework has a `get`.
                framework = framework?.id ?: UNATTRIBUTED_FRAMEWORK,
                httpMethods = methods,
                pathTemplate = normalizePath(path),
                pathParameters = pathParametersOf(path),
                handlerSymbol = handler,
                foundBy = if (framework == null) "$foundBy-unattributed" else foundBy,
                position = Position(at.file, at.line, at.line),
                exported = null,
                permissions = null,
                deepLinkHosts = null,
                consumes = consumes,
                produces = produces,
                authentication = authentication,
            ),
        )
    }

    private fun rawOf(fn: KirFunction, block: KirBlock, index: Int, register: String): String {
        for (i in index - 1 downTo 0) {
            val ins = block.instructions.getOrNull(i) ?: continue
            if (ins is KirLoad && ins.result == register) {
                return (ins.constant as? io.cdxgen.kosi.kir.KirConstant.Str)?.value?.removeSurrounding("\"") ?: register
            }
        }
        return register
    }

    /**
     * The prefix a MOUNTED router publishes under: Vert.x 5's
     * mount idiom — a wildcard route on the parent router whose subRouter
     * call takes the mounted router as its argument — puts every route
     * declared on the mounted router under the wildcard route's path. The
     * walk is keyed on the MOUNTED ROUTER'S REGISTER (the mount call's
     * first argument) through one store alias (`val api = Router.router(v)`),
     * which is the shape the routes are declared against; the lambda-link
     * chain cannot see it because a sub-router is a VALUE, not a lambda.
     * The mount route's trailing wildcard marker is the framework's own
     * "and everything below" spelling and contributes no segment.
     * Same-function mounts only: a sub-router built in another function
     * crosses a boundary this walk does not follow — a named gap, recorded
     * in the pack comment, not a wrong prefix.
     */
    private fun mountedPrefix(
        fn: KirFunction,
        routeReceiver: String?,
        framework: FrameworkModel?,
        input: Input,
    ): String {
        if (framework == null || framework.mountFunctions.isEmpty() || routeReceiver == null) return ""
        val storeSources = HashMap<String, String>()
        for (block in fn.body?.blocks.orEmpty()) {
            for (ins in block.instructions) {
                if (ins is KirStore) storeSources[ins.target] = ins.value
            }
        }
        for (block in fn.body?.blocks.orEmpty()) {
            for ((at, ins) in block.instructions.withIndex()) {
                if (ins !is KirCall) continue
                val fqn = ins.callee.fqn.split('.').filterNot { it == "Companion" }.joinToString(".")
                if (framework.mountFunctions.none { matches(fqn, it) }) continue
                val mounted = ins.args.firstOrNull() ?: continue
                val receiverIsMounted = routeReceiver == mounted || storeSources[routeReceiver] == mounted
                if (!receiverIsMounted) continue
                // The mount call's own receiver is the ROUTE the mount hangs
                // off; its producer is the `router.route("/api/*")` call and
                // its first argument is the prefix.
                val routeObject = ins.receiver ?: continue
                val producer = producerOf(block, at, routeObject) ?: continue
                if (producer.callee.fqn.substringAfterLast('.') != "route") continue
                val prefixReg = producer.args.firstOrNull() ?: continue
                val folded = input.folder.valueAt(fn, block, at, prefixReg)?.value ?: continue
                return folded.trimEnd('*').trimEnd('/')
            }
        }
        return ""
    }

    /**
     * The route prefix carried by the chain of `route(...)`-shaped calls that
     * extracted this function as a lambda: `route("/x") { get("/y") {} }`
     * composes "/x" + "/y". Bounded hops keep pathological chains cheap.
     */
    private fun prefixChain(functionCanonical: String, input: Input): String = prefixChainWithRoot(functionCanonical, input).first

    /**
     * Every prefix a route in [functionCanonical] is served under. Beyond
     * the lambda chain, a route declared in a NAMED function — Ktor's
     * `fun Route.userRoutes() { get("/{id}") { } }`, "grouped into extension
     * functions" per ktor.io — takes the prefix of each place the function
     * is CALLED from (`route("/api/users") { userRoutes() }`): one prefix per
     * call site. Bounded depth; a function nobody calls keeps its own chain.
     */
    private fun prefixChains(functionCanonical: String, input: Input, depth: Int = 0, seen: Set<String> = emptySet()): List<String> {
        val (chain, root) = prefixChainWithRoot(functionCanonical, input)
        if (depth >= 4 || root in seen) return listOf(chain)
        val callers = input.callersOf(root)
        if (callers.isEmpty()) return listOf(chain)
        return callers.flatMap { caller ->
            prefixChains(caller, input, depth + 1, seen + root).map { outer -> joinPaths(outer, chain) }
        }.distinct()
    }

    private fun prefixChainWithRoot(functionCanonical: String, input: Input): Pair<String, String> {
        var current: String? = functionCanonical
        var root = functionCanonical
        val segments = mutableListOf<String>()
        var hops = 0
        while (current != null && hops < 8) {
            hops++
            val link = input.lambdaLinks[current] ?: break
            val call = link.creationCall
            // A RESOLVED nesting call matches its row by FQN; only an
            // unresolved one falls back to the name.
            val nests = when (call) {
                is KirCall -> input.nestingPatterns.any { matches(call.callee.fqn, it) }
                else -> EndpointDetector.callName(call) in input.nestingNames
            }
            if (nests) {
                val parent = input.module.functions.firstOrNull { it.canonicalName == link.parentFunction }
                val block = parent?.body?.blocks?.firstOrNull { it.instructions.any { it === call } }
                if (parent != null && block != null) {
                    val index = block.instructions.indexOfFirst { it === call }
                    val callArgs = when (call) {
                        is KirCall -> call.args
                        is KirDynamicCall -> call.args
                        else -> emptyList()
                    }
                    // `"/api".nest { }` carries the path as the call's
                    // RECEIVER (an extension receiver); `route("/api") { }`
                    // as its first argument.
                    val receiver = (call as? KirCall)?.receiver
                    val first = receiver?.takeIf { r -> input.folder.valueAt(parent, block, index, r)?.value != null }
                        ?: receiver?.takeIf { r ->
                            block.instructions.take(index).any { (it as? KirCall)?.result == r && callName(it) == "path" }
                        }
                        ?: callArgs.firstOrNull()
                    val folded = first?.let { input.folder.valueAt(parent, block, index, it) }
                    // `path("/api").nest { }`: the nesting argument is a
                    // PREDICATE, and its path is the argument of the `path`
                    // call that produced it. Any other predicate (`accept(..)`,
                    // `method(..)`) adds no segment.
                    val viaPredicate = if (folded?.value == null && first != null) {
                        block.instructions.take(index).lastOrNull { producer ->
                            (producer as? KirCall)?.result == first && callName(producer) == "path" && producer.args.size == 1
                        }?.let { producer ->
                            val at = block.instructions.indexOf(producer)
                            input.folder.valueAt(parent, block, at, (producer as KirCall).args.single())?.value
                        }
                    } else {
                        null
                    }
                    (folded?.value ?: viaPredicate)?.trim('/')?.takeIf { it.isNotEmpty() }?.let { segments.add(0, it) }
                }
            }
            current = link.parentFunction
            root = link.parentFunction
        }
        // A composed prefix is an absolute path: the leading slash comes
        // from the nesting call's own template ("", "/metrics" etc.).
        val joined = segments.joinToString("/")
        return (if (joined.isEmpty()) "" else "/$joined") to root
    }

    // ---- gRPC service impls --------------------------------------------------

    private fun detectGrpc(
        fn: KirFunction,
        pack: EndpointsPack,
        add: (Candidate) -> Unit,
    ) {
        val supertypes = fn.supertypes
        if (supertypes.isEmpty() || fn.syntheticCause != null) return
        // EVERY supertype framework, not just the first one in the pack:
        // with gRPC alone in this kind the `firstOrNull` was invisible, and
        // the moment a second one (AWS Lambda's RequestHandler) was added it
        // silently took gRPC's place and every gRPC endpoint disappeared.
        var matched: Pair<FrameworkModel, String>? = null
        for (candidate in pack.frameworks.filter { it.kind == "supertype" }) {
            val hit = supertypes.firstOrNull { supertype ->
                (candidate.supertypeSuffixes.isEmpty() || candidate.supertypeSuffixes.any { supertype.endsWith(it) }) &&
                    (candidate.supertypeMarkers.isEmpty() || candidate.supertypeMarkers.any { supertype.contains(it) }) &&
                    (candidate.supertypeSuffixes.isNotEmpty() || candidate.supertypeMarkers.isNotEmpty())
            }
            if (hit != null) {
                matched = candidate to hit
                break
            }
        }
        val (grpc, base) = matched ?: return
        if (grpc.supertypeSuffixes.isEmpty()) {
            // Not an RPC base: a Ratpack Handler or a Lambda RequestHandler
            // names NO route on the class. The route is wherever a chain
            // call mounts it, or in the deployment (API Gateway, a function
            // URL) — never `/<Supertype>/<method>`, which this published and
            // which matches no traffic. A DSL mount found elsewhere
            // supersedes this candidate; an unmounted one says so.
            val method = fn.canonicalName.substringAfterLast('.')
            if (method == "<init>") return
            add(
                Candidate(
                    framework = grpc.id,
                    httpMethods = emptyList(),
                    pathTemplate = "",
                    pathParameters = emptyList(),
                    handlerSymbol = fn.canonicalName,
                    foundBy = "annotation",
                    position = Position(fn.file, fn.line, fn.line),
                    exported = null,
                    permissions = null,
                    deepLinkHosts = null,
                    pathUnresolved = "the ${base.substringAfterLast('.')} implementation declares no route; " +
                        "it is bound where the application mounts it, which kosi did not link",
                ),
            )
            return
        }
        // The RPC path is `/<Service>/<Method>`; the service names out of
        // the generated base's simple name minus its suffix
        // (`GreeterImplBase` -> `Greeter`, the proto service's name).
        // LONGEST suffix first: gRPC's Kotlin generator emits
        // `GreeterCoroutineImplBase`, and stripping only `ImplBase` names
        // the service `GreeterCoroutine` — a service that does not exist, so
        // the reported RPC path `/GreeterCoroutine/sayHello` matches no
        // traffic and no proto.
        val suffix = grpc.supertypeSuffixes.filter { base.endsWith(it) }.maxByOrNull { it.length } ?: "ImplBase"
        val simple = base.substringAfterLast('.').removeSuffix(suffix)
        // The Kotlin stub is nested in `<Service>GrpcKt`; when the nested
        // name is now empty the outer class carries the service name.
        val service = simple.ifEmpty {
            base.substringBeforeLast('.').substringAfterLast('.').removeSuffix("GrpcKt").removeSuffix("Grpc")
        }
        val method = fn.canonicalName.substringAfterLast('.')
        if (method == "<init>") return
        // Only an OVERRIDE of the generated base is an RPC: a helper or a
        // `close()` on the service class is not in the service descriptor.
        if (fn.overrides.isEmpty() && "override" !in fn.modifiers) return
        add(
            Candidate(
                framework = grpc.id,
                httpMethods = emptyList(),
                pathTemplate = "/$service/$method",
                pathParameters = emptyList(),
                handlerSymbol = fn.canonicalName,
                foundBy = "annotation",
                position = Position(fn.file, fn.line, fn.line),
                exported = null,
                permissions = null,
                deepLinkHosts = null,
            ),
        )
    }

    // ---- shared helpers ------------------------------------------------------

    /**
     * The one matching rule for FRAMEWORK symbols: suffix-segment match on
     * the RESOLVED fqn, and never a short PSI name against a packaged
     * pattern — `GetMapping` (an annotation the front end could not
     * resolve) does not match `org.springframework...GetMapping`. An
     * unresolvable annotation is never treated as the framework's.
     */
    internal fun matches(symbol: String, pattern: String): Boolean {
        if (symbol == pattern) return true
        val patternSegments = pattern.split('.')
        val symbolSegments = symbol.split('.')
        if (patternSegments.size > symbolSegments.size) return false
        return symbolSegments.takeLast(patternSegments.size) == patternSegments
    }

    /** A bind pattern matches on the call's last name segment (`bind`). */
    private fun matchesCallName(ins: KirCall, pattern: String): Boolean =
        ins.callee.fqn.substringAfterLast('.') == pattern.substringAfterLast('.')

    private fun joinPaths(prefix: String, path: String): String = when {
        prefix.isEmpty() -> path
        path.isEmpty() -> prefix
        else -> prefix.trimEnd('/') + "/" + path.trimStart('/')
    }

    /**
     * The path a `@Resource`-annotated class declares, composed with its
     * enclosing resource when nested — Ktor nests `@Resource("{id}")`
     * inside `@Resource("/articles")` to mean `/articles/{id}`.
     */
    private fun resourcePathOf(typeName: String, framework: FrameworkModel, input: Input): String? {
        val parts = ArrayDeque<String>()
        var current: String? = typeName
        var guard = 0
        while (current != null && guard++ < 8) {
            val annotation = input.annotationValues[current].orEmpty().firstOrNull { ann ->
                framework.resourceAnnotations.any { matches(ann.fqn, it) }
            } ?: break
            val value = annotation.value?.trim()?.removeSurrounding("\"").orEmpty()
            if (value.isNotEmpty()) parts.addFirst(value)
            val outer = current.substringBeforeLast('.', "")
            current = outer.takeIf { it.isNotEmpty() && input.annotationValues.containsKey(it) }
        }
        if (parts.isEmpty()) return null
        return parts.reduce { outerPath, innerPath -> joinPaths(outerPath, innerPath) }
    }

    /** A handler's URL parameters, split by the transport that carries them. */
    data class TransportParameters(val path: List<String>, val query: List<String>) {
        companion object {
            val EMPTY = TransportParameters(emptyList(), emptyList())
        }
    }

    /**
     * The parameters a CONTEXT handler actually reads, recovered from its
     * body.
     *
     * A framework whose handlers are annotated declares its parameters in
     * the signature, and [annotatedParameters] reads them there. A context
     * framework declares nothing: `ctx.pathParam("id")` and
     * `call.parameters["id"]` are ordinary calls, and the name is a string
     * literal argument — so the inventory is recovered by folding that
     * argument through the same [KirValueFolder] the route paths use, which
     * means a name built from a `const val` resolves exactly as a literal
     * does and an unprovable name is reported as nothing rather than as a
     * guess.
     *
     * [routeTemplate] settles the transport for a `merged` reader. Ktor's
     * `call.parameters` and the servlet API's `getParameter` read the path
     * and query parameters from ONE map, and the map cannot say which is
     * which — but the route can: a name the route declares as `{name}` came
     * from the path, and a name it does not declare could only have come
     * from the query string.
     */
    internal fun transportParameters(
        fn: KirFunction,
        framework: FrameworkModel,
        folder: KirValueFolder,
        routeTemplate: String,
    ): TransportParameters {
        if (framework.contextReaders.isEmpty()) return TransportParameters.EMPTY
        val declared = pathParametersOf(routeTemplate).toSet()
        val path = sortedSetOf<String>()
        val query = sortedSetOf<String>()
        fun record(kind: String, name: String) {
            if (name.isEmpty()) return
            when (kind) {
                TRANSPORT_PATH -> path.add(name)
                TRANSPORT_QUERY -> query.add(name)
                TRANSPORT_MERGED -> if (name in declared) path.add(name) else query.add(name)
                // A header, cookie, form field or body is attacker input and
                // the security pack seeds it, but it is not a URL parameter
                // and this list is the URL's.
                else -> Unit
            }
        }
        for (block in fn.body?.blocks.orEmpty()) {
            for ((index, ins) in block.instructions.withIndex()) {
                val call = ins as? KirCall ?: continue
                val reader = framework.contextReaders
                    .firstOrNull { matches(call.callee.fqn, it.pattern) } ?: continue
                if (reader.indexed) {
                    // `call.parameters["id"]`: the reader yields the map and
                    // the name is the index of a get against it.
                    val map = call.result ?: continue
                    for ((at, other) in block.instructions.withIndex()) {
                        val get = other as? KirIndexGet ?: continue
                        if (get.receiver != map) continue
                        val folded = folder.valueAt(fn, block, at, get.index) ?: continue
                        if (folded.resolved) record(reader.kind, folded.value.orEmpty())
                    }
                } else if (reader.nameArgument >= 0) {
                    val argument = call.args.getOrNull(reader.nameArgument) ?: continue
                    val folded = folder.valueAt(fn, block, index, argument) ?: continue
                    if (folded.resolved) record(reader.kind, folded.value.orEmpty())
                }
            }
        }
        return TransportParameters(path.toList(), query.toList())
    }

    /**
     * The parameters an ANNOTATED handler declares, from the parameter
     * annotations the KIR carries. The name is the parameter's own, which is
     * what every one of these frameworks defaults to when the annotation
     * names none.
     */
    internal fun annotatedParameters(
        fn: KirFunction,
        framework: FrameworkModel,
        /** The parameter's annotations WITH values, by parameter name. */
        valuesOf: (String) -> List<DeclAnnotation> = { emptyList() },
    ): TransportParameters {
        if (framework.parameterAnnotations.isEmpty()) return TransportParameters.EMPTY
        val path = sortedSetOf<String>()
        val query = sortedSetOf<String>()
        for (param in fn.params) {
            if (param.receiver) continue
            // A parameter the KIR could not name contributes nothing: an
            // unnamed entry in this list is worse than a shorter list.
            val own = param.name?.takeIf { it.isNotEmpty() } ?: continue
            val declaredAnnotations = valuesOf(own)
            val model = (param.annotations + declaredAnnotations.map { it.fqn }).firstNotNullOfOrNull { annotation ->
                framework.parameterAnnotations.firstOrNull { matches(annotation, it.pattern) }
            } ?: continue
            val kind = model.kind
            // The ANNOTATION's name wins: `@PathVariable("idProduct") id`
            // binds the URL variable `idProduct`, and `id` is only the Kotlin
            // name (Spring's value/name aliases; JAX-RS's value).
            val declared = declaredAnnotations.firstOrNull { matches(it.fqn, model.pattern) }
            val name = declared?.let { ann ->
                sequenceOf("value", "name").firstNotNullOfOrNull { key ->
                    ann.namedValues[key]?.firstOrNull()?.takeIf { it.isNotEmpty() }
                }
            } ?: own
            when (kind) {
                TRANSPORT_PATH -> path.add(name)
                TRANSPORT_QUERY -> query.add(name)
                else -> Unit
            }
        }
        return TransportParameters(path.toList(), query.toList())
    }

    internal fun pathParametersOf(path: String): List<String> =
        Regex("\\{([^}:]+)}").findAll(normalizePath(path)).map { it.groupValues[1].trim() }.sorted().toList()

    /**
     * ONE path-template spelling across frameworks. The same route is
     * written four ways on the JVM — Spring's `{id:[0-9]+}`, JAX-RS's
     * `{id: \\d+}`, Vert.x's and Spark's `:id`, Ktor's `{id?}` and `{...}` —
     * and reporting each verbatim means a consumer cannot match two
     * frameworks' routes against one another, or against traffic, without
     * re-implementing every framework's syntax.
     *
     * The normal form is `{name}` for a variable and `*` for a wildcard
     * segment. The REGEX CONSTRAINT is dropped from the template, not
     * ignored: it constrains values, and `pathParameters` names the
     * variable either way.
     */
    /**
     * RFC 6570 URI-template forms Micronaut routes use
     * (docs.micronaut.io 5.1 "URI Templates"): `/books{/id}` "An optional URI
     * variable", `/books{?max,offset}` "Optional query parameters",
     * `{/path:.*}{.ext}` a path plus extension, `/books/{+path}` reserved
     * (multi-segment) matching, `{#frag}` a fragment. Rewritten to the
     * `{name}` normal form; the query and fragment expansions are NOT path
     * and are removed from it (their names are [uriTemplateQueryParameters]).
     */
    private fun rewriteUriTemplate(path: String): String =
        path.replace(Regex("""\{[?&][^}]*}"""), "")
            .replace(Regex("""\{#[^}]*}"""), "")
            .replace(Regex("""\{/([^}:]+)(?::[^}]*)?}"""), "/{$1}")
            .replace(Regex("""\{\.([^}:]+)(?::[^}]*)?}"""), ".{$1}")
            .replace(Regex("""\{\+([^}:]+)(?::[^}]*)?}"""), "{$1}")

    /** The query names an RFC 6570 `{?a,b}` / `{&c}` expansion declares. */
    internal fun uriTemplateQueryParameters(path: String): List<String> =
        Regex("""\{[?&]([^}]*)}""").findAll(path)
            .flatMap { it.groupValues[1].split(',').asSequence() }
            .map { it.trim().removeSuffix("*").substringBefore(':') }
            .filter { it.isNotEmpty() }
            .distinct().sorted().toList()

    internal fun normalizePath(path: String): String {
        if (path.isEmpty()) return path
        val segments = rewriteUriTemplate(path).split('/').map { segment ->
            when {
                // Vert.x / Spark / Javalin v3: `:id`
                segment.startsWith(":") && segment.length > 1 -> "{" + segment.removePrefix(":") + "}"
                // Spring `**`, Ktor `{...}` tailcard: any remaining path.
                segment == "**" || segment == "{...}" -> "**"
                segment == "*" -> "*"
                segment.startsWith("{") && segment.endsWith("}") -> {
                    val inner = segment.removeSurrounding("{", "}")
                    // Spring `{id:[0-9]+}` / JAX-RS `{id: \\d+}`: the name is
                    // everything before the first colon. Ktor's `{id?}`
                    // marks the variable optional; the name is the same.
                    // Spring's capture-all `{*path}` names the variable too.
                    "{" + inner.substringBefore(':').removeSuffix("?").removePrefix("*").trim() + "}"
                }

                else -> segment
            }
        }
        // `/templates` + `{/id}` composes a doubled separator; a URL path
        // never means an empty segment here.
        return segments.joinToString("/").replace(Regex("/{2,}"), "/")
    }
}

/**
 * Resolves a lambda-valued argument register to its extracted body's
 * canonical name, following assignment aliases (`val f = { .. }; g(f)`).
 */
internal object LambdaResolver {
    fun resolve(fn: KirFunction, register: String, input: EndpointDetector.Input): String? {
        val lambdas = HashMap<String, String>()
        val assigns = HashMap<String, String>()
        for (block in fn.body?.blocks.orEmpty()) {
            for (ins in block.instructions) {
                when (ins) {
                    is io.cdxgen.kosi.kir.KirLambda -> lambdas[ins.result] = ins.function
                    is io.cdxgen.kosi.kir.KirAssign -> assigns[ins.result] = ins.source
                    else -> {}
                }
            }
        }
        var reg: String? = register
        var hops = 0
        while (reg != null && hops < 4) {
            hops++
            lambdas[reg]?.let { return it }
            reg = assigns[reg] ?: break
        }
        return null
    }
}
