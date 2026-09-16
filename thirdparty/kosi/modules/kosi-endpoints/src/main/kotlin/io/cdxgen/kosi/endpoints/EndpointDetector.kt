package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.kir.CallKind
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
import io.cdxgen.kosi.kir.KirValueFolder
import io.cdxgen.kosi.models.EndpointsPack
import io.cdxgen.kosi.models.FrameworkModel
import io.cdxgen.kosi.schema.Position

/**
 * Inbound endpoint detection (P7): one detector over the KIR + the resolved
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
    )

    class Input(
        val module: KirModule,
        /** Canonical name of the declaration -> its annotations (with values). */
        val annotationValues: Map<String, List<DeclAnnotation>>,
        val folder: KirValueFolder,
        /** Extracted-lambda links: lambda canonical -> (parent function, creating call). */
        val lambdaLinks: Map<String, LambdaLink>,
    )

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
        /** Media types the handler's annotations name it as accepting (P14). */
        val consumes: List<String> = emptyList(),
        /** Media types the handler's annotations name it as producing (P14). */
        val produces: List<String> = emptyList(),
        /** Authentication requirements, from annotations or the enclosing DSL (P14). */
        val authentication: List<String> = emptyList(),
    )

    fun detect(input: Input, pack: EndpointsPack = io.cdxgen.kosi.models.EndpointModels.loadBuiltin()): List<Candidate> {
        val byKey = linkedMapOf<String, Candidate>()
        fun add(candidate: Candidate) {
            val key = candidate.framework + "\u0000" + candidate.handlerSymbol + "\u0000" + candidate.pathTemplate
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
        return byKey.values.sortedWith(
            compareBy({ it.framework }, { it.pathTemplate }, { it.handlerSymbol }),
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
        val annotations = input.annotationValues[fn.canonicalName].orEmpty()
        val ownerAnnotations = fn.ownerAnnotations
        val ownerCanonical = fn.canonicalName.substringBeforeLast('.')
        val ownerDeclAnnotations = input.annotationValues[ownerCanonical].orEmpty()

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
            val path = classMapping.value?.trim()?.removeSurrounding("\"").orEmpty()
            add(
                Candidate(
                    framework = framework.id,
                    httpMethods = handler.methods,
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
                val prefix = ownerDeclAnnotations
                    .firstOrNull { ann -> framework.pathPrefixAnnotations.any { matches(ann.fqn, it) } }
                    ?.value?.trim()?.removeSurrounding("\"").orEmpty()
                val rawPath = matched.value?.trim()?.removeSurrounding("\"").orEmpty()
                val path = joinPaths(prefix, rawPath)
                add(
                    Candidate(
                        framework = framework.id,
                        httpMethods = mapping.methods,
                        pathTemplate = normalizePath(path),
                        pathParameters = pathParametersOf(path),
                        handlerSymbol = fn.canonicalName,
                        foundBy = "annotation",
                        position = Position(fn.file, fn.line, fn.line),
                        exported = null,
                        permissions = null,
                        deepLinkHosts = null,
                    ),
                )
                return
            }
        }
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
                            detectRouteCall(fn, block, index, ins, framework, mapping.methods, input, add)
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
                        // to whichever framework sat first in the pack. R84
                        // showed the wrong-framework answer in production: a
                        // Ktor 1.x app's routes reported as Vert.x. A miss
                        // is never a WRONG answer.
                        val byName = pack.frameworks.filter { f ->
                            f.dslFunctions.any { it.pattern.substringAfterLast('.') == ins.name && !it.nesting } &&
                                hasRouteShape(fn, ins, input)
                        }
                        if (byName.isEmpty()) continue
                        val evidenced = byName.firstOrNull { f -> f.dslPackages().any { it in resolvedPackages } }
                        if (evidenced != null) {
                            val mapping = evidenced.dslFunctions.firstOrNull {
                                it.pattern.substringAfterLast('.') == ins.name && !it.nesting
                            } ?: continue
                            detectRouteCall(fn, block, index, ins, evidenced, mapping.methods, input, add)
                        } else {
                            // No framework's package is demonstrably present:
                            // publish the ROUTE (the path and handler are
                            // real) with no framework claim and no verb list
                            // — a verb would name a framework's builder.
                            detectRouteCall(fn, block, index, ins, null, emptyList(), input, add)
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
        val callArgs = when (ins) {
            is KirCall -> ins.args
            is KirDynamicCall -> ins.args
            else -> emptyList()
        }
        val prefix = prefixChain(fn.canonicalName, input)

        // A TYPED route names its path on a class, not at the call site:
        // `get<Article> { }` with `@Resource("/articles/{id}")` on
        // `Article`. The path argument this function otherwise reads simply
        // does not exist, so such a route used to resolve to nothing.
        val typeArguments = (ins as? KirCall)?.typeArguments.orEmpty()
        if (framework?.resourceAnnotations?.isNotEmpty() == true && typeArguments.isNotEmpty()) {
            val resourcePath = resourcePathOf(typeArguments.first(), framework, input)
            if (resourcePath != null) {
                val handler = handlerOfRegs(fn, callArgs, input)
                publish(add, framework, methods, joinPaths(prefix, resourcePath), handler ?: "", fn, "dsl")
                return
            }
        }

        val pathReg = callArgs.firstOrNull() ?: return

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
        // P15: Vert.x builds routes as a CHAIN —
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
            authentication = roles,
        )
    }

    /**
     * Media and handler declared on the ROUTE OBJECT'S receiver chain
     * (Vert.x): the route call's result flows through `.produces(..)` /
     * `.consumes(..)` calls before `.handler { .. }` attaches the real
     * handler. The walk follows the receiver chain one call at a time — a
     * `.produces` result is the input of the NEXT chained call — and stops
     * at the first call that consumes the chain without producing a route
     * (the handler attach).
     */
    private class ChainedRouteFacts(
        val handler: String?,
        val consumes: List<String>,
        val produces: List<String>,
    )

    private fun chainedRouteFacts(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirIns,
        framework: FrameworkModel?,
        input: Input,
    ): ChainedRouteFacts {
        if (framework == null || (framework.mediaDsl.isEmpty() && framework.handlerDsl.isEmpty())) {
            return ChainedRouteFacts(null, emptyList(), emptyList())
        }
        val result = (ins as? KirCall)?.result ?: return ChainedRouteFacts(null, emptyList(), emptyList())
        var consumes = mutableListOf<String>()
        var produces = mutableListOf<String>()
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
                handler = chainedHandlerOf(fn, block, nextAt, next, input)
                break
            }
            break
        }
        return ChainedRouteFacts(handler, consumes, produces)
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
    private fun hasRouteShape(fn: KirFunction, ins: KirDynamicCall, input: Input): Boolean {
        if (ins.args.size < 2) return false
        val handler = LambdaResolver.resolve(fn, ins.args.last(), input) ?: return false
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

    /** http4k: `"/path" bind GET to { ... }` — receiver is the path, the `to` side the handler. */
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
        val folded = input.folder.valueAt(fn, block, index, receiver)
        val path = folded?.value ?: rawOf(fn, block, index, receiver)
        // The handler lives on the `to` call whose receiver is this bind's
        // result, and the method constant is the bind's argument.
        val target = bindTarget(fn, ins.result, input, framework)
        val method = ins.args.firstOrNull()?.let { methodReg ->
            block.instructions.firstOrNull {
                it is io.cdxgen.kosi.kir.KirFieldGet && it.result == methodReg
            }?.let {
                (it as io.cdxgen.kosi.kir.KirFieldGet).path.elements.lastOrNull()
                    ?.let { e -> (e as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name }
            }
        }
        publish(add, framework, listOfNotNull(method), path, target?.handler ?: "", fn, "dsl", authentication = target?.authentication ?: emptyList())
    }

    /** A bind's `to` target: the handler, and any auth the target declares. */
    private class BindTarget(val handler: String?, val authentication: List<String>)

    private fun bindTarget(fn: KirFunction, bindResult: String?, input: Input, framework: FrameworkModel): BindTarget? {
        if (bindResult == null) return null
        for (block in fn.body?.blocks.orEmpty()) {
            for (ins in block.instructions) {
                if (ins is KirCall && ins.receiver == bindResult && ins.callee.fqn.substringAfterLast('.') == "to") {
                    val arg = ins.args.lastOrNull() ?: return BindTarget(null, emptyList())
                    // P16 §4: contract mode binds `to SecureRoute(security,
                    // handler)` — the route's auth requirement declared AT the
                    // route, the scheme being the construction's first
                    // argument (pack: secureRouteConstructors). Core DSL
                    // binds a plain lambda and declares nothing.
                    for (pattern in framework.secureRouteConstructors) {
                        val construct = constructorOfReg(fn, arg, pattern) ?: continue
                        val scheme = construct.args.firstOrNull()?.let { secReg ->
                            securitySchemeOf(fn, block, secReg)
                        }
                        val handlerReg = construct.args.lastOrNull()
                        return BindTarget(
                            handlerReg?.let { LambdaResolver.resolve(fn, it, input) },
                            listOfNotNull(scheme?.let { "SecureRoute($it)" }),
                        )
                    }
                    return BindTarget(LambdaResolver.resolve(fn, arg, input), emptyList())
                }
            }
        }
        return null
    }

    /** The constructor call that produced [reg], when its callee matches [pattern]. */
    private fun constructorOfReg(fn: KirFunction, reg: String, pattern: String): KirCall? {
        for (block in fn.body?.blocks.orEmpty()) {
            for (ins in block.instructions) {
                if (ins is KirCall && ins.result == reg && ins.callee.kind == CallKind.CONSTRUCTOR &&
                    matches(ins.callee.fqn, pattern)
                ) {
                    return ins
                }
            }
        }
        return null
    }

    /** The security scheme a SecureRoute's first argument names: its construction's own simple name. */
    private fun securitySchemeOf(fn: KirFunction, block: KirBlock, reg: String): String? {
        for (ins in block.instructions) {
            if (ins is KirCall && ins.result == reg && ins.callee.kind == CallKind.CONSTRUCTOR) {
                return ins.callee.fqn.substringAfterLast('.')
            }
            if (ins is io.cdxgen.kosi.kir.KirNew && ins.result == reg) {
                return ins.type.substringAfterLast('.')
            }
        }
        return reg.substringAfterLast('.')
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
        return LambdaResolver.resolve(fn, handlerReg, input)
    }

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
     * The route prefix carried by the chain of `route(...)`-shaped calls that
     * extracted this function as a lambda: `route("/x") { get("/y") {} }`
     * composes "/x" + "/y". Bounded hops keep pathological chains cheap.
     */
    private fun prefixChain(functionCanonical: String, input: Input): String {
        var current: String? = functionCanonical
        val segments = mutableListOf<String>()
        var hops = 0
        while (current != null && hops < 8) {
            hops++
            val link = input.lambdaLinks[current] ?: break
            val call = link.creationCall
            if (EndpointDetector.callName(call) in setOf("route", "path")) {
                val parent = input.module.functions.firstOrNull { it.canonicalName == link.parentFunction }
                val block = parent?.body?.blocks?.firstOrNull { it.instructions.any { it === call } }
                if (parent != null && block != null) {
                    val index = block.instructions.indexOfFirst { it === call }
                    val callArgs = when (call) {
                        is KirCall -> call.args
                        is KirDynamicCall -> call.args
                        else -> emptyList()
                    }
                    val folded = callArgs.firstOrNull()?.let { input.folder.valueAt(parent, block, index, it) }
                    folded?.value?.trim('/')?.takeIf { it.isNotEmpty() }?.let { segments.add(0, it) }
                }
            }
            current = link.parentFunction
        }
        // A composed prefix is an absolute path: the leading slash comes
        // from the nesting call's own template ("", "/metrics" etc.).
        val joined = segments.joinToString("/")
        return if (joined.isEmpty()) "" else "/$joined"
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
    internal fun annotatedParameters(fn: KirFunction, framework: FrameworkModel): TransportParameters {
        if (framework.parameterAnnotations.isEmpty()) return TransportParameters.EMPTY
        val path = sortedSetOf<String>()
        val query = sortedSetOf<String>()
        for (param in fn.params) {
            if (param.receiver) continue
            val kind = param.annotations.firstNotNullOfOrNull { annotation ->
                framework.parameterAnnotations.firstOrNull { matches(annotation, it.pattern) }?.kind
            } ?: continue
            // A parameter the KIR could not name contributes nothing: an
            // unnamed entry in this list is worse than a shorter list.
            val name = param.name?.takeIf { it.isNotEmpty() } ?: continue
            when (kind) {
                TRANSPORT_PATH -> path.add(name)
                TRANSPORT_QUERY -> query.add(name)
                else -> Unit
            }
        }
        return TransportParameters(path.toList(), query.toList())
    }

    private fun pathParametersOf(path: String): List<String> =
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
    internal fun normalizePath(path: String): String {
        if (path.isEmpty()) return path
        val segments = path.split('/').map { segment ->
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
                    "{" + inner.substringBefore(':').removeSuffix("?").trim() + "}"
                }

                else -> segment
            }
        }
        return segments.joinToString("/")
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
