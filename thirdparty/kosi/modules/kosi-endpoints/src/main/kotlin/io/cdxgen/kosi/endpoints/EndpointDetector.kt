package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.kir.KirAssign
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirFunction
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

    /** A declaration annotation the resolved front end carried: fqn + first constant value. */
    data class DeclAnnotation(
        val fqn: String,
        val value: String?,
        val line: Int,
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

    data class Candidate(
        val framework: String,
        val httpMethods: List<String>,
        val pathTemplate: String,
        val pathParameters: List<String>,
        val handlerSymbol: String,
        val foundBy: String,
        val position: Position?,
        val exported: Boolean?,
        val permissions: List<String>?,
        val deepLinkHosts: List<String>?,
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
        for (fn in functions) {
            detectAnnotated(fn, input, pack, ::add)
            detectGrpc(fn, pack, ::add)
            detectDsl(fn, input, pack, ::add)
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
        if (annotations.isEmpty()) return
        val ownerAnnotations = fn.ownerAnnotations
        val ownerCanonical = fn.canonicalName.substringBeforeLast('.')
        val ownerDeclAnnotations = input.annotationValues[ownerCanonical].orEmpty()

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
                        pathTemplate = path,
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

    private fun detectDsl(
        fn: KirFunction,
        input: Input,
        pack: EndpointsPack,
        add: (Candidate) -> Unit,
    ) {
        val body = fn.body ?: return
        for (block in body.blocks) {
            for ((index, ins) in block.instructions.withIndex()) {
                val framework = when (ins) {
                    is KirCall -> pack.frameworks.firstOrNull { f ->
                        f.dslFunctions.any { matches(ins.callee.fqn, it.pattern) } ||
                            f.bindFunctions.any { matchesCallName(ins, it.pattern) }
                    }

                    // An UNRESOLVED extension lowers as a dynamic call that
                    // keeps only its name. It stands for a DSL route when it
                    // carries the route SHAPE - a path value plus a lambda -
                    // which is how `routing { get("/x") { .. } }` lowers when
                    // the receiver type never resolved. A RESOLVED homonym
                    // (the legacy fixture's own `get`) is a KirCall whose
                    // fqn the suffix rule rejects, so resolved type identity
                    // still wins over name matching.
                    is KirDynamicCall -> pack.frameworks.firstOrNull { f ->
                        f.dslFunctions.any { it.pattern.substringAfterLast('.') == ins.name && !it.nesting } &&
                            hasRouteShape(fn, ins, input)
                    }

                    else -> null
                } ?: continue
                when (ins) {
                    is KirCall -> {
                        val mapping = framework.dslFunctions.firstOrNull { matches(ins.callee.fqn, it.pattern) }
                        if (mapping != null) {
                            if (mapping.nesting) continue
                            detectRouteCall(fn, block, index, ins, framework, mapping.methods, input, add)
                        } else {
                            detectBindCall(fn, block, index, ins, framework, input, add)
                        }
                    }

                    is KirDynamicCall -> {
                        val mapping = framework.dslFunctions.firstOrNull { it.pattern.substringAfterLast('.') == ins.name }
                        if (mapping != null && !mapping.nesting) {
                            detectRouteCall(fn, block, index, ins, framework, mapping.methods, input, add)
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
        framework: FrameworkModel,
        methods: List<String>,
        input: Input,
        add: (Candidate) -> Unit,
    ) {
        val callArgs = when (ins) {
            is KirCall -> ins.args
            is KirDynamicCall -> ins.args
            else -> emptyList()
        }
        val pathReg = callArgs.firstOrNull() ?: return
        val prefix = prefixChain(fn.canonicalName, input)
        val folded = input.folder.valueAt(fn, block, index, pathReg)
        val foldedPath = folded?.value
        if (foldedPath == null) {
            // An unresolvable path is UNRESOLVED evidence, not a silently
            // dropped endpoint: the raw register rendering is the template.
            publish(add, framework, methods, joinPaths(prefix, rawOf(fn, block, index, pathReg)), fn.canonicalName, fn, "dsl")
            return
        }
        val handler = handlerOfRegs(fn, callArgs, input)
        val boundMethod: String? = when (ins) {
            is KirCall -> boundMethodName(fn, block, index, ins)
            else -> null
        }
        publish(add, framework, boundMethod?.let { listOf(it) } ?: methods, joinPaths(prefix, foldedPath), handler ?: "", fn, "dsl")
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
        val handler = bindHandler(fn, ins.result, input)
        val method = ins.args.firstOrNull()?.let { methodReg ->
            block.instructions.firstOrNull {
                it is io.cdxgen.kosi.kir.KirFieldGet && it.result == methodReg
            }?.let {
                (it as io.cdxgen.kosi.kir.KirFieldGet).path.elements.lastOrNull()
                    ?.let { e -> (e as? io.cdxgen.kosi.kir.AccessPath.Element.Field)?.name }
            }
        }
        publish(add, framework, listOfNotNull(method), path, handler ?: "", fn, "dsl")
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

    private fun handlerOfRegs(fn: KirFunction, args: List<String>, input: Input): String? {
        if (args.size < 2) return null
        return LambdaResolver.resolve(fn, args.last(), input)
    }

    private fun publish(
        add: (Candidate) -> Unit,
        framework: FrameworkModel,
        methods: List<String>,
        path: String,
        handler: String,
        at: KirFunction,
        foundBy: String,
    ) {
        add(
            Candidate(
                framework = framework.id,
                httpMethods = methods,
                pathTemplate = path,
                pathParameters = pathParametersOf(path),
                handlerSymbol = handler,
                foundBy = foundBy,
                position = Position(at.file, at.line, at.line),
                exported = null,
                permissions = null,
                deepLinkHosts = null,
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
        val grpc: FrameworkModel = pack.frameworks.firstOrNull { it.kind == "supertype" } ?: return
        val base = supertypes.firstOrNull { supertype ->
            grpc.supertypeSuffixes.any { supertype.endsWith(it) } &&
                grpc.supertypeMarkers.any { supertype.contains(it) }
        } ?: return
        // The RPC path is `/<Service>/<Method>`; the service names out of
        // the generated base's simple name minus its suffix
        // (`GreeterImplBase` -> `Greeter`, the proto service's name).
        val suffix = grpc.supertypeSuffixes.firstOrNull { base.endsWith(it) } ?: "ImplBase"
        val service = base.substringAfterLast('.').removeSuffix(suffix)
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

    private fun pathParametersOf(path: String): List<String> =
        Regex("\\{([^}:]+)}").findAll(path).map { it.groupValues[1].trim() }.sorted().toList()
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
