package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirStore

/**
 * The values a `for` loop variable takes, when the loop walks a LITERAL
 * collection. ktorio/ktor-samples httpbin registers 25 routes this way:
 *
 *     for (method in ALL_METHODS) { method(method) { handle { } } }
 *     for ((method, path) in listOf(HttpMethod.Post to "/post", ..)) {
 *         route(path) { method(method) { handle { } } }
 *     }
 *
 * The KIR lowers a `for` over a collection to `iterator()`, then
 * `hasNext()`/`next()`, with the loop variable stored from `next()` (or from
 * `componentN()` of it when destructured). This walks back from a register
 * to that `next()`, then to the collection: a `listOf`/`setOf`/`arrayOf`
 * call, inline or as the initializer of a top-level `val`. It never guesses:
 * a collection that is a parameter, a computed value or a call kosi does
 * not model resolves to null, and the route stays unresolved.
 *
 * Without the framework jar the loop's calls do not resolve: `HttpMethod`
 * does not type, so `listOf(HttpMethod.Get, ..)`, `a to b`, `iterator()`
 * and `next()` lower as DYNAMIC calls. These are matched by name, receiver
 * shape included. A receiverless `listOf` that failed to resolve cannot be
 * a user's own function, which is source and would resolve; only the
 * stdlib's is left.
 */
internal object LoopElements {

    /**
     * One loop's elements as seen through one variable. [key] identifies
     * the ITERATION (function + iterator register), so two variables bound
     * by the same destructured loop correlate element by element. Every
     * entry of [values] is resolved; a single unresolvable element makes
     * the whole binding null.
     */
    data class Binding(val key: String, val values: List<String>)

    enum class Kind { VERB, STRING }

    private val BUILDER_NAMES = setOf("listOf", "setOf", "mutableListOf", "mutableSetOf", "arrayListOf", "linkedSetOf", "hashSetOf", "arrayOf")

    /** A call's name, receiver and arguments, resolved or dynamic. */
    private data class Call(val name: String, val fqn: String?, val receiver: String?, val args: List<String>, val result: String?)

    private fun call(ins: KirIns?): Call? = when (ins) {
        is KirCall -> Call(ins.callee.fqn.substringAfterLast('.'), ins.callee.fqn, ins.receiver, ins.args, ins.result)
        is KirDynamicCall -> Call(ins.name, null, ins.receiver, ins.args, ins.result)
        else -> null
    }

    private fun isBuilder(c: Call): Boolean =
        c.receiver == null && (if (c.fqn != null) c.fqn in COLLECTION_BUILDERS else c.name in BUILDER_NAMES)

    private val COLLECTION_BUILDERS = setOf(
        "kotlin.collections.listOf", "kotlin.collections.setOf", "kotlin.collections.mutableListOf",
        "kotlin.collections.mutableSetOf", "kotlin.collections.arrayListOf", "kotlin.collections.linkedSetOf",
        "kotlin.collections.hashSetOf", "kotlin.arrayOf",
    )

    fun resolve(fn: KirFunction, register: String, kind: Kind, input: EndpointDetector.Input, depth: Int = 0): Binding? {
        if (depth > 6) return null
        // A captured variable: `%cK` is the K-th capture of the KirLambda
        // that created this function, named in the parent's own registers.
        if (register.startsWith("%c")) {
            val k = register.removePrefix("%c").toIntOrNull() ?: return null
            val link = input.lambdaLinks[fn.canonicalName] ?: return null
            val parent = input.module.functions.firstOrNull { it.canonicalName == link.parentFunction } ?: return null
            val lambda = instructions(parent).filterIsInstance<KirLambda>().firstOrNull { it.function == fn.canonicalName } ?: return null
            val captured = lambda.captures.getOrNull(k) ?: return null
            return resolve(parent, captured, kind, input, depth + 1)
        }
        // Exactly one store: a reassigned `var` (or a slot two loops share)
        // has no single loop to bind to.
        val stores = instructions(fn).filterIsInstance<KirStore>().filter { it.target == register }.toList()
        if (stores.size > 1) return null
        val value = stores.singleOrNull()?.value ?: register
        val producer = call(definer(fn, value)) ?: return null
        val (nextCall, component) = when (producer.name) {
            "next" -> producer to 0
            "component1", "component2" -> {
                val next = call(producer.receiver?.let { definer(fn, it) }) ?: return null
                if (next.name != "next") return null
                next to producer.name.last().digitToInt()
            }
            else -> return null
        }
        val iterator = call(nextCall.receiver?.let { definer(fn, it) }) ?: return null
        if (iterator.name != "iterator") return null
        val collection = iterator.receiver ?: return null
        val (owner, elements) = elementsOf(fn, collection, input) ?: return null
        val values = elements.map { element ->
            val reg = if (component == 0) element else pairComponent(owner, element, component) ?: return null
            valueOf(owner, reg, kind, input) ?: return null
        }
        if (values.isEmpty()) return null
        return Binding("${fn.canonicalName}#${iterator.result}", values)
    }

    /** The element registers of a literal collection, and the function they live in. */
    private fun elementsOf(fn: KirFunction, register: String, input: EndpointDetector.Input): Pair<KirFunction, List<String>>? {
        when (val def = definer(fn, register)) {
            is KirCall, is KirDynamicCall -> call(def)?.takeIf { isBuilder(it) && !mutated(fn, register, it) }?.let { return fn to it.args }
            is KirFieldGet -> {
                // A top-level `val` read: its initializer lowers to a
                // function of the same name in the declaring package. The
                // one that returns a literal collection is the one read.
                val name = (def.path.elements.lastOrNull() as? AccessPath.Element.Field)?.name ?: return null
                // The reader's own PACKAGE (a member function's canonical name
                // carries its class too): a same-named val elsewhere is not it.
                val scopes = generateSequence(fn.canonicalName.substringBefore('$')) { s -> s.substringBeforeLast('.', "").takeIf { it.isNotEmpty() } }.drop(1)
                val initializer = scopes.firstNotNullOfOrNull { scope ->
                    input.module.functions.firstOrNull { it.canonicalName == "$scope.$name" && it.params.isEmpty() }
                } ?: return null
                val returned = instructions(initializer).filterIsInstance<KirReturn>().mapNotNull { it.value }.singleOrNull() ?: return null
                val built = call(definer(initializer, returned)) ?: return null
                // A mutable val any function mutates is not its initializer.
                val mutatedAnywhere = MUTABLE_BUILDERS.contains(built.name) && input.module.functions.any { f ->
                    instructions(f).any { ins ->
                        val c = call(ins)
                        c != null && c.name in MUTATORS && c.receiver != null &&
                            (definer(f, c.receiver) as? KirFieldGet)?.path?.elements?.lastOrNull()?.let { (it as? AccessPath.Element.Field)?.name } == name
                    }
                }
                if (isBuilder(built) && !mutatedAnywhere) return initializer to built.args
            }
            else -> Unit
        }
        return null
    }

    private val MUTABLE_BUILDERS = setOf("mutableListOf", "mutableSetOf", "arrayListOf", "linkedSetOf", "hashSetOf")
    private val MUTATORS = setOf("add", "addAll", "plusAssign", "remove", "removeAll", "clear", "set", "retainAll")

    /** Whether a mutable collection built into [register] is mutated in [fn] before or after the loop. */
    private fun mutated(fn: KirFunction, register: String, built: Call): Boolean {
        if (built.name !in MUTABLE_BUILDERS) return false
        val aliases = mutableSetOf(register)
        instructions(fn).forEach { if (it is KirStore && it.value in aliases) aliases.add(it.target) }
        return instructions(fn).any { ins -> call(ins)?.let { it.name in MUTATORS && it.receiver in aliases } == true }
    }

    /** `a to b`: component1 is the receiver, component2 the argument. */
    private fun pairComponent(fn: KirFunction, element: String, component: Int): String? {
        val to = call(definer(fn, element)) ?: return null
        if (to.name != "to" || (to.fqn != null && to.fqn != "kotlin.to") || to.args.size != 1) return null
        return if (component == 1) to.receiver else to.args.single()
    }

    private fun valueOf(fn: KirFunction, register: String, kind: Kind, input: EndpointDetector.Input): String? = when (kind) {
        // `HttpMethod.Post` lowers as a field read whose last element is the
        // verb, the same rule the non-loop selector reads.
        Kind.VERB -> ((definer(fn, register) as? KirFieldGet)?.path?.elements?.lastOrNull() as? AccessPath.Element.Field)
            ?.name?.uppercase()?.takeIf { it in EndpointDetector.HTTP_METHODS }
        Kind.STRING -> blockOf(fn, register)?.let { (block, index) -> input.folder.valueAt(fn, block, index, register)?.value }
    }

    private fun instructions(fn: KirFunction): Sequence<KirIns> =
        fn.body?.blocks?.asSequence()?.flatMap { it.instructions.asSequence() }.orEmpty()

    private fun definer(fn: KirFunction, register: String): KirIns? =
        instructions(fn).firstOrNull { resultOf(it) == register }

    private fun blockOf(fn: KirFunction, register: String): Pair<KirBlock, Int>? {
        for (block in fn.body?.blocks.orEmpty()) {
            val index = block.instructions.indexOfFirst { resultOf(it) == register }
            if (index >= 0) return block to index + 1
        }
        return null
    }

    private fun resultOf(ins: KirIns): String? = when (ins) {
        is KirCall -> ins.result
        is KirDynamicCall -> ins.result
        is KirFieldGet -> ins.result
        is io.cdxgen.kosi.kir.KirLoad -> ins.result
        else -> null
    }
}
