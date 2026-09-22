package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirAssign
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCast
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirElvis
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirIndexGet
import io.cdxgen.kosi.kir.KirIndexSet
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirPhi
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.kir.KirStringConcat
import io.cdxgen.kosi.kir.KirTypeCheck

/**
 * Factories whose arguments BECOME the collection's elements. Kept to the
 * builders that take their elements directly — a function that computes its
 * elements is not on this list, because its result is not its arguments.
 */
private val COLLECTION_FACTORIES = setOf(
    "kotlin.collections.listOf",
    "kotlin.collections.mutableListOf",
    "kotlin.collections.arrayListOf",
    "kotlin.collections.setOf",
    "kotlin.collections.mutableSetOf",
    "kotlin.arrayOf",
)

/**
 * the object that is the same object.
 *
 * Everything the taint engine tracks is keyed by `(register, access path)` —
 * a NAME, not a thing. Two names for one object are two unrelated keys, so
 * `val g = h; g.v = tainted; sink(h.v)` reports nothing, and an object
 * carrying taint in a field loses it the moment a second register names it.
 * This class is the allocation-site abstraction that closes that gap: a
 * fixpoint over the SAME CFG the taint runs on, computing which registers
 * may hold the same abstract object.
 *
 * The tokens are abstract objects:
 *  - `alloc:<site>`  — one per `KirNew` / constructor call (the allocation
 *    site; the doc's primary abstraction);
 *  - `param:<i>`     — a function parameter (one abstract object per
 *    parameter, the granularity the summary channel already speaks);
 *  - `opaque:<site>` — a value from a call the run has no model for, or a
 *    load; per-site so two unknown values are not silently aliased;
 *  - `lambda:<canonical>` — a function value at its allocation site (the
 *    KirLambda instruction): an object whose target is KNOWN, which is what
 *    a call through it resolves to.
 *
 * A mini-heap rides along — `(register, path) -> tokens` — because the
 * deep tier must follow a value stored in another object's field back out:
 * `box.inner = holder; ... box.inner.v`. Field writes fan out through the
 * WRITER's alias class, so a write through one name of an object is a write
 * through all of them.
 *
 * Soundness direction (the change contract): the relation is MAY-alias.
 * Re-assignment unions (a `var` re-pointed may still hold the old object),
 * allocation kills (a fresh object is not the old one), and nothing narrows
 * on types. A false alias can cost a finding's precision, never its
 * existence; a silent false negative is the defect this exists to remove.
 */
internal class AliasAnalysis(
    private val compiled: CompiledFunction,
    /** The summary table to consult (the reporting engine's final one; the summary engine's current one). */
    private val summaryOf: (KirCall) -> FunctionSummary?,
) {
    /** Register -> the abstract objects it may hold. */
    private val points = HashMap<String, MutableSet<String>>()

    /** (register, path suffix) -> the abstract objects stored in that field. */
    private val heap = HashMap<String, MutableSet<String>>()

    /** token -> the registers that may hold it; the class lookup's index. */
    private val tokenRegisters = HashMap<String, MutableSet<String>>()

    private fun learn(register: String, token: String) {
        if (points.getOrPut(register) { sortedSetOf() }.add(token)) {
            tokenRegisters.getOrPut(token) { sortedSetOf() }.add(register)
        }
    }

    private fun learnAll(register: String, tokens: Collection<String>) {
        if (tokens.isEmpty()) return
        val set = points.getOrPut(register) { sortedSetOf() }
        for (token in tokens) {
            if (set.add(token)) tokenRegisters.getOrPut(token) { sortedSetOf() }.add(register)
        }
    }

    /** A FRESH object: the register stops naming whatever it held before. */
    private fun replace(register: String, token: String) {
        forget(register)
        learn(register, token)
    }

    private fun forget(register: String) {
        val old = points.remove(register) ?: return
        for (token in old) {
            tokenRegisters[token]?.remove(register)
        }
    }

    private fun heapWrite(base: String, suffix: String, tokens: Collection<String>) {
        if (tokens.isEmpty()) return
        heap.getOrPut("$base\u0000$suffix") { sortedSetOf() }.addAll(tokens)
    }

    private fun heapRead(base: String, suffix: String): Set<String> =
        heap["$base\u0000$suffix"].orEmpty()

    private fun pathSuffix(path: AccessPath?): String =
        if (path == null) {
            ""
        } else {
            path.elements.joinToString(".") { element ->
                when (element) {
                    is AccessPath.Element.Field -> element.name
                    AccessPath.Element.Index -> "[]"
                    AccessPath.Element.Star -> "*"
                }
            }
        }

    private fun classOf(register: String): Set<String> {
        // The alias class, computed at fixpoint: every register sharing a
        // token with [register], plus itself.
        val out = sortedSetOf(register)
        for (token in points[register].orEmpty()) {
            tokenRegisters[token]?.let { out.addAll(it) }
        }
        return out
    }

    /** Registers that may name the same object as [register], itself included. */
    fun aliasClass(register: String): Set<String> = aliasClasses[register] ?: setOf(register)

    /**
     * The abstract objects [register] may hold. Consumers use it to ask where
     * a value CAME FROM — a `param:` token means the caller supplied it, so
     * the caller is where it can be named.
     */
    fun tokensOf(register: String): Set<String> = points[register].orEmpty()

    /** Lambda bodies [register] may hold, when it holds function values. */
    fun lambdaTargets(register: String): List<String> =
        points[register].orEmpty().filter { it.startsWith("lambda:") }.map { it.removePrefix("lambda:") }.sorted()

    private val aliasClasses: Map<String, Set<String>> by lazy {
        val out = HashMap<String, Set<String>>()
        val seen = HashSet<String>()
        for (register in points.keys.sorted()) {
            if (register in seen) continue
            val cls = classOf(register)
            for (member in cls) {
                out[member] = cls
                seen.add(member)
            }
        }
        out
    }

    fun run() {
        // Parameters seed their own abstract objects FIRST: a summary's
        // effects speak parameter indices, and the caller's argument class
        // is what those effects fan out through at application time.
        compiled.function.params.forEachIndexed { index, param ->
            learn(param.register, "param:$index")
        }
        // The fixpoint: monotone over finitely many (register, token) pairs.
        // The budget mirrors the taint worklist's shape — generous, and its
        // trip is a defect, not a setting. (The token index is maintained
        // incrementally, so the fan-outs inside the fixpoint see the classes
        // the earlier iterations learned.)
        val budget = 64 + 16 * compiled.blocks.size
        var rounds = 0
        var changed = true
        while (changed && rounds < budget) {
            changed = false
            rounds++
            for (block in compiled.blocks) {
                for (ins in block.instructions) {
                    changed = step(ins) || changed
                }
            }
        }
    }

    private fun step(ins: KirIns): Boolean {
        var changed = false
        when (ins) {
            is KirNew -> {
                val before = points[ins.result]
                replace(ins.result, "alloc:${ins.result}")
                changed = before != points[ins.result]
                heapWrite(ins.result, "", listOf("alloc:${ins.result}"))
            }

            is KirLoad -> {
                val before = points[ins.result]
                replace(ins.result, "opaque:${ins.result}")
                changed = before != points[ins.result]
            }

            is KirLambda -> {
                val before = points[ins.result]
                replace(ins.result, "lambda:${ins.function}")
                changed = before != points[ins.result]
            }

            is KirAssign -> {
                val tokens = points[ins.source].orEmpty()
                val size = points[ins.result]?.size ?: 0
                learnAll(ins.result, tokens)
                changed = (points[ins.result]?.size ?: 0) != size
            }

            is KirStore -> {
                val tokens = points[ins.value].orEmpty()
                val size = points[ins.target]?.size ?: 0
                learnAll(ins.target, tokens)
                changed = (points[ins.target]?.size ?: 0) != size
            }

            is KirPhi -> {
                for (source in ins.inputs.values) {
                    val size = points[ins.result]?.size ?: 0
                    learnAll(ins.result, points[source].orEmpty())
                    changed = changed || (points[ins.result]?.size ?: 0) != size
                }
            }

            is KirElvis -> {
                for (source in listOf(ins.value, ins.fallback)) {
                    val size = points[ins.result]?.size ?: 0
                    learnAll(ins.result, points[source].orEmpty())
                    changed = changed || (points[ins.result]?.size ?: 0) != size
                }
            }

            is KirCast -> {
                val size = points[ins.result]?.size ?: 0
                learnAll(ins.result, points[ins.value].orEmpty())
                changed = (points[ins.result]?.size ?: 0) != size
            }

            is KirTypeCheck -> {
                val before = points[ins.result]
                replace(ins.result, "opaque:${ins.result}")
                changed = changed || before != points[ins.result]
            }

            is KirStringConcat -> {
                val before = points[ins.result]
                replace(ins.result, "opaque:${ins.result}")
                changed = changed || before != points[ins.result]
            }

            is KirFieldGet -> {
                // A field read sees what every name of the object stored.
                val suffix = pathSuffix(ins.path)
                val tokens = sortedSetOf<String>()
                for (base in classOf(ins.receiver)) {
                    tokens.addAll(heapRead(base, suffix))
                }
                val size = points[ins.result]?.size ?: 0
                learnAll(ins.result, tokens)
                changed = (points[ins.result]?.size ?: 0) != size
            }

            is KirFieldSet -> {
                // The write fans out through the WRITER's alias class: a
                // write through one name of an object is a write through
                // all of them.
                val suffix = pathSuffix(ins.path)
                val tokens = points[ins.value].orEmpty()
                for (base in classOf(ins.receiver)) {
                    val before = heap["$base\u0000$suffix"]?.size ?: 0
                    heapWrite(base, suffix, tokens)
                    changed = changed || (heap["$base\u0000$suffix"]?.size ?: 0) != before
                }
            }

            is KirIndexGet -> {
                val tokens = sortedSetOf<String>()
                for (base in classOf(ins.receiver)) {
                    tokens.addAll(heapRead(base, "[]"))
                }
                val size = points[ins.result]?.size ?: 0
                learnAll(ins.result, tokens)
                changed = changed || (points[ins.result]?.size ?: 0) != size
            }

            is KirIndexSet -> {
                val tokens = points[ins.value].orEmpty()
                for (base in classOf(ins.receiver)) {
                    val before = heap["$base\u0000[]"]?.size ?: 0
                    heapWrite(base, "[]", tokens)
                    changed = changed || (heap["$base\u0000[]"]?.size ?: 0) != before
                }
            }

            is KirCall -> {
                val result = ins.result ?: return changed
                when (ins.callee.kind) {
                    CallKind.CONSTRUCTOR -> {
                        // The new object, plus the fields the constructor
                        // summary says it wrote from its arguments — the
                        // object-identity reading of a constructor: a
                        // function that writes the object's fields.
                        val before = points[result]
                        replace(result, "alloc:$result")
                        changed = changed || before != points[result]
                        heapWrite(result, "", listOf("alloc:$result"))
                        val ctor = summaryOf(ins)
                        if (ctor != null) {
                            for ((from, tos) in ctor.paramFieldWrites) {
                                for ((to, suffixes) in tos) {
                                    val toReg = constructorParamRegister(ins, to) ?: continue
                                    if (toReg != result) continue // only the new object's fields
                                    for (suffix in suffixes) {
                                        val fromReg = constructorParamRegister(ins, from) ?: continue
                                        val beforeHeap = heap["$result\u0000$suffix"]?.size ?: 0
                                        heapWrite(result, suffix, points[fromReg].orEmpty())
                                        changed = changed || (heap["$result\u0000$suffix"]?.size ?: 0) != beforeHeap
                                    }
                                }
                            }
                        }
                    }

                    else -> {
                        // A SAM CONVERSION is an identity on the function
                        // value: `Bridge { s -> .. }` and `Runnable { .. }`
                        // lower to a static call taking a `FunctionN` and
                        // returning the interface type, and the object it
                        // returns runs exactly the lambda it was handed. The
                        // token has to survive that hop or the later
                        // `b.cross(..)` is a virtual call on an interface
                        // with no workspace implementation — which is what
                        // it was, silently.
                        val samArg = samConversionArgument(ins)
                        if (samArg != null) {
                            val before = points[result]?.size ?: 0
                            learnAll(result, points[samArg].orEmpty().filter { it.startsWith("lambda:") })
                            changed = changed || (points[result]?.size ?: 0) != before
                        }
                        // A collection FACTORY puts its arguments in the
                        // collection: `listOf(f)[0]` has to read back the
                        // `f` it was built from, and there is no `indexset`
                        // to carry it because the elements never pass
                        // through one.
                        if (ins.callee.fqn in COLLECTION_FACTORIES) {
                            val tokens = sortedSetOf<String>()
                            for (arg in ins.args) tokens.addAll(points[arg].orEmpty())
                            val before = heap["$result []"]?.size ?: 0
                            heapWrite(result, "[]", tokens)
                            changed = changed || (heap["$result []"]?.size ?: 0) != before
                        }
                        // A modelled callee that returns a parameter's
                        // object makes the result an alias of that
                        // argument; everything else is a fresh opaque.
                        val summary = summaryOf(ins)
                        val returns = summary?.paramToReturn.orEmpty()
                        if (returns.isNotEmpty()) {
                            for (param in returns.sorted()) {
                                val argReg = callParamRegister(ins, summary!!, param) ?: continue
                                val size = points[result]?.size ?: 0
                                learnAll(result, points[argReg].orEmpty())
                                changed = changed || (points[result]?.size ?: 0) != size
                            }
                        } else {
                            val before = points[result]
                            learn(result, "opaque:$result")
                            changed = changed || before != points[result]
                        }
                    }
                }
            }

            is KirDynamicCall -> {
                ins.result?.let { result ->
                    val before = points[result]
                    learn(result, "opaque:$result")
                    changed = changed || before != points[result]
                }
            }

            else -> {}
        }
        return changed
    }

    /**
     * The argument of a SAM conversion at [ins], or null when this is not one.
     *
     * The lowering marks it, because RESOLUTION is the only thing that knows.
     * An earlier cut recognised the conversion from its KIR shape — a STATIC
     * call taking one `kotlin.jvm.functions.FunctionN` and returning the
     * callee's own name — and that shape is shared exactly by an ordinary
     * factory named after its return type:
     *
     *     fun Handler(block: (String) -> Unit): Handler = ...   // IGNORES block
     *
     * Kotlin's resolution prefers such a function over the interface's SAM
     * constructor, so the collision is reachable whenever one exists. Applying
     * the argument's body at every later call on the result then publishes a
     * flow through a lambda the program never runs.
     */
    private fun samConversionArgument(ins: KirCall): String? {
        if (!ins.callee.samConstructor) return null
        if (ins.callee.kind != CallKind.STATIC) return null
        return ins.args.singleOrNull()
    }

    /** The caller register bound to the callee's parameter [index] at [ins]. */
    private fun callParamRegister(ins: KirCall, summary: FunctionSummary, index: Int): String? {
        val receiverIndex = summary.function.params.indexOfFirst { it.receiver }
        return when {
            receiverIndex >= 0 && index == 0 -> ins.receiver
            receiverIndex >= 0 -> ins.args.getOrNull(index - 1)
            else -> ins.args.getOrNull(index)
        }
    }

    /**
     * A constructor call's "receiver" is the RESULT — the new object. The
     * synthesised `<init>` bodies declare their receiver like any member.
     */
    private fun constructorParamRegister(ins: KirCall, index: Int): String? =
        if (index == 0) ins.result else ins.args.getOrNull(index - 1)
}
