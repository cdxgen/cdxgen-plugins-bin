package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.KirFunction

/**
 * Dispatch resolution over the lowered facts (02-ARCHITECTURE.md §5). The
 * candidate model is built ONLY from what the KIR records — overrides named
 * by workspace functions, enclosing-class flags and supertypes — so a sealed
 * hierarchy narrows to its closed target set, an exact target (final /
 * private / object / companion / enum / top-level) collapses to one, and
 * everything else falls back to the open-hierarchy candidate set. Missing
 * facts narrow toward MORE candidates, never fewer: a function whose symbol
 * facts were unavailable has empty `overrides`, which can only ADD
 * candidates, and `unknown` visibility never reads as exact.
 */
internal class DispatchIndex(functions: List<KirFunction>) {

    /** Canonical name of an overridden symbol -> workspace functions overriding it. */
    private val overriders: Map<String, List<KirFunction>> =
        functions.flatMap { f -> f.overrides.map { it to f } }
            .groupBy({ it.first }, { it.second })
            .mapValues { (_, fs) -> fs.sortedBy { it.canonicalName } }

    /** Functions by canonical name (overloads share it; descriptors disambiguate). */
    val byCanonical: Map<String, List<KirFunction>> =
        functions.groupBy { it.canonicalName }.mapValues { (_, fs) -> fs.sortedBy { it.jvmDescriptor ?: "" } }

    /** Workspace class fqn -> transitive supertype closure (workspace edges only). */
    private val supertypeClosure: Map<String, Set<String>> = run {
        val direct = functions
            .filter { it.enclosingClass != null }
            .groupBy({ it.enclosingClass!! }) { it.supertypes }
            .mapValues { (_, lists) -> lists.flatten().toSortedSet() }
        val out = HashMap<String, Set<String>>()
        fun closureOf(klass: String, seen: MutableSet<String>): Set<String> {
            seen.add(klass)
            val result = out[klass]
            if (result != null) return result
            val acc = sortedSetOf<String>()
            for (superType in direct[klass].orEmpty()) {
                acc.add(superType)
                if (superType !in seen) acc.addAll(closureOf(superType, seen))
            }
            out[klass] = acc.toSet()
            return out[klass]!!
        }
        for (klass in direct.keys.sorted()) closureOf(klass, mutableSetOf())
        out
    }

    /** Workspace class fqn -> the flags any of its members recorded. */
    val classFlags: Map<String, Set<String>> =
        functions.filter { it.enclosingClass != null }
            .groupBy({ it.enclosingClass!! }) { it.ownerFlags }
            .mapValues { (_, sets) -> sets.fold(emptySet()) { acc, s -> acc + s } }

    val classes: Set<String> get() = supertypeClosure.keys

    /**
     * Workspace classes indexed by their last simple name, so a type FQN that
     * arrives package-qualified (constructor callees, receiver types from
     * resolution) can be canonicalized to the chain form the KIR uses for
     * `enclosingClass`. Without this, `pkg.Ticket.Advance` and the KIR's
     * `Ticket.Advance` are silently two different classes and RTA/VTA
     * comparisons fail by naming, not by fact.
     */
    private val classesBySimpleName: Map<String, List<String>> = run {
        val index = HashMap<String, MutableList<String>>()
        for (klass in supertypeClosure.keys) {
            index.getOrPut(klass.substringAfterLast('.')) { mutableListOf() }.add(klass)
        }
        index.mapValues { (_, list) -> list.sorted() }
    }

    /** The workspace class [typeFqn] names, in chain form; null when foreign. */
    fun canonicalize(typeFqn: String): String? {
        val segments = typeFqn.split('.')
        for (take in 1..segments.size) {
            val candidate = segments.takeLast(take).joinToString(".")
            for (klass in classesBySimpleName[candidate.substringAfterLast('.')].orEmpty()) {
                if (typeFqn == klass || typeFqn.endsWith(".$klass")) return klass
            }
        }
        return null
    }

    /**
     * Subtyping in mixed notations: [klass] is the KIR chain form,
     * [supertype] may be chain or package-qualified (resolved supertypes,
     * receiver types). A class is its own subtype.
     */
    fun isSubtypeOf(klass: String, supertype: String): Boolean {
        if (klass == supertype || klass.endsWith(".$supertype") || supertype.endsWith(".$klass")) return true
        return supertypeClosure[klass].orEmpty().any { it == supertype || it.endsWith(".$supertype") }
    }

    /**
     * True when the workspace function can be the target of a virtual
     * dispatch: it has a body (abstract/expect declarations are dispatch
     * LANDMARKS, not executions) and nothing about it forces exact dispatch.
     */
    fun isConcrete(f: KirFunction): Boolean = f.body != null

    /**
     * Exact dispatch: no runtime target selection can take place. Requires
     * POSITIVE evidence — final or private member, an owner that cannot have
     * overriding subclasses, or no enclosing class at all (top-level
     * functions are statically dispatched by definition).
     */
    fun isExact(f: KirFunction): Boolean {
        if (f.enclosingClass == null) return true
        if ("final" in f.modifiers) return true
        if (f.visibility == "private") return true
        val flags = f.ownerFlags
        if (flags.any { it == "final" || it == "object" || it == "companion" || it == "enum" }) return true
        return false
    }

    /** The dispatch site's hierarchy is closed (sealed class or enum owner). */
    fun isSealedSite(f: KirFunction): Boolean = f.ownerFlags.any { it == "sealed" || it == "enum" }

    /** The site dispatches through an interface (or fun interface). */
    fun isInterfaceSite(f: KirFunction): Boolean =
        f.ownerFlags.any { it == "interface" || it == "fun-interface" }

    /** Workspace functions whose canonical name is listed in [f].overrides. */
    fun overriding(f: KirFunction): List<KirFunction> = overriders[f.canonicalName].orEmpty()

    /**
     * Workspace functions overriding a canonical name that is NOT itself a
     * workspace declaration — a library interface method (`java.lang.Runnable.run`)
     * a local class implements. Dispatch on such a receiver lands in the
     * workspace implementations, and missing them would strand the call on an
     * external leaf node.
     */
    fun overridingCanonical(canonical: String): List<KirFunction> = overriders[canonical].orEmpty()

    /**
     * The declared callee as a workspace function, when it is one. Prefer the
     * descriptor match (overloads); a null descriptor falls back to the
     * first candidate in canonical order, deterministically.
     */
    fun workspaceCallee(fqn: String, descriptor: String?): KirFunction? {
        val candidates = byCanonical[fqn] ?: return null
        if (descriptor == null) return candidates.first()
        return candidates.firstOrNull { it.jvmDescriptor == descriptor } ?: candidates.first()
    }
}
