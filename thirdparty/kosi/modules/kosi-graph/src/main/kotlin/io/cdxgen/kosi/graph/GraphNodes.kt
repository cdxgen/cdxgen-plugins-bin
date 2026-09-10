package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.KirFunction

/**
 * The graph's node store. Local nodes come from the lowered module; external
 * nodes (stdlib and dependency callees, class nodes for constructors) are
 * created on demand as the walk resolves calls. Ids are assigned once, after
 * a canonical sort over the whole node set, so they are stable across runs.
 *
 * Identity: `canonicalName` plus the JVM descriptor when one is known
 * (overloads). An external callee with no descriptor merges its overloads
 * into one node — call evidence, not declaration evidence — which the
 * `null` jvmDescriptor on the emitted node states plainly.
 */
internal class GraphNodes(private val attribution: CallGraphBuilder.Attribution) {

    class GNode internal constructor(
        val key: String,
        val canonicalName: String,
        val name: String,
        val jvmDescriptor: String?,
        val kind: String,
        val local: Boolean,
        val synthetic: Boolean,
        val suspend: Boolean,
        val visibility: String,
        val filePath: String,
        val relativePath: String,
        val line: Int,
        val column: Int,
        val modulePath: String,
        val purl: String,
        val ownerless: Boolean,
        val enclosingClass: String?,
        val supertypes: List<String>,
        val annotations: List<String>,
        val ownerAnnotations: List<String>,
        val ownerVisibility: String?,
        val positionKnown: Boolean,
        val function: KirFunction?,
    )

    private val byKey = LinkedHashMap<String, GNode>()
    private val localByKey = HashMap<String, String>()

    fun localNode(f: KirFunction): String {
        val key = localKey(f)
        if (localByKey.containsKey(key)) return localByKey.getValue(key)
        val attr = attribution.byAbsoluteFilePath[f.file]
        val relativePath = attr?.first ?: f.file
        val modulePath = attr?.second ?: ""
        val node = GNode(
            key = key,
            canonicalName = f.canonicalName,
            name = f.canonicalName.substringAfterLast('.'),
            jvmDescriptor = f.jvmDescriptor,
            kind = kindOf(f),
            local = true,
            synthetic = f.syntheticCause != null,
            suspend = "suspend" in f.modifiers,
            visibility = f.visibility.ifBlank { "unknown" },
            filePath = f.file,
            relativePath = relativePath,
            line = f.line,
            column = f.column,
            modulePath = modulePath,
            purl = attribution.purlByModulePath[modulePath] ?: f.purl,
            ownerless = f.enclosingClass == null,
            enclosingClass = f.enclosingClass,
            supertypes = f.supertypes,
            annotations = f.annotations,
            ownerAnnotations = f.ownerAnnotations,
            ownerVisibility = f.ownerVisibility,
            positionKnown = true,
            function = f,
        )
        byKey[key] = node
        localByKey[key] = key
        return key
    }

    fun externalNode(fqn: String, descriptor: String?, kind: String? = null): String {
        val key = externalKey(fqn, descriptor)
        if (byKey.containsKey(key)) return key
        val node = GNode(
            key = key,
            canonicalName = fqn,
            name = fqn.substringAfterLast('.'),
            jvmDescriptor = descriptor,
            kind = kind ?: externalKindOf(fqn),
            local = false,
            synthetic = false,
            suspend = false,
            visibility = "unknown",
            filePath = "",
            relativePath = "",
            line = 0,
            column = 0,
            modulePath = "",
            purl = "",
            ownerless = false,
            enclosingClass = null,
            supertypes = emptyList(),
            annotations = emptyList(),
            ownerAnnotations = emptyList(),
            ownerVisibility = null,
            positionKnown = false,
            function = null,
        )
        byKey[key] = node
        return key
    }

    fun keyOf(f: KirFunction): String? = localByKey[localKey(f)]

    fun node(key: String): GNode? = byKey[key]

    fun functionOf(key: String): KirFunction? = byKey[key]?.function

    fun list(): List<GNode> = byKey.values.toList()

    fun keysSorted(): List<String> = byKey.keys.toSortedSet().toList()

    private fun localKey(f: KirFunction): String =
        f.canonicalName + "\u0000" + (f.jvmDescriptor ?: paramSignature(f)) + "\u0000L"

    private fun externalKey(fqn: String, descriptor: String?): String =
        fqn + "\u0000" + (descriptor ?: "") + "\u0000E"

    /** Overloads without a descriptor get a parameter-text signature. */
    private fun paramSignature(f: KirFunction): String =
        f.params.joinToString(",") { it.type ?: "?" }

    /**
     * Node kind from what the lowering produced: accessors keep their
     * `<get-`/`<set-` names, `<init>` is a constructor, anything inside a
     * class is a method, everything else a (top-level) function.
     */
    private fun kindOf(f: KirFunction): String = when {
        f.canonicalName.endsWith(".<init>") || f.canonicalName == "<init>" -> "constructor"
        "<get-" in f.canonicalName -> "getter"
        "<set-" in f.canonicalName -> "setter"
        f.enclosingClass != null -> "method"
        else -> "function"
    }

    /**
     * External node kind, decided by the shape of the canonical name: a
     * constructor node only ever receives constructor edges (the caller says
     * so explicitly), otherwise an upper-case second-to-last segment means a
     * class-qualified method and its absence a top-level function.
     */
    private fun externalKindOf(fqn: String): String {
        val segments = fqn.split('.')
        return if (segments.size >= 2 && segments[segments.size - 2].firstOrNull()?.isUpperCase() == true) {
            "method"
        } else {
            "function"
        }
    }
}
