package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirParam
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.schema.CallGraphMode
import io.cdxgen.kosi.schema.DependencyDetail

/** Builders shared by the call-graph tests: functions whose facts are stated by hand. */
internal object GraphFixtures {

    fun module(vararg functions: KirFunction) = KirModule(functions.toList())

    fun function(
        canonicalName: String,
        enclosingClass: String? = null,
        visibility: String = "public",
        modifiers: Set<String> = emptySet(),
        overrides: List<String> = emptyList(),
        supertypes: List<String> = emptyList(),
        ownerFlags: Set<String> = emptySet(),
        annotations: List<String> = emptyList(),
        ownerAnnotations: List<String> = emptyList(),
        filePath: String = "src/main/kotlin/T.kt",
        body: List<KirIns>? = listOf(KirReturn(null)),
    ): KirFunction = KirFunction(
        canonicalName = canonicalName,
        jvmDescriptor = null,
        purl = "",
        file = filePath,
        line = 1,
        column = 1,
        params = if (enclosingClass == null) {
            emptyList()
        } else {
            listOf(KirParam("%0", "this", enclosingClass, receiver = true))
        },
        returnType = null,
        modifiers = modifiers,
        visibility = visibility,
        enclosingClass = enclosingClass,
        overrides = overrides,
        overriddenBy = emptyList(),
        annotations = annotations,
        syntheticCause = null,
        body = body?.let { io.cdxgen.kosi.kir.KirBody(listOf(KirBlock("b0", entry = true, instructions = it))) },
        supertypes = supertypes,
        ownerFlags = ownerFlags,
        ownerAnnotations = ownerAnnotations,
        ownerVisibility = enclosingClass?.let { "public" },
    )

    fun call(result: String, fqn: String, kind: CallKind, receiver: String? = null, line: Int = 1): KirIns =
        KirCall(result, KirCallee(fqn, null, kind), receiver, emptyList(), line)

    fun options(
        mode: CallGraphMode = CallGraphMode.AUTO,
        roots: List<String> = listOf("exported"),
        includeStdlib: Boolean = false,
        dependencyDetail: DependencyDetail = DependencyDetail.COLLAPSE,
    ) = GraphOptions(
        mode = mode,
        roots = GraphOptions.rootsOf(roots),
        includeStdlib = includeStdlib,
        dependencyDetail = dependencyDetail,
        maxPathsPerSymbol = 3,
        timeoutSeconds = 60,
    )

    fun build(module: KirModule, options: GraphOptions): CallGraphBuilder.Result =
        CallGraphBuilder.build(module, options, CallGraphBuilder.Attribution.NONE)

    fun edgeTargets(result: CallGraphBuilder.Result, sourceSuffix: String): List<Pair<String, String>> =
        result.callGraph.edges
            .filter { it.sourceId.endsWith(sourceSuffix) || nodeId(result, it.sourceId).endsWith(sourceSuffix) }
            .map { nodeId(result, it.targetId) to it.callType }

    fun nodeId(result: CallGraphBuilder.Result, id: String): String =
        result.callGraph.nodes.first { it.id == id }.canonicalName

    fun edgeByNames(
        result: CallGraphBuilder.Result,
        source: String,
        target: String,
    ): List<String> = result.callGraph.edges
        .filter { nodeId(result, it.sourceId).endsWith(source) && nodeId(result, it.targetId).endsWith(target) }
        .map { it.callType }
}
