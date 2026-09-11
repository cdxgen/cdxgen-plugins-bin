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
            configReaders = configReaders,
        )
    }

    private fun require(value: String?, where: String): String =
        value ?: throw IllegalStateException("endpoints pack: missing $where")
}
