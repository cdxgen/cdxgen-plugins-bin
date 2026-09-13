package io.cdxgen.kosi.models

import io.cdxgen.kosi.schema.JsonReader

/**
 * The crypto mapping table (P8) and its loader. One row per transform,
 * algorithm or curve; the collector matches against these and reports only
 * what a row carries. The population rule on the file header is enforced by
 * the P8 gate: a mapping without an exercising fixture fails the build.
 */
data class TransformMapping(
    val transform: String,
    val algorithm: String,
    val family: String,
    val primitive: String,
    val mode: String?,
    val padding: String?,
    val findings: List<String>,
)

data class AlgorithmMapping(
    val name: String,
    val family: String,
    val primitive: String,
    val keySizeBits: Int?,
    val findings: List<String>,
)

data class CurveMapping(
    val name: String,
    val keySizeBits: Int?,
)

data class CryptoMappings(
    val name: String,
    val transforms: List<TransformMapping>,
    val algorithms: List<AlgorithmMapping>,
    val curves: List<CurveMapping>,
    val modeVocabulary: List<String>,
    val paddingVocabulary: List<String>,
    val pbkdf2MinIterations: Int,
) {
    /** The shipped mapping population the P8 coverage gate divides by. */
    val mappingCount: Int get() = transforms.size + algorithms.size + curves.size
}

object CryptoMappingModels {

    const val CRYPTO_MAPPINGS_RESOURCE = "/models/crypto-mappings-v0.json"

    fun loadBuiltin(): CryptoMappings = loadResource(CRYPTO_MAPPINGS_RESOURCE)

    fun loadResource(resource: String): CryptoMappings {
        val text = CryptoMappingModels::class.java.getResourceAsStream(resource)
            ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
            ?: throw IllegalStateException("builtin crypto mappings missing: $resource")
        return parse(text)
    }

    fun parse(text: String): CryptoMappings {
        val root = JsonReader.parse(text).asObject()
        val transforms = root.arr("transforms")?.objects()?.map { t ->
            TransformMapping(
                transform = require(t.str("transform"), "transforms[].transform"),
                algorithm = require(t.str("algorithm"), "transforms[].algorithm"),
                family = require(t.str("family"), "transforms[].family"),
                primitive = require(t.str("primitive"), "transforms[].primitive"),
                mode = t.str("mode"),
                padding = t.str("padding"),
                findings = t.arr("findings")?.strings() ?: emptyList(),
            )
        } ?: emptyList()
        val algorithms = root.arr("algorithms")?.objects()?.map { a ->
            AlgorithmMapping(
                name = require(a.str("name"), "algorithms[].name"),
                family = require(a.str("family"), "algorithms[].family"),
                primitive = require(a.str("primitive"), "algorithms[].primitive"),
                keySizeBits = a.long("keySizeBits")?.toInt(),
                findings = a.arr("findings")?.strings() ?: emptyList(),
            )
        } ?: emptyList()
        val curves = root.arr("curves")?.objects()?.map { c ->
            CurveMapping(
                name = require(c.str("name"), "curves[].name"),
                keySizeBits = c.long("keySizeBits")?.toInt(),
            )
        } ?: emptyList()
        return CryptoMappings(
            name = root.str("name") ?: "crypto-mappings",
            transforms = transforms,
            algorithms = algorithms,
            curves = curves,
            modeVocabulary = root.arr("modeVocabulary")?.strings() ?: emptyList(),
            paddingVocabulary = root.arr("paddingVocabulary")?.strings() ?: emptyList(),
            pbkdf2MinIterations = root.long("pbkdf2MinIterations")?.toInt() ?: 210000,
        )
    }

    private fun require(value: String?, where: String): String =
        value ?: throw IllegalStateException("crypto mappings: missing $where")
}
