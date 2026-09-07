package io.cdxgen.kosi.schema

/**
 * Crypto/CBOM evidence (CycloneDX-1.7-shaped fields, 02-ARCHITECTURE.md §8).
 * Material records carry the name only, never the value.
 */
data class CryptoAsset(
    val name: String,
    val algorithmFamily: String?,
    val primitive: String?,
    val mode: String?,
    val padding: String?,
    val keySizeBits: Int?,
    val curve: String?,
    val position: Position?,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("algorithm", name)
        if (algorithmFamily != null) w.str("algorithmFamily", algorithmFamily) else w.nul("algorithmFamily")
        if (curve != null) w.str("curve", curve) else w.nul("curve")
        if (keySizeBits != null) w.num("keySizeBits", keySizeBits) else w.nul("keySizeBits")
        if (mode != null) w.str("mode", mode) else w.nul("mode")
        if (padding != null) w.str("padding", padding) else w.nul("padding")
        position?.writeJson(w, "position")
        if (primitive != null) w.str("primitive", primitive) else w.nul("primitive")
        w.endObject()
    }
}

data class CryptoOperation(
    val kind: String,
    val asset: String,
    val function: String,
    val modulePath: String,
    val filePath: String,
    val position: Position,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("asset", asset)
        w.str("filePath", filePath)
        w.str("function", function)
        w.str("kind", kind)
        w.str("modulePath", modulePath)
        position.writeJson(w, "position")
        w.endObject()
    }
}

data class CryptoMaterial(
    val name: String,
    val kind: String,
    val filePath: String,
    val position: Position,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("filePath", filePath)
        w.str("kind", kind)
        w.str("name", name)
        position.writeJson(w, "position")
        w.endObject()
    }
}

data class CryptoFinding(
    val code: String,
    val severity: String,
    val message: String,
    val asset: String?,
    val filePath: String,
    val position: Position,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("asset", asset)
        w.str("code", code)
        w.str("filePath", filePath)
        w.str("message", message)
        position.writeJson(w, "position")
        w.str("severity", severity)
        w.endObject()
    }
}

data class CryptoEvidence(
    val libraries: List<String>,
    val assets: List<CryptoAsset>,
    val operations: List<CryptoOperation>,
    val materials: List<CryptoMaterial>,
    val protocols: List<String>,
    val findings: List<CryptoFinding>,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginArray("assets")
        for (a in assets.sortedWith(compareBy({ it.name }, { it.position?.filename ?: "" }, { it.position?.line ?: 0 }))) a.writeJson(w)
        w.endArray()
        w.beginArray("findings")
        for (f in findings.sortedWith(compareBy({ it.code }, { it.filePath }, { it.position.line }))) f.writeJson(w)
        w.endArray()
        w.beginArray("libraries")
        for (l in libraries.sorted()) w.str(l)
        w.endArray()
        w.beginArray("materials")
        for (m in materials.sortedWith(compareBy({ it.name }, { it.filePath }, { it.position.line }))) m.writeJson(w)
        w.endArray()
        w.beginArray("operations")
        for (o in operations.sortedWith(compareBy({ it.function }, { it.filePath }, { it.position.line }))) o.writeJson(w)
        w.endArray()
        w.beginArray("protocols")
        for (p in protocols.sorted()) w.str(p)
        w.endArray()
        w.endObject()
    }
}
