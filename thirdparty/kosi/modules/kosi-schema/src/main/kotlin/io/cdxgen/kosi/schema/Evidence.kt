package io.cdxgen.kosi.schema

/** ModuleRef — a Gradle/Maven project or a Kotlin source set (03-SCHEMA.md). */
data class ModuleRef(
    val name: String,
    val modulePath: String,
    val platform: String,
    val workspaceMember: String,
    val purl: String,
    val sourceRoots: List<String>,
    val declaredLanguageVersion: String?,
    val declaredApiVersion: String?,
    val effectiveLanguageVersion: String?,
    val jvmTarget: String?,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("declaredApiVersion", declaredApiVersion)
        w.str("declaredLanguageVersion", declaredLanguageVersion)
        w.str("effectiveLanguageVersion", effectiveLanguageVersion)
        w.str("jvmTarget", jvmTarget)
        w.str("modulePath", modulePath)
        w.str("name", name)
        w.str("platform", platform)
        w.beginArray("sourceRoots")
        for (root in sourceRoots.sorted()) w.str(root)
        w.endArray()
        w.str("purl", purl)
        w.str("workspaceMember", workspaceMember)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<ModuleRef>({ it.modulePath }, { it.name })
    }
}

/** PackageEvidence — per module rollup + file list. */
data class PackageEvidence(
    val purl: String,
    val name: String,
    val modulePath: String,
    val files: List<String>,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginArray("files")
        for (f in files.sorted()) w.str(f)
        w.endArray()
        w.str("modulePath", modulePath)
        w.str("name", name)
        w.str("purl", purl)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<PackageEvidence>({ it.purl }, { it.modulePath })
    }
}

/** FileEvidence. Per-file collections are never nested here (schema rule 3). */
data class FileEvidence(
    val path: String,
    val modulePath: String,
    val purl: String,
    val language: String,
    val generated: Boolean,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.bool("generated", generated)
        w.str("language", language)
        w.str("modulePath", modulePath)
        w.str("path", path)
        w.str("purl", purl)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<FileEvidence> { it.path }
        const val LANGUAGE_KOTLIN = "kotlin"
        const val LANGUAGE_JAVA = "java"
    }
}

/** ImportUsage — canonical imports. */
data class ImportUsage(
    val name: String,
    val alias: String?,
    val star: Boolean,
    val purl: String?,
    val filePath: String,
    val position: Position,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("alias", alias)
        w.str("filePath", filePath)
        w.str("name", name)
        w.str("purl", purl)
        position.writeJson(w, "position")
        w.bool("star", star)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<ImportUsage>({ it.name }, { it.filePath }, { it.position.line }, { it.position.column })
    }
}

/** Annotation evidence attached to a declaration. */
data class AnnotationEvidence(
    val name: String,
    val value: String?,
    val position: Position,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("name", name)
        if (value != null) w.str("value", value)
        position.writeJson(w, "position")
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<AnnotationEvidence>({ it.name }, { it.position.line })
    }
}

/**
 * Declaration — canonical (03-SCHEMA.md). `qualifiedName` is rooted at the
 * module + source set so commonMain/androidMain `actual` bodies are
 * distinguishable; `canonicalName` is generic-free and hash-free.
 */
data class Declaration(
    val id: String,
    val name: String,
    val qualifiedName: String,
    val canonicalName: String,
    val jvmOwner: String?,
    val jvmDescriptor: String?,
    val kind: String,
    val modulePath: String,
    val purl: String,
    val filePath: String,
    val signature: String?,
    val receiverType: String?,
    val extensionReceiverType: String?,
    val visibility: String,
    val modifiers: List<String>,
    val annotations: List<AnnotationEvidence>,
    val overrides: List<String>,
    val position: Position,
    val generated: Boolean?,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginArray("annotations")
        for (a in annotations.sortedWith(AnnotationEvidence.COMPARATOR)) a.writeJson(w)
        w.endArray()
        w.str("canonicalName", canonicalName)
        w.str("extensionReceiverType", extensionReceiverType)
        w.str("filePath", filePath)
        if (generated != null) w.bool("generated", generated) else w.nul("generated")
        w.str("id", id)
        w.str("jvmDescriptor", jvmDescriptor)
        w.str("jvmOwner", jvmOwner)
        w.str("kind", kind)
        w.beginArray("modifiers")
        for (m in modifiers.sorted()) w.str(m)
        w.endArray()
        w.str("modulePath", modulePath)
        w.str("name", name)
        w.beginArray("overrides")
        for (o in overrides.sorted()) w.str(o)
        w.endArray()
        w.str("purl", purl)
        position.writeJson(w, "position")
        w.str("qualifiedName", qualifiedName)
        w.str("receiverType", receiverType)
        w.str("signature", signature)
        w.str("visibility", visibility)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<Declaration>({ it.filePath }, { it.position.line }, { it.position.column }, { it.name })
    }
}
