package io.cdxgen.kosi.schema

/**
 * The v1 kosi report (03-SCHEMA.md). `schemaVersion` is `kosi/1`; after the
 * first cdxgen release the shape is additive-only.
 */
data class ToolInfo(
    val name: String,
    val version: String,
    val description: String,
    val commit: String,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("commit", commit)
        w.str("description", description)
        w.str("name", name)
        w.str("version", version)
        w.endObject()
    }
}

/**
 * Runtime provenance. `kotlinVersion` is the built-with compiler version,
 * which is also the analysable ceiling; `languageVersionRange` is read from
 * the bundled compiler's LanguageVersion constants at runtime, never
 * hard-coded (08-VERSION-POLICY.md policy 3).
 */
data class RuntimeInfo(
    val kotlinVersion: String,
    val languageVersionRange: LanguageVersionRange,
    val jvmVersion: String,
    val host: String,
    val workingDirectory: String,
    val nativeImage: Boolean,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("host", host)
        w.str("jvmVersion", jvmVersion)
        languageVersionRange.writeJson(w, "languageVersionRange")
        w.bool("nativeImage", nativeImage)
        w.str("kotlinVersion", kotlinVersion)
        w.str("workingDirectory", workingDirectory)
        w.endObject()
    }
}

data class LanguageVersionRange(
    val first: String,
    val firstNonDeprecated: String,
    val latestStable: String,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("first", first)
        w.str("firstNonDeprecated", firstNonDeprecated)
        w.str("latestStable", latestStable)
        w.endObject()
    }
}

data class KosiReport(
    val schemaVersion: String,
    val tool: ToolInfo,
    val runtime: RuntimeInfo,
    val options: AnalyzeOptions,
    val modules: List<ModuleRef>,
    val packages: List<PackageEvidence>,
    val files: List<FileEvidence>,
    val imports: List<ImportUsage>,
    val declarations: List<Declaration>,
    val usages: List<LibraryUsage>,
    val securitySignals: List<SecuritySignal>,
    val crypto: CryptoEvidence,
    val callGraph: CallGraph?,
    val dataFlow: DataFlowEvidence?,
    val apiEndpoints: List<ApiEndpoint>,
    val services: List<ServiceRef>,
    val urls: List<UrlEvidence>,
    val diagnostics: List<Diagnostic>,
    val stats: Stats,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginArray("apiEndpoints")
        for (e in apiEndpoints.sortedWith(ApiEndpoint.COMPARATOR)) e.writeJson(w)
        w.endArray()
        // callGraph/dataFlow stay null until their modes produce them; the
        // keys are still emitted so the envelope is stable for consumers.
        if (callGraph != null) callGraph.writeJson(w, "callGraph") else w.nul("callGraph")
        crypto.writeJson(w, "crypto")
        if (dataFlow != null) dataFlow.writeJson(w, "dataFlow") else w.nul("dataFlow")
        w.beginArray("declarations")
        for (d in declarations.sortedWith(Declaration.COMPARATOR)) d.writeJson(w)
        w.endArray()
        w.beginArray("diagnostics")
        for (d in diagnostics.sortedWith(Diagnostic.COMPARATOR)) d.writeJson(w)
        w.endArray()
        w.beginArray("files")
        for (f in files.sortedWith(FileEvidence.COMPARATOR)) f.writeJson(w)
        w.endArray()
        w.beginArray("imports")
        for (i in imports.sortedWith(ImportUsage.COMPARATOR)) i.writeJson(w)
        w.endArray()
        w.beginArray("modules")
        for (m in modules.sortedWith(ModuleRef.COMPARATOR)) m.writeJson(w)
        w.endArray()
        options.writeJson(w, "options")
        w.beginArray("packages")
        for (p in packages.sortedWith(PackageEvidence.COMPARATOR)) p.writeJson(w)
        w.endArray()
        w.str("schemaVersion", schemaVersion)
        w.beginArray("securitySignals")
        for (s in securitySignals.sortedWith(SecuritySignal.COMPARATOR)) s.writeJson(w)
        w.endArray()
        w.beginArray("services")
        for (s in services.sortedWith(ServiceRef.COMPARATOR)) s.writeJson(w)
        w.endArray()
        stats.writeJson(w, "stats")
        tool.writeJson(w, "tool")
        w.beginArray("urls")
        for (u in urls.sortedWith(UrlEvidence.COMPARATOR)) u.writeJson(w)
        w.endArray()
        w.beginArray("usages")
        for (u in usages.sortedWith(LibraryUsage.COMPARATOR)) u.writeJson(w)
        w.endArray()
        w.endObject()
    }

    fun toJson(pretty: Boolean): String {
        val w = JsonWriter(pretty)
        writeJson(w)
        return w.render()
    }

    companion object {
        const val SCHEMA_VERSION = "kosi/1"
    }
}
