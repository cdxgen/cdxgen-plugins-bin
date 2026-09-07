package io.cdxgen.kosi.schema

/** ApiEndpoint — inbound HTTP/gRPC/GraphQL/Android entry points. */
data class ApiEndpoint(
    val id: String,
    val framework: String,
    val httpMethods: List<String>,
    val pathTemplate: String,
    val pathParameters: List<String>,
    val queryParameters: List<String>,
    val consumes: List<String>,
    val produces: List<String>,
    val authentication: List<String>,
    val handlerSymbol: String,
    val handlerCanonicalName: String,
    val modulePath: String,
    val purl: String,
    val position: Position?,
    val exported: Boolean?,
    val permissions: List<String>?,
    val deepLinkHosts: List<String>?,
    val reachableSources: List<String>,
    val sliceIds: List<String>,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.beginArray("authentication")
        for (a in authentication.sorted()) w.str(a)
        w.endArray()
        w.beginArray("consumes")
        for (c in consumes.sorted()) w.str(c)
        w.endArray()
        w.str("handlerCanonicalName", handlerCanonicalName)
        w.str("handlerSymbol", handlerSymbol)
        w.beginArray("deepLinkHosts")
        for (d in (deepLinkHosts ?: emptyList()).sorted()) w.str(d)
        w.endArray()
        if (exported != null) w.bool("exported", exported) else w.nul("exported")
        w.str("framework", framework)
        w.beginArray("httpMethod")
        for (m in httpMethods.sorted()) w.str(m)
        w.endArray()
        w.str("id", id)
        w.str("modulePath", modulePath)
        w.beginArray("pathParameters")
        for (p in pathParameters) w.str(p)
        w.endArray()
        w.str("pathTemplate", pathTemplate)
        w.str("purl", purl)
        position?.writeJson(w, "position")
        w.beginArray("permissions")
        for (p in (permissions ?: emptyList()).sorted()) w.str(p)
        w.endArray()
        w.beginArray("produces")
        for (p in produces.sorted()) w.str(p)
        w.endArray()
        w.beginArray("queryParameters")
        for (q in queryParameters) w.str(q)
        w.endArray()
        w.beginArray("reachableSources")
        for (r in reachableSources.sorted()) w.str(r)
        w.endArray()
        w.beginArray("sliceIds")
        for (s in sliceIds.sorted()) w.str(s)
        w.endArray()
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<ApiEndpoint>({ it.pathTemplate }, { it.handlerSymbol }, { it.id })
    }
}

/** ServiceRef — outbound dependencies, cdxgen services[]-shaped. */
data class ServiceRef(
    val id: String,
    val name: String,
    val endpoints: List<String>,
    val authenticated: Boolean?,
    val xTrustBoundary: Boolean?,
    val protocol: String,
    val clientLibrary: String,
    val clientPurl: String,
    val resolution: String,
    val position: Position?,
    val sliceIds: List<String>,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        if (authenticated != null) w.bool("authenticated", authenticated) else w.nul("authenticated")
        w.str("clientLibrary", clientLibrary)
        w.str("clientPurl", clientPurl)
        w.beginArray("endpoints")
        for (e in endpoints.sorted()) w.str(e)
        w.endArray()
        w.str("id", id)
        w.str("name", name)
        w.str("protocol", protocol)
        position?.writeJson(w, "position")
        w.str("resolution", resolution)
        w.beginArray("sliceIds")
        for (s in sliceIds.sorted()) w.str(s)
        w.endArray()
        if (xTrustBoundary != null) w.bool("x-trust-boundary", xTrustBoundary) else w.nul("x-trust-boundary")
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<ServiceRef>({ it.name }, { it.id })
    }
}

/** UrlEvidence — resolved and unresolved URL/host/JDBC strings. */
data class UrlEvidence(
    val url: String,
    val raw: String,
    val resolution: String,
    val kind: String,
    val enclosingSymbol: String,
    val modulePath: String,
    val filePath: String,
    val position: Position,
) {
    fun writeJson(w: JsonWriter, key: String? = null) {
        w.beginObject(key)
        w.str("enclosingSymbol", enclosingSymbol)
        w.str("filePath", filePath)
        w.str("kind", kind)
        w.str("modulePath", modulePath)
        w.str("raw", raw)
        w.str("resolution", resolution)
        position.writeJson(w, "position")
        w.str("url", url)
        w.endObject()
    }

    companion object {
        val COMPARATOR = compareBy<UrlEvidence>({ it.url }, { it.filePath }, { it.position.line })
        const val RESOLUTION_LITERAL = "literal"
        const val RESOLUTION_FOLDED = "folded"
        const val RESOLUTION_CONFIG = "config"
        const val RESOLUTION_ENV = "env"
        const val RESOLUTION_UNRESOLVED = "unresolved"
    }
}
