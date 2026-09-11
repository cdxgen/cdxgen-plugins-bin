package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirValueFolder
import io.cdxgen.kosi.models.EndpointsPack
import io.cdxgen.kosi.schema.ApiEndpoint
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.ServiceRef
import io.cdxgen.kosi.schema.UrlEvidence
import java.nio.file.Path

/**
 * The P7 facade: inbound endpoints, outbound services and URL evidence from
 * one deterministic pass over the lowered module, the resolved declaration
 * annotations, the config table and the Android manifests. Ids are assigned
 * after sorting — two runs on one input produce byte-identical arrays.
 */
object Endpoints {

    data class Result(
        val apiEndpoints: List<ApiEndpoint>,
        val services: List<ServiceRef>,
        val urls: List<UrlEvidence>,
        /** Endpoint handlers whose parameter is a taint source when the run asks for it. */
        val sourceHandlers: Map<String, String>,
        /** Config-derived values: total and how many resolved (the gate's two counts). */
        val configValuesTotal: Int,
        val configValuesResolved: Int,
    )

    data class Attribution(
        /** Absolute file path -> (relativePath, modulePath). */
        val byAbsoluteFilePath: Map<String, Pair<String, String>>,
        val purlByModulePath: Map<String, String>,
    )

    fun analyze(
        module: KirModule,
        root: Path,
        sourceTexts: Map<String, String>,
        annotationValues: Map<String, List<EndpointDetector.DeclAnnotation>>,
        attribution: Attribution,
        includeManifests: Boolean,
    ): Result {
        val pack: EndpointsPack = io.cdxgen.kosi.models.EndpointModels.loadBuiltin()
        val configTable = ConfigResolver.load(root)
        val configValues = configTable.keys().mapNotNull { key -> configTable[key]?.let { key to it.value!! } }.toMap()
        val folder = KirValueFolder(
            module = module,
            constValues = ConstTable.fromSources(sourceTexts),
            configReaders = pack.configReaders.map { it.pattern to it.argument },
            configTable = configValues,
        )
        val lambdaLinks = buildLambdaLinks(module)

        // ---- inbound endpoints -----------------------------------------------
        val candidates = EndpointDetector.detect(
            EndpointDetector.Input(
                module = module,
                annotationValues = annotationValues,
                folder = folder,
                lambdaLinks = lambdaLinks,
            ),
            pack,
        )
        val manifests = if (includeManifests) AndroidManifestParser.parse(root) else emptyList()
        val manifestCandidates = manifestEndpoints(module, manifests, pack)

        val all = (candidates + manifestCandidates)
            .sortedWith(compareBy({ it.framework }, { it.pathTemplate }, { it.handlerSymbol }))

        val apiEndpoints = all.mapIndexed { index, candidate ->
            val at = relPosition(candidate.position, attribution)
            val modulePath = candidate.position?.let { attribution.byAbsoluteFilePath[it.filename]?.second } ?: ""
            ApiEndpoint(
                id = "ep-" + (index + 1).toString().padStart(6, '0'),
                framework = candidate.framework,
                httpMethods = candidate.httpMethods,
                pathTemplate = candidate.pathTemplate,
                pathParameters = candidate.pathParameters,
                queryParameters = emptyList(),
                consumes = emptyList(),
                produces = emptyList(),
                authentication = emptyList(),
                handlerSymbol = candidate.handlerSymbol,
                handlerCanonicalName = candidate.handlerSymbol,
                modulePath = modulePath,
                purl = attribution.purlByModulePath[modulePath] ?: "",
                position = at,
                exported = candidate.exported,
                permissions = candidate.permissions,
                deepLinkHosts = candidate.deepLinkHosts,
                reachableSources = emptyList(),
                sliceIds = emptyList(),
                foundBy = candidate.foundBy,
            )
        }

        // ---- outbound services and URLs ---------------------------------------
        val outbounds = OutboundDetector.detect(module, folder, pack)
        val services = outbounds.mapIndexed { index, outbound ->
            val modulePath = attribution.byAbsoluteFilePath[outbound.position.filename]?.second ?: ""
            ServiceRef(
                id = "svc-" + (index + 1).toString().padStart(6, '0'),
                name = serviceName(outbound),
                endpoints = listOfNotNull(outbound.endpoint ?: outbound.raw),
                authenticated = null,
                xTrustBoundary = null,
                protocol = outbound.protocol,
                clientLibrary = outbound.clientLibrary,
                clientPurl = attribution.byAbsoluteFilePath[outbound.position.filename]?.second
                    ?.let { attribution.purlByModulePath[it] } ?: "",
                resolution = outbound.resolution,
                position = relPosition(outbound.position, attribution) ?: outbound.position,
                sliceIds = emptyList(),
            )
        }
        val urls = outbounds.map { outbound ->
            val filePair = attribution.byAbsoluteFilePath[outbound.position.filename]
            UrlEvidence(
                url = outbound.endpoint ?: outbound.raw,
                raw = outbound.raw,
                resolution = outbound.resolution,
                kind = outbound.protocol,
                enclosingSymbol = outbound.enclosingSymbol,
                modulePath = filePair?.second ?: "",
                filePath = filePair?.first ?: outbound.position.filename,
                position = relPosition(outbound.position, attribution) ?: outbound.position,
            )
        }

        // ---- the config-resolution gate's two counts ---------------------------
        // The denominator is the values whose source is CONFIG-DERIVED (a
        // `${key}` template or a config-reader call); a literal is neither.
        val configDerived = outbounds.filter { it.resolution == "config" || it.raw.contains("\${") }
        val configResolved = configDerived.filter { it.resolution == "config" }

        return Result(
            apiEndpoints = apiEndpoints,
            services = services,
            urls = urls,
            sourceHandlers = apiEndpoints
                .filter { it.handlerSymbol.isNotEmpty() }
                .associate { it.handlerCanonicalName to SOURCE_CATEGORY },
            configValuesTotal = configDerived.size,
            configValuesResolved = configResolved.size,
        )
    }

    /** The category an endpoint handler's parameters carry when the run asks for endpoint sources. */
    const val SOURCE_CATEGORY = "untrusted-input"

    private fun relPosition(position: Position?, attribution: Attribution): Position? {
        position ?: return null
        val rel = attribution.byAbsoluteFilePath[position.filename]?.first ?: position.filename
        return Position(rel, position.line, position.column)
    }

    private fun serviceName(outbound: OutboundDetector.Outbound): String {
        val value = outbound.endpoint ?: outbound.raw
        return when (outbound.protocol) {
            "jdbc" -> value.substringBefore(';').substringBefore('?')
            "http", "https" -> value.substringAfter("://").substringBefore('/').ifEmpty { value }
            else -> value
        }.ifEmpty { outbound.clientLibrary }
    }

    /**
     * The component's lifecycle entry, resolved against the workspace: an
     * activity publishes onCreate, a service onStartCommand, a receiver
     * onReceive, a provider query. A component whose class carries no such
     * method in the workspace publishes an EMPTY handler symbol — the
     * unresolved half of the resolved-handler denominator.
     */
    private fun manifestEndpoints(
        module: KirModule,
        manifests: List<AndroidManifestParser.Manifest>,
        pack: EndpointsPack,
    ): List<EndpointDetector.Candidate> {
        val android = pack.frameworks.firstOrNull { it.kind == "manifest" } ?: return emptyList()
        val components = android.manifestComponents
        val out = mutableListOf<EndpointDetector.Candidate>()
        for (manifest in manifests) {
            for (component in manifest.components) {
                if (component.kind !in components && component.kind != "activity-alias") continue
                val lifecycle = lifecycleHandler(component.kind, module, component.className)
                out.add(
                    EndpointDetector.Candidate(
                        framework = android.id,
                        httpMethods = emptyList(),
                        pathTemplate = component.actions.firstOrNull()
                            ?: component.className.substringAfterLast('.'),
                        pathParameters = emptyList(),
                        handlerSymbol = lifecycle,
                        foundBy = "manifest",
                        position = Position(manifest.file, 1, 1),
                        exported = component.exported,
                        permissions = component.permissions.ifEmpty { null },
                        deepLinkHosts = component.deepLinkHosts.ifEmpty { null },
                    ),
                )
            }
        }
        return out
    }

    private fun lifecycleHandler(kind: String, module: KirModule, className: String): String {
        val methodNames = when (kind) {
            "activity", "activity-alias" -> listOf("onCreate")
            "service" -> listOf("onStartCommand", "onCreate")
            "receiver" -> listOf("onReceive")
            "provider" -> listOf("query")
            else -> return ""
        }
        val simple = className.substringAfterLast('.')
        for (methodName in methodNames) {
            val found = module.functions.firstOrNull { fn ->
                fn.enclosingClass != null && fn.canonicalName.endsWith(".$methodName") && (
                    fn.enclosingClass == simple ||
                        fn.canonicalName.startsWith("$className.") ||
                        className.endsWith("." + fn.enclosingClass)
                    )
            } ?: continue
            return found.canonicalName
        }
        return ""
    }

    private fun buildLambdaLinks(module: KirModule): Map<String, EndpointDetector.LambdaLink> {
        val links = HashMap<String, EndpointDetector.LambdaLink>()
        for (fn in module.functions) {
            for (block in fn.body?.blocks.orEmpty()) {
                for (ins in block.instructions) {
                    val lambda = ins as? KirLambda ?: continue
                    val creation = block.instructions.firstOrNull { candidate ->
                        candidate is KirCall && lambda.result in candidate.args
                    } as? KirCall ?: continue
                    links[lambda.function] = EndpointDetector.LambdaLink(fn.canonicalName, creation)
                }
            }
        }
        return links
    }
}

/** Workspace `const val` name -> value, only for names with a UNIQUE value. */
object ConstTable {
    private val PATTERN = Regex(
        """(?:\bconst\s+val\s+|\bpublic\s+static\s+final\s+String\s+|\bstatic\s+final\s+String\s+)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"""",
    )

    fun fromSources(sourceTexts: Map<String, String>): Map<String, String> {
        val byName = HashMap<String, MutableSet<String>>()
        for (text in sourceTexts.values) {
            for (match in PATTERN.findAll(text)) {
                byName.getOrPut(match.groupValues[1]) { mutableSetOf() }.add(match.groupValues[2])
            }
        }
        return byName.filterValues { it.size == 1 }.mapValues { (_, vs) -> vs.first() }
    }
}
