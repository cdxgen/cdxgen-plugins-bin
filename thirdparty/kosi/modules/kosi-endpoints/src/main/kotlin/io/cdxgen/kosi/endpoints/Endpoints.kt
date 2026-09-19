package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.uses
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
        /**
         * Resolved dependency coordinates (`group:artifact:version`). Some
         * routes exist because a dependency is PRESENT and for no other
         * reason — Actuator's tree, springdoc's `/v3/api-docs` — with no
         * handler anywhere in the application's source.
         */
        dependencyCoordinates: Set<String> = emptySet(),
        /**
         * The pack to detect with. Production always loads the builtin; the
         * P19 liveness gate re-runs THIS analysis once per removed pack
         * entry over the SAME captured inputs, so an entry no fixture's
         * report depends on is a mechanical fact, not an anecdote.
         */
        pack: EndpointsPack = io.cdxgen.kosi.models.EndpointModels.loadBuiltin(),
        /**
         * P20 §0: when non-null, every value the consumers ask the folder
         * for is counted here with its failure reason — the depth report's
         * value-resolution table. Production passes null and pays nothing.
         */
        foldStats: KirValueFolder.FoldStats? = null,
        /**
         * P20 §2: `false` restores the pre-P20 block-local scan — the depth
         * report's baseline column measures both ways over one capture.
         */
        crossBlock: Boolean = true,
    ): Result {
        val configTable = ConfigResolver.load(root)
        // `value` is null for a key the config files DISAGREE about (P23 §1,
        // R140): known key, unprovable value, so it is absent from the fold
        // table and the site publishes `unresolved` with the key named. The
        // `!!` that stood here was safe only while nothing could ever be
        // ambiguous — the same read one layer up (`configValuesForCrypto`)
        // has always used `mapNotNull` on the value, and two readers of one
        // nullable field disagreeing about whether it can be null is the
        // shape P22's rule is about.
        val configValues = configTable.keys()
            .mapNotNull { key -> configTable[key]?.value?.let { key to it } }
            .toMap()
        val folder = KirValueFolder(
            module = module,
            constValues = ConstTable.fromSources(sourceTexts),
            configReaders = pack.configReaders.map { it.pattern to it.argument },
            configTable = configValues,
            statsSink = foldStats,
            crossBlock = crossBlock,
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
        val webXmlCandidates = webXmlEndpoints(module, WebXmlParser.parse(root), pack, root)
        val implicitCandidates = implicitEndpoints(module, pack, dependencyCoordinates, configTable)

        // The DEPLOYMENT base path. A handler's annotation or DSL call names
        // a path relative to the application; what a client actually calls
        // is that path under the context path the deployment configures.
        // Reporting `/users` for an app served at `/api/users` is a wrong
        // URL, not a partial one — and the value is sitting in the same
        // application.properties the config table already read.
        val basePath = basePathFrom(configTable)
        // A base path declared in CODE, per framework: JAX-RS puts it on an
        // `Application` subclass rather than in configuration, so a config
        // lookup alone reports every Quarkus route without its prefix.
        val annotationBasePaths: Map<String, String> = buildMap {
            for (framework in pack.frameworks) {
                if (framework.applicationPathAnnotations.isEmpty()) continue
                val declared = annotationValues.values.asSequence()
                    .flatten()
                    .firstOrNull { ann ->
                        framework.applicationPathAnnotations.any {
                            EndpointDetector.matches(ann.fqn, it)
                        }
                    }
                    ?.value?.trim()?.removeSurrounding("\"").orEmpty()
                if (declared.isNotEmpty() && declared != "/") put(framework.id, declared)
            }
        }
        val all = (candidates + manifestCandidates + webXmlCandidates + implicitCandidates)
            .map { candidate ->
                val prefix = annotationBasePaths[candidate.framework]?.takeIf { it.isNotEmpty() } ?: basePath
                if (prefix.isEmpty() || candidate.framework == "android") {
                    candidate
                } else {
                    candidate.copy(pathTemplate = joinPaths(prefix, candidate.pathTemplate))
                }
            }
            .map { candidate -> withTransportParameters(candidate, module, pack, folder) }
            .map { candidate -> withMediaAndAuthentication(candidate, module, pack, folder, lambdaLinks, annotationValues) }
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
                queryParameters = candidate.queryParameters,
                consumes = candidate.consumes,
                produces = candidate.produces,
                authentication = candidate.authentication,
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
        val outbounds = OutboundDetector.detect(module, folder, pack, annotationValues)
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

    /**
     * The handler's URL parameters, added to a candidate after detection.
     *
     * One pass over every candidate rather than one per detection branch,
     * because the question is the same whichever way the route was found: a
     * servlet mapped in `web.xml` reads `getParameter("q")` exactly as an
     * annotated one does. The route's own template is passed in because it
     * is what settles a `merged` reader's transport — which is only knowable
     * here, after the base path has been composed and the path normalised.
     */
    private fun withTransportParameters(
        candidate: EndpointDetector.Candidate,
        module: KirModule,
        pack: EndpointsPack,
        folder: KirValueFolder,
    ): EndpointDetector.Candidate {
        if (candidate.handlerSymbol.isEmpty()) return candidate
        val framework = pack.frameworks.firstOrNull { it.id == candidate.framework } ?: return candidate
        val fn = module.functions.firstOrNull { it.canonicalName == candidate.handlerSymbol } ?: return candidate
        val read = EndpointDetector.transportParameters(fn, framework, folder, candidate.pathTemplate)
        val declaredByAnnotation = EndpointDetector.annotatedParameters(fn, framework)
        // The template's own variables stay authoritative for the path: a
        // route declares `{id}` whether or not the handler ever reads it.
        val path = (candidate.pathParameters + read.path + declaredByAnnotation.path).distinct().sorted()
        val query = (read.query + declaredByAnnotation.query).distinct().sorted()
        return candidate.copy(pathParameters = path, queryParameters = query)
    }

    /** The category an endpoint handler's parameters carry when the run asks for endpoint sources. */
    const val SOURCE_CATEGORY = "untrusted-input"

    /**
     * A candidate's `consumes`/`produces`/`authentication`, filled from the
     * same places the frameworks themselves read them (P14). These three
     * lists were `emptyList()` on every endpoint kosi had ever emitted —
     * the information was in annotations the detector already loaded, and
     * in Ktor's case in the ENCLOSING call, and nothing looked at either.
     *
     *  - ANNOTATED frameworks: the handler's own annotations first, then
     *    the owning class's (a class-level `@RequestMapping(consumes=..)`
     *    covers every handler Spring would route to it).
     *  - DSL frameworks: authentication sits on the nesting chain —
     *    `authenticate("basic") { get { .. } }` — collected by walking the
     *    same lambda links the route prefixes use. Media annotations do not
     *    exist for a bare DSL route (the handler is a lambda with no
     *    annotations), so an honest empty stays empty.
     *
     * A framework the pack gives no media/auth annotations to reports empty
     * lists — empty because nothing declares them, which is the truth, not
     * a gap nobody has looked at.
     */
    private fun withMediaAndAuthentication(
        candidate: EndpointDetector.Candidate,
        module: KirModule,
        pack: EndpointsPack,
        folder: KirValueFolder,
        lambdaLinks: Map<String, EndpointDetector.LambdaLink>,
        annotationValues: Map<String, List<EndpointDetector.DeclAnnotation>>,
    ): EndpointDetector.Candidate {
        val framework = pack.frameworks.firstOrNull { it.id == candidate.framework }
        if (framework == null) return candidate
        val handler = candidate.handlerSymbol
        val owner = handler.substringBeforeLast('.')
        val handlerAnnotations = if (handler.isNotEmpty()) annotationValues[handler].orEmpty() else emptyList()
        val ownerAnnotations = if (handler.isNotEmpty()) annotationValues[owner].orEmpty() else emptyList()

        val consumes = sortedSetOf<String>()
        val produces = sortedSetOf<String>()
        val authentication = sortedSetOf<String>()
        // Media kinds are resolved as a SET across the framework's patterns
        // first: Spring's method-level composed annotation (@GetMapping)
        // REPLACES the class default (@RequestMapping) for its kind — and
        // matching each pattern independently would append the class default
        // beside the method's own, which Spring never routes.
        for (kind in listOf(io.cdxgen.kosi.models.KIND_CONSUMES, io.cdxgen.kosi.models.KIND_PRODUCES)) {
            val patterns = framework.mediaAnnotations.filter { it.kind == kind }
            if (patterns.isEmpty()) continue
            val target = when (kind) {
                io.cdxgen.kosi.models.KIND_CONSUMES -> consumes
                else -> produces
            }
            val methodValues = patterns.flatMap { media ->
                handlerAnnotations.filter { EndpointDetector.matches(it.fqn, media.pattern) }
                    .flatMap { mediaValuesOf(it, media) }
            }
            if (methodValues.isNotEmpty()) {
                target.addAll(methodValues)
            } else {
                target.addAll(
                    patterns.flatMap { media ->
                        ownerAnnotations.filter { EndpointDetector.matches(it.fqn, media.pattern) }
                            .flatMap { mediaValuesOf(it, media) }
                    },
                )
            }
        }
        for (auth in framework.authenticationAnnotations) {
            val hit = handlerAnnotations.firstOrNull { EndpointDetector.matches(it.fqn, auth.pattern) }
                ?: ownerAnnotations.firstOrNull { EndpointDetector.matches(it.fqn, auth.pattern) }
                ?: continue
            // An array-valued requirement (`@RolesAllowed(["a","b"])`) names
            // every entry; a single constant falls back to the plain value.
            val declared = hit.namedValues["value"] ?: listOfNotNull(hit.value)
            authentication.add(if (declared.isEmpty()) auth.scheme else "${auth.scheme}(${declared.joinToString(",")})")
        }
        authentication.addAll(authenticationChain(handler, framework, module, folder, lambdaLinks))
        if (consumes.isEmpty() && produces.isEmpty() && authentication.isEmpty()) return candidate
        return candidate.copy(
            consumes = consumes.toList(),
            produces = produces.toList(),
            authentication = authentication.toList(),
        )
    }

    /**
     * The media types one annotation declares: the NAMED argument the pack
     * names (Spring's `consumes = [...]`), or the annotation's positional
     * value arguments when the pack names none (JAX-RS's
     * `@Consumes("application/json")`).
     */
    private fun mediaValuesOf(
        annotation: EndpointDetector.DeclAnnotation?,
        media: io.cdxgen.kosi.models.MediaAnnotation,
    ): List<String> {
        annotation ?: return emptyList()
        if (media.argument.isNotEmpty()) {
            return annotation.namedValues[media.argument].orEmpty()
        }
        // The positional `value` arguments: namedValues carries a `value`
        // entry when written as `Consumes(value = [...])`, and the bare
        // positional form reduces to the single carried value.
        val named = annotation.namedValues["value"]
        if (named != null) return named
        return listOfNotNull(annotation.value)
    }

    /**
     * Authentication a DSL route inherits from its ENCLOSING nesting calls:
     * Ktor's `authenticate("basic") { get("/x") { .. } }` puts the handler
     * two lambda hops from the call that names the scheme. The walk is the
     * one [EndpointDetector] uses for route prefixes, over the same links,
     * collecting any hop whose creating call is the framework's
     * authentication wrapper.
     */
    private fun authenticationChain(
        handlerCanonical: String,
        framework: io.cdxgen.kosi.models.FrameworkModel,
        module: KirModule,
        folder: KirValueFolder,
        lambdaLinks: Map<String, EndpointDetector.LambdaLink>,
    ): List<String> {
        if (framework.authenticationDsl.isEmpty() || handlerCanonical.isEmpty()) return emptyList()
        val out = mutableListOf<String>()
        var current: String? = handlerCanonical
        var hops = 0
        while (current != null && hops < 8) {
            hops++
            val link = lambdaLinks[current] ?: break
            val call = link.creationCall
            val name = EndpointDetector.callName(call)
            if (name != null && framework.authenticationDsl.any { it.substringAfterLast('.') == name }) {
                val parent = module.functions.firstOrNull { it.canonicalName == link.parentFunction }
                val block = parent?.body?.blocks?.firstOrNull { it.instructions.any { it === call } }
                val index = block?.instructions?.indexOfFirst { it === call } ?: -1
                val args = when (call) {
                    is KirCall -> call.args
                    is KirDynamicCall -> call.args
                    else -> emptyList()
                }
                val folded = if (parent != null && block != null && index >= 0) {
                    args.firstOrNull()?.let { folder.valueAt(parent, block, index, it) }?.value
                } else {
                    null
                }
                out.add(if (folded.isNullOrEmpty()) name!! else "$name($folded)")
            }
            current = link.parentFunction
        }
        return out.reversed()
    }

    /**
     * The filter chain's handler. A filter serves EVERY verb, so its
     * candidate carries no method list — the empty list here is the honest
     * answer, not a missing one.
     */
    private const val DO_FILTER = "doFilter"

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
    /**
     * Servlets mapped in `WEB-INF/web.xml` rather than by annotation. The
     * descriptor names the class and its URL patterns; the HTTP methods
     * come from the handler methods that class actually declares, read out
     * of the KIR — so a servlet that implements only `doGet` publishes a
     * GET route and not the whole verb set.
     */
    /**
     * Routes with no handler in source.
     *
     * Two kinds, both real attack surface and both invisible to a scanner
     * that only reads handlers:
     *
     *  - DEPENDENCY-implied: Actuator's endpoints and springdoc's API
     *    documents exist because the artifact is on the classpath. They are
     *    among the most probed paths on any Spring deployment, and kosi
     *    reported none of them.
     *  - REPOSITORY-implied: Spring Data REST exposes every repository
     *    interface as a collection resource named after the entity, with the
     *    full verb set, without anyone writing a controller.
     *
     * Both are published with `foundBy = "implicit"`, so a consumer can tell
     * a route that was read from code apart from one inferred from a
     * dependency.
     */
    private fun implicitEndpoints(
        module: KirModule,
        pack: EndpointsPack,
        dependencyCoordinates: Set<String>,
        configTable: ConfigResolver.ConfigTable,
    ): List<EndpointDetector.Candidate> {
        val out = mutableListOf<EndpointDetector.Candidate>()
        for (framework in pack.frameworks) {
            val present = framework.dependencyMarkers.any { marker ->
                dependencyCoordinates.any { it.contains(marker) }
            }
            if (present) {
                // The configured base REPLACES the framework's default —
                // Actuator served at `/ops` answers `/ops/health`, never
                // `/ops/actuator/health`.
                val base = framework.implicitBasePathKeys
                    .firstNotNullOfOrNull { key -> configTable[key]?.value?.trim()?.takeIf { it.isNotEmpty() } }
                    ?: framework.implicitBasePathDefault
                for (route in framework.implicitRoutes) {
                    out.add(
                        EndpointDetector.Candidate(
                            framework = framework.id,
                            httpMethods = route.methods,
                            pathTemplate = EndpointDetector.normalizePath(joinPaths(base, route.path)),
                            pathParameters = emptyList(),
                            handlerSymbol = "",
                            foundBy = "implicit",
                            position = null,
                            exported = true,
                            permissions = emptyList(),
                            deepLinkHosts = emptyList(),
                        ),
                    )
                }
            }
            if (framework.repositorySupertypes.isEmpty()) continue
            // A repository is a TYPE, and types reach the KIR through the
            // functions they own; a repository interface declares only
            // abstract members, so its supertypes are read from any function
            // the module attributes to it.
            val repositories = module.functions.asSequence()
                .filter { fn -> fn.supertypes.any { st -> framework.repositorySupertypes.any { EndpointDetector.matches(st, it) } } }
                .map { it.canonicalName.substringBeforeLast('.') }
                .distinct()
                .sorted()
            for (repository in repositories) {
                val simple = repository.substringAfterLast('.')
                val collection = collectionNameOf(simple)
                out.add(
                    EndpointDetector.Candidate(
                        framework = framework.id,
                        httpMethods = framework.repositoryMethods,
                        pathTemplate = EndpointDetector.normalizePath("/" + collection),
                        pathParameters = emptyList(),
                        handlerSymbol = repository,
                        foundBy = "implicit",
                        position = null,
                        exported = true,
                        permissions = emptyList(),
                        deepLinkHosts = emptyList(),
                    ),
                )
            }
        }
        return out
    }

    /**
     * Spring Data REST's default collection name: the repository's entity,
     * lower-camel, pluralised the way its own `EvoInflector` does for the
     * regular cases (`OrderRepository` -> `orders`, `CategoryRepository` ->
     * `categories`). An irregular plural is NOT guessed at; the regular form
     * is reported and named as implicit.
     */
    internal fun collectionNameOf(repositoryName: String): String {
        val entity = repositoryName.removeSuffix("Repository").removeSuffix("Repo")
        if (entity.isEmpty()) return repositoryName.lowercase()
        val lower = entity.replaceFirstChar { it.lowercaseChar() }
        return when {
            lower.endsWith("y") && lower.length > 1 && lower[lower.length - 2] !in "aeiou" ->
                lower.dropLast(1) + "ies"
            lower.endsWith("s") || lower.endsWith("x") || lower.endsWith("ch") || lower.endsWith("sh") ->
                lower + "es"
            else -> lower + "s"
        }
    }

    private fun webXmlEndpoints(
        module: KirModule,
        mappings: List<WebXmlParser.ServletMapping>,
        pack: EndpointsPack,
        root: Path,
    ): List<EndpointDetector.Candidate> {
        if (mappings.isEmpty()) return emptyList()
        val servlet = pack.frameworks.firstOrNull { it.handlerMethodNames.isNotEmpty() } ?: return emptyList()
        // The descriptor's own authentication requirements (P15): a
        // `<security-constraint>` names url-patterns and the roles that may
        // reach them — servlet spec 13.8 matching, exact / prefix / extension
        // — and every descriptor endpoint whose pattern matches carries the
        // requirement. The XML was already parsed for mappings; the
        // constraint element had been parsed past since P13.
        val constraints = WebXmlParser.securityConstraints(root)
        val out = mutableListOf<EndpointDetector.Candidate>()
        for (mapping in mappings) {
            // A filter's handler is `doFilter` and nothing else; a servlet's
            // is any of the verb methods but NOT doFilter, or a servlet that
            // happened to define one would publish its routes twice.
            val names = servlet.handlerMethodNames.filter {
                if (mapping.kind == WebXmlParser.KIND_FILTER) it.name == DO_FILTER else it.name != DO_FILTER
            }
            val handlers = module.functions.filter { fn ->
                fn.syntheticCause == null &&
                    fn.canonicalName.substringBeforeLast('.') == mapping.className &&
                    names.any { it.name == fn.canonicalName.substringAfterLast('.') }
            }
            for (fn in handlers) {
                val methods = names
                    .firstOrNull { it.name == fn.canonicalName.substringAfterLast('.') }
                    ?.methods.orEmpty()
                for (pattern in mapping.urlPatterns) {
                    val auth = constraints
                        .filter { c -> c.urlPatterns.any { cp -> urlPatternMatches(pattern, cp) } }
                        .map { c ->
                            when {
                                c.denyAll -> "security-constraint(denied)"
                                c.roles == listOf("*") -> "security-constraint(authenticated)"
                                else -> "security-constraint(${c.roles.joinToString(",")})"
                            }
                        }
                        .distinct()
                        .sorted()
                    out.add(
                        EndpointDetector.Candidate(
                            framework = servlet.id,
                            httpMethods = methods,
                            pathTemplate = EndpointDetector.normalizePath(pattern),
                            pathParameters = emptyList(),
                            handlerSymbol = fn.canonicalName,
                            foundBy = "descriptor",
                            position = io.cdxgen.kosi.schema.Position(fn.file, fn.line, fn.line),
                            exported = true,
                            permissions = emptyList(),
                            deepLinkHosts = emptyList(),
                            authentication = auth,
                        ),
                    )
                }
            }
        }
        return out
    }

    /**
     * Servlet url-pattern matching (spec 13.8.2): a path MAPPED endpoint
     * (`/legacy` + wildcard) is constrained by a constraint pattern that is
     * an EXACT match or a PREFIX of it (`/legacy` + wildcard covers
     * `/legacy/report`); an EXTENSION mapping (star-dot form) matches a
     * constraint pattern of the same extension or the catch-all root
     * wildcard. Both sides are descriptor patterns, so the comparison is
     * pattern-to-pattern with the stricter (more specific) mapping winning:
     * a constraint on `/legacy` + wildcard constrains the endpoint mapped
     * at `/legacy/report`.
     */
    internal fun urlPatternMatches(mapping: String, constraint: String): Boolean {
        if (constraint == "/*") return true
        if (mapping == constraint) return true
        val constraintPrefix = constraint.removeSuffix("/*")
        if (constraint.endsWith("/*")) {
            if (mapping.startsWith("$constraintPrefix/")) return true
            // `/legacy/*` also covers the exact path `/legacy` itself.
            if (mapping == constraintPrefix) return true
        }
        if (constraint.startsWith("*.")) {
            if (mapping.endsWith(constraint.removePrefix("*"))) return true
            // Both patterns name the same extension.
            if (mapping.startsWith("*.") && mapping.removePrefix("*.") == constraint.removePrefix("*.")) return true
        }
        return false
    }

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
                        (candidate is KirCall || candidate is KirDynamicCall) && lambda.result in candidate.uses
                    } ?: continue
                    links[lambda.function] = EndpointDetector.LambdaLink(fn.canonicalName, creation)
                }
            }
        }
        return links
    }
    /**
     * The configured context path, by framework, first match wins in a fixed
     * order. Each key is the one that framework documents; a project that
     * sets none reports application-relative paths, as before.
     */
    private val BASE_PATH_KEYS = listOf(
        "server.servlet.context-path",
        "spring.webflux.base-path",
        "micronaut.server.context-path",
        "quarkus.http.root-path",
        "ktor.deployment.rootPath",
        "server.base-path",
    )

    internal fun basePathFrom(configTable: ConfigResolver.ConfigTable): String {
        for (key in BASE_PATH_KEYS) {
            val value = configTable[key]?.value?.trim().orEmpty()
            if (value.isNotEmpty() && value != "/") return value
        }
        return ""
    }

    /** `/api` + `/users` -> `/api/users`, with no doubled or missing slash. */
    internal fun joinPaths(base: String, path: String): String {
        if (base.isEmpty() || base == "/") return path
        val left = base.removeSuffix("/")
        val right = path.removePrefix("/")
        val prefix = if (left.startsWith("/")) left else "/$left"
        return if (right.isEmpty()) prefix else "$prefix/$right"
    }

}

/** Workspace `const val` name -> value, only for names with a UNIQUE value. */
object ConstTable {
    private val PATTERN = Regex(
        """(?:\bconst\s+val\s+|\bpublic\s+static\s+final\s+String\s+|\bstatic\s+final\s+String\s+)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"""",
    )

    // P22 §1: keyed by the `const val` NAME — deliberately name-unique: a
    // name mapping to two values anywhere is ambiguous and is REFUSED below
    // (filterValues size == 1), never guessed, so the non-unique key is the
    // mechanism, not a defect.
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
