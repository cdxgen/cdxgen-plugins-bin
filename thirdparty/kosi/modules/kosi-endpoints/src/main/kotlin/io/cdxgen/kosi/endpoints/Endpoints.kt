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
 * The facade: inbound endpoints, outbound services and URL evidence from
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
        /** Repositories whose CRUD surface depends on an unknown spring-data-commons generation. */
        val repositoriesCrudUnknown: List<String> = emptyList(),
    )

    data class Attribution(
        /** Absolute file path -> (relativePath, modulePath). */
        val byAbsoluteFilePath: Map<String, Pair<String, String>>,
        val purlByModulePath: Map<String, String>,
    )

    /** A type the run read: canonical name, its ROOT-RELATIVE file, and its supertypes. */
    data class TypeDeclaration(val canonicalName: String, val file: String, val supertypes: List<String>)

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
         * The canonical names of every declaration the run read —
         * Kotlin AND Java, types and members alike. A manifest names a
         * class; whether that class was READ is the only honest basis for
         * `substantiated`, and the KIR alone cannot answer it because Java
         * declarations never enter it.
         */
        analysedDeclarations: Set<String> = emptySet(),
        /**
         * The pack to detect with. Production always loads the builtin; the
         * liveness gate re-runs THIS analysis once per removed pack
         * entry over the SAME captured inputs, so an entry no fixture's
         * report depends on is a mechanical fact, not an anecdote.
         */
        pack: EndpointsPack = io.cdxgen.kosi.models.EndpointModels.loadBuiltin(),
        /**
         * When non-null, every value the consumers ask the folder
         * for is counted here with its failure reason — the depth report's
         * value-resolution table. Production passes null and pays nothing.
         */
        foldStats: KirValueFolder.FoldStats? = null,
        /**
         * `false` restores the earlier block-local scan — the depth
         * report's baseline column measures both ways over one capture.
         */
        crossBlock: Boolean = true,
        /**
         * Every TYPE the run read with its supertypes. A Spring Data
         * repository is usually an interface with no body — `interface
         * CustomerRepository : CrudRepository<Customer, Long>` — and a type
         * with no members owns no function, so the KIR alone never sees it.
         */
        typeDeclarations: List<TypeDeclaration> = emptyList(),
        /** File (root-relative) -> two-segment roots of the packages it imports. */
        importRootsByFile: Map<String, Set<String>> = emptyMap(),
    ): Result {
        val configTable = ConfigResolver.load(root)
        // `value` is null for a key the config files DISAGREE about: known
        // key, unprovable value, so it is absent from the fold table and the
        // site publishes `unresolved` with the key named. The `!!` that
        // stood here was safe only while nothing could ever be ambiguous —
        // the same read one layer up (`configValuesForCrypto`) has always
        // used `mapNotNull` on the value, and two readers of one nullable
        // field disagreeing about whether it can be null is the shape the
        // rule is about.
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
                importRootsByFile = importRootsByFile,
            ),
            pack,
        )
        val manifests = if (includeManifests) AndroidManifestParser.parse(root) else emptyList()
        val manifestCandidates = manifestEndpoints(module, manifests, pack, analysedDeclarations)
        val webXmlCandidates = webXmlEndpoints(module, WebXmlParser.parse(root), pack, root)
        val crudUnknown = mutableListOf<String>()
        val modules = ModuleConfigs(root, configTable)
        val implicitCandidates = implicitEndpoints(module, pack, dependencyCoordinates, configTable) +
            repositoryEndpoints(module, pack, annotationValues, typeDeclarations, dependencyCoordinates, crudUnknown, modules)

        // The DEPLOYMENT base path. A handler's annotation or DSL call names
        // a path relative to the application; what a client actually calls
        // is that path under the context path the deployment configures.
        // Reporting `/users` for an app served at `/api/users` is a wrong
        // URL, not a partial one — and the value is sitting in the same
        // application.properties the config table already read.
        // Resolved per MODULE: a multi-module build is several deployments,
        // and one app's `server.servlet.context-path` is not its sibling's.
        // digital-restaurant sets `spring.data.rest.base-path: /api/query`
        // in its query modules only; read repo-wide, it was either applied
        // to every command module's handlers or refused as ambiguous.
        val dataRestBases = DataRestBases(module, pack, folder, modules)
        // A base path declared in CODE: JAX-RS puts it on an `Application`
        // subclass. Per MODULE, like the config keys — one module's
        // `@ApplicationPath` is not its sibling's.
        fun applicationPathFor(framework: io.cdxgen.kosi.models.FrameworkModel, file: String?): String? {
            if (framework.applicationPathAnnotations.isEmpty()) return null
            val module = modules.moduleRootOf(file)
            return annotationValues.values.asSequence().flatten()
                .filter { ann -> framework.applicationPathAnnotations.any { EndpointDetector.matches(ann.fqn, it) } }
                .filter { ann -> modules.moduleRootOf(ann.file) == module }
                .map { it.value?.trim()?.removeSurrounding("\"").orEmpty() }
                .firstOrNull { it.isNotEmpty() && it != "/" }
        }
        val all = (candidates + manifestCandidates + webXmlCandidates + implicitCandidates)
            .map { candidate -> if (candidate.dataRestBase) dataRestBases.compose(candidate) else candidate }
            .map { candidate -> servingFacts(candidate, pack, module, annotationValues, modules) }
            .map { candidate ->
                val framework = pack.frameworks.firstOrNull { it.id == candidate.framework }
                if (framework == null || candidate.transport != null) return@map candidate
                val file = candidate.position?.filename
                val prefix = deploymentBasePath(framework, modules.tableFor(file)) { applicationPathFor(framework, file) }
                if (prefix.isEmpty()) candidate else candidate.copy(pathTemplate = joinPaths(prefix, candidate.pathTemplate))
            }
            .map { candidate -> withTransportParameters(candidate, module, pack, folder, annotationValues) }
            .map { candidate -> withMediaAndAuthentication(candidate, module, pack, folder, lambdaLinks, annotationValues) }
            .sortedWith(compareBy({ it.framework }, { it.pathTemplate }, { it.handlerSymbol }, { it.position?.filename.orEmpty() }))

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
                substantiated = candidate.substantiated ?: true,
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
                pathUnresolved = candidate.pathUnresolved,
                anyMethod = candidate.anyMethod,
                transport = candidate.transport,
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
            repositoriesCrudUnknown = crudUnknown.sorted(),
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
        annotationValues: Map<String, List<EndpointDetector.DeclAnnotation>>,
    ): EndpointDetector.Candidate {
        if (candidate.handlerSymbol.isEmpty()) return candidate
        val framework = pack.frameworks.firstOrNull { it.id == candidate.framework } ?: return candidate
        // The handler in the candidate's OWN file: one canonical name can be
        // a handler in each of several app modules.
        val file = candidate.position?.filename
        val fn = module.functions.firstOrNull {
            it.canonicalName == candidate.handlerSymbol && (file == null || sameFile(it.file, file))
        } ?: return candidate
        val read = EndpointDetector.transportParameters(fn, framework, folder, candidate.pathTemplate)
        val declaredByAnnotation = EndpointDetector.annotatedParameters(fn, framework) { param ->
            EndpointDetector.declaredIn(annotationValues[fn.canonicalName + "#" + param].orEmpty(), fn.file)
        }
        // The template's own variables stay authoritative for the path: a
        // route declares `{id}` whether or not the handler ever reads it.
        val path = (candidate.pathParameters + read.path + declaredByAnnotation.path).distinct().sorted()
        val query = (candidate.queryParameters + read.query + declaredByAnnotation.query).distinct().sorted()
        return candidate.copy(pathParameters = path, queryParameters = query)
    }

    /** The category an endpoint handler's parameters carry when the run asks for endpoint sources. */
    const val SOURCE_CATEGORY = "untrusted-input"

    /**
     * A candidate's `consumes`/`produces`/`authentication`, filled from the
     * same places the frameworks themselves read them. These three
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
        val file = candidate.position?.filename
        val handlerAnnotations = if (handler.isNotEmpty()) EndpointDetector.declaredIn(annotationValues[handler].orEmpty(), file) else emptyList()
        val ownerAnnotations = if (handler.isNotEmpty()) EndpointDetector.declaredIn(annotationValues[owner].orEmpty(), file) else emptyList()

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
        }
        return out
    }

    /**
     * What SERVES a candidate, from the pack: a non-HTTP transport, the one
     * path every handler of a single-endpoint framework answers at
     * (GraphQL), or a cloud function's HTTP trigger.
     */
    private fun servingFacts(
        candidate: EndpointDetector.Candidate,
        pack: EndpointsPack,
        module: KirModule,
        annotationValues: Map<String, List<EndpointDetector.DeclAnnotation>>,
        modules: ModuleConfigs,
    ): EndpointDetector.Candidate {
        val framework = pack.frameworks.firstOrNull { it.id == candidate.framework } ?: return candidate
        var out = candidate
        if (framework.transport.isNotEmpty()) out = out.copy(transport = framework.transport)
        val file = candidate.position?.filename
        framework.servedAtDefault?.let { default ->
            val table = modules.tableFor(file)
            val configured = framework.servedAtKeys.firstNotNullOfOrNull { key -> table[key] }
            val path = when {
                configured == null -> default
                configured.value == null -> default.also {
                    out = out.copy(pathUnresolved = "${configured.key}: no value a default run serves (set only by a non-default profile, or config files of one precedence disagree)")
                }
                else -> configured.value.trim()
            }
            out = out.copy(
                pathTemplate = EndpointDetector.normalizePath(path),
                pathParameters = EndpointDetector.pathParametersOf(path),
                httpMethods = framework.servedAtMethods,
            )
        }
        if (framework.functionHttpTriggers.isNotEmpty()) {
            val fn = module.functions.firstOrNull {
                it.canonicalName == candidate.handlerSymbol && (file == null || sameFile(it.file, file))
            }
            val trigger = fn?.params?.firstNotNullOfOrNull { param ->
                if (param.annotations.none { a -> framework.functionHttpTriggers.any { EndpointDetector.matches(a, it) } }) return@firstNotNullOfOrNull null
                EndpointDetector.declaredIn(annotationValues[fn.canonicalName + "#" + param.name].orEmpty(), fn.file)
                    .firstOrNull { ann -> framework.functionHttpTriggers.any { EndpointDetector.matches(ann.fqn, it) } }
                    ?: EndpointDetector.DeclAnnotation("", null, 0)
            }
            if (trigger == null) {
                // A queue, timer or blob trigger: the function is real, and
                // it is not an HTTP route.
                return out.copy(transport = "function", pathTemplate = "", pathParameters = emptyList(), httpMethods = emptyList())
            }
            val route = trigger.namedValues["route"]?.firstOrNull()?.takeIf { it.isNotEmpty() } ?: candidate.pathTemplate.trimStart('/')
            val prefix = functionRoutePrefix(framework, modules.moduleRootOf(file))
            val path = EndpointDetector.normalizePath(joinPaths(prefix, route).let { if (it.startsWith("/")) it else "/$it" })
            val methods = trigger.namedValues["methods"].orEmpty()
                .map { it.substringAfterLast('.').uppercase() }
                .filter { it in setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT") }
                .distinct()
            out = out.copy(
                pathTemplate = path,
                pathParameters = EndpointDetector.pathParametersOf(path),
                httpMethods = methods,
                anyMethod = methods.isEmpty(),
            )
        }
        return out
    }

    /** `host.json`'s route prefix for the module, else the framework's default. */
    private fun functionRoutePrefix(framework: io.cdxgen.kosi.models.FrameworkModel, moduleRoot: Path): String {
        val hostJson = moduleRoot.resolve("host.json")
        if (framework.functionRoutePrefixHostKey.isEmpty() || !java.nio.file.Files.isRegularFile(hostJson)) {
            return framework.functionRoutePrefixDefault
        }
        return try {
            var node: io.cdxgen.kosi.schema.JsonValue? = io.cdxgen.kosi.schema.JsonReader.parse(java.nio.file.Files.readString(hostJson))
            for (segment in framework.functionRoutePrefixHostKey.split('.')) {
                node = (node as? io.cdxgen.kosi.schema.JsonObj)?.members?.get(segment)
            }
            (node as? io.cdxgen.kosi.schema.JsonStr)?.value ?: framework.functionRoutePrefixDefault
        } catch (_: Exception) {
            framework.functionRoutePrefixDefault
        }
    }

    /**
     * Config tables per build MODULE: the nearest directory at or above a
     * file that holds a build script, bounded by the analysed root. A file
     * with no module above it, and a candidate with no file, read the
     * root's table — which is what every lookup read before.
     */
    internal class ModuleConfigs(private val root: Path, private val rootTable: ConfigResolver.ConfigTable) {
        private val absoluteRoot = root.toAbsolutePath().normalize()
        private val tables = HashMap<Path, ConfigResolver.ConfigTable>()
        private val moduleOf = HashMap<String, Path>()

        fun moduleRootOf(file: String?): Path {
            if (file == null) return absoluteRoot
            return moduleOf.getOrPut(file) {
                val path = Path.of(file).let { if (it.isAbsolute) it else absoluteRoot.resolve(it) }.normalize()
                var dir: Path? = path.parent
                while (dir != null && dir.startsWith(absoluteRoot)) {
                    if (BUILD_SCRIPTS.any { java.nio.file.Files.isRegularFile(dir!!.resolve(it)) }) return@getOrPut dir
                    if (dir == absoluteRoot) break
                    dir = dir.parent
                }
                absoluteRoot
            }
        }

        private val buildTexts = HashMap<Path, String?>()

        /**
         * Whether the build scripts from [file]'s module up to the analysed
         * root declare any of [markers] (artifact-name substrings). With no
         * build script anywhere on that chain, the resolved classpath
         * [coordinates] decide.
         */
        fun declaresDependency(file: String?, markers: List<String>, coordinates: Set<String>): Boolean {
            var dir: Path? = moduleRootOf(file)
            var sawBuildScript = false
            while (dir != null && dir.startsWith(absoluteRoot)) {
                val text = buildTexts.getOrPut(dir) {
                    BUILD_SCRIPTS.map { dir!!.resolve(it) }.filter { java.nio.file.Files.isRegularFile(it) }
                        .takeIf { it.isNotEmpty() }
                        ?.joinToString("\n") { runCatching { java.nio.file.Files.readString(it) }.getOrDefault("") }
                }
                if (text != null) {
                    sawBuildScript = true
                    if (markers.any { text.contains(it) }) return true
                }
                if (dir == absoluteRoot) break
                dir = dir.parent
            }
            return !sawBuildScript && coordinates.any { c -> markers.any { c.contains(it) } }
        }

        fun tableFor(file: String?): ConfigResolver.ConfigTable {
            val module = moduleRootOf(file)
            if (module == absoluteRoot) return rootTable
            return tables.getOrPut(module) { ConfigResolver.load(module) }
        }

        private companion object {
            val BUILD_SCRIPTS = listOf("build.gradle.kts", "build.gradle", "pom.xml")
        }
    }

    /**
     * The Spring Data REST base path, per module. Spring applies the
     * `spring.data.rest.base-path` property and then every
     * `RepositoryRestConfigurer`, so a folded `setBasePath` argument wins
     * over the key. What cannot be proven — two config files in one module
     * disagreeing, a setter argument that does not fold, two setters with
     * different values — is NOT guessed: the path stays relative and
     * [EndpointDetector.Candidate.pathUnresolved] names why.
     */
    internal class DataRestBases(
        module: KirModule,
        private val pack: EndpointsPack,
        folder: KirValueFolder,
        private val modules: ModuleConfigs,
    ) {
        private class Setter(val value: String?, val detail: String)

        private val settersByModule: Map<Path, List<Setter>> = buildMap<Path, MutableList<Setter>> {
            val patterns = pack.frameworks.flatMap { it.dataRestBasePathSetters }
            if (patterns.isEmpty()) return@buildMap
            for (fn in module.functions) {
                val body = fn.body ?: continue
                for (block in body.blocks) {
                    for ((index, ins) in block.instructions.withIndex()) {
                        if (ins !is KirCall) continue
                        if (patterns.none { EndpointDetector.matches(ins.callee.fqn, it) }) continue
                        val arg = ins.args.firstOrNull()
                        val folded = arg?.let { folder.valueAt(fn, block, index, it) }
                        val proven = folded?.value?.takeIf {
                            folded.status == KirValueFolder.ValueStatus.LITERAL ||
                                folded.status == KirValueFolder.ValueStatus.FOLDED_CONST ||
                                folded.status == KirValueFolder.ValueStatus.FOLDED_TEMPLATE ||
                                folded.status == KirValueFolder.ValueStatus.CONFIG
                        }
                        val at = "${fn.canonicalName}:${if (ins.line > 0) ins.line else fn.line}"
                        getOrPut(modules.moduleRootOf(fn.file)) { mutableListOf() }.add(Setter(proven, at))
                    }
                }
            }
        }

        private val resolved = HashMap<Path, Pair<String, String?>>()

        /** (base, unresolved reason) for the module [file] belongs to. */
        fun baseFor(file: String?, framework: String): Pair<String, String?> {
            val module = modules.moduleRootOf(file)
            return resolved.getOrPut(module) {
                val setters = settersByModule[module].orEmpty()
                if (setters.isNotEmpty()) {
                    val unfolded = setters.firstOrNull { it.value == null }
                    val values = setters.mapNotNull { it.value }.distinct()
                    return@getOrPut when {
                        unfolded != null -> "" to "setBasePath argument did not fold at ${unfolded.detail}"
                        values.size > 1 -> "" to "setBasePath is called with ${values.size} different values in one module"
                        else -> values.single() to null
                    }
                }
                val keys = pack.frameworks.firstOrNull { it.id == framework }?.dataRestBasePathKeys.orEmpty()
                val table = modules.tableFor(file)
                for (key in keys) {
                    val entry = table[key] ?: continue
                    val value = entry.value?.trim() ?: return@getOrPut "" to "$key: no value a default run serves (set only by a non-default profile, or config files of one precedence disagree)"
                    return@getOrPut value to null
                }
                "" to null
            }
        }

        fun compose(candidate: EndpointDetector.Candidate): EndpointDetector.Candidate {
            val (base, unresolved) = baseFor(candidate.position?.filename, candidate.framework)
            val path = EndpointDetector.normalizePath(joinPaths(base, candidate.pathTemplate))
            return candidate.copy(
                pathTemplate = path,
                pathParameters = EndpointDetector.pathParametersOf(path),
                pathUnresolved = unresolved ?: candidate.pathUnresolved,
            )
        }
    }

    /**
     * Spring Data REST repository resources: one collection route, one item
     * route and one search route per exported query method, with the verbs
     * [FrameworkModel.repositoryRoutes] assigns and the repository's own
     * `exported = false` declarations removing the verbs they back.
     */
    private fun repositoryEndpoints(
        module: KirModule,
        pack: EndpointsPack,
        annotationValues: Map<String, List<EndpointDetector.DeclAnnotation>>,
        typeDeclarations: List<TypeDeclaration>,
        dependencyCoordinates: Set<String>,
        crudUnknown: MutableList<String>,
        modules: ModuleConfigs,
    ): List<EndpointDetector.Candidate> {
        val out = mutableListOf<EndpointDetector.Candidate>()
        // spring-data-commons 3.0 split PagingAndSortingRepository off
        // CrudRepository: before it, extending the former brought save,
        // findById and delete; from it, only the paged findAll.
        fun generationOf(framework: io.cdxgen.kosi.models.FrameworkModel): Int? {
            val artifact = framework.repositoryGenerationArtifact ?: return null
            // `group:artifact:version` from a resolved pin, or the jar's own
            // file name (`spring-data-commons-2.6.4.jar`) for an explicit
            // classpath entry that carries no coordinate.
            val fileVersion = Regex("^" + Regex.escape(artifact.substringAfter(':')) + "-(\\d+)\\.")
            return dependencyCoordinates.firstNotNullOfOrNull { coordinate ->
                if (coordinate.startsWith("$artifact:")) {
                    coordinate.removePrefix("$artifact:").substringBefore('.').toIntOrNull()
                } else {
                    fileVersion.find(coordinate)?.groupValues?.get(1)?.toIntOrNull()
                }
            }
        }
        for (framework in pack.frameworks) {
            if (framework.repositorySupertypes.isEmpty()) continue
            val commonsMajor = generationOf(framework)
            fun isRepository(supertypes: List<String>) =
                supertypes.any { st -> framework.repositorySupertypes.any { EndpointDetector.matches(st, it) } }
            // (canonical name, file) -> the file as the KIR spells it when a
            // member of the type lowered, else the root-relative spelling.
            val repositories = sortedMapOf<Pair<String, String>, List<String>>(compareBy({ it.first }, { it.second }))
            for (fn in module.functions) {
                if (!isRepository(fn.supertypes)) continue
                val owner = fn.canonicalName.substringBeforeLast('.')
                val existing = repositories.keys.firstOrNull { it.first == owner && sameFile(it.second, fn.file) }
                if (existing == null) repositories[owner to fn.file] = fn.supertypes
            }
            for (type in typeDeclarations) {
                if (!isRepository(type.supertypes)) continue
                if (repositories.keys.none { it.first == type.canonicalName && sameFile(it.second, type.file) }) {
                    repositories[type.canonicalName to type.file] = type.supertypes
                }
            }
            for ((key, supertypes) in repositories) {
                val (repository, file) = key
                // Spring Data REST exports a repository only where its
                // starter is on the module's classpath: a data-jdbc or
                // data-jpa module's CrudRepository serves no HTTP route.
                // Publishing one there made 37 spurious endpoints in the
                // corpus. The module's (or an enclosing) build script is the
                // evidence, read as text; classpath coordinates stand in only
                // for a tree with no build script at all.
                if (framework.repositoryDependencyMarkers.isNotEmpty() &&
                    !modules.declaresDependency(file, framework.repositoryDependencyMarkers, dependencyCoordinates)
                ) continue
                // The framework's own repository types (an in-source stub, a
                // decompiled dependency) are the supertypes, not resources.
                if (framework.repositorySupertypes.any { EndpointDetector.matches(repository, it) }) continue
                val resource = EndpointDetector.declaredIn(annotationValues[repository].orEmpty(), file)
                    .firstOrNull { ann -> framework.repositoryResourceAnnotations.any { EndpointDetector.matches(ann.fqn, it) } }
                if (resource?.namedValues?.get("exported")?.firstOrNull() == "false") continue
                val collection = resource?.namedValues?.get("path")?.firstOrNull()?.trim()?.trim('/')?.takeIf { it.isNotEmpty() }
                    ?: collectionNameOf(repository.substringAfterLast('.'))
                val declared = module.functions.filter { fn ->
                    fn.canonicalName.substringBeforeLast('.') == repository && sameFile(fn.file, file)
                }
                val hidden = mutableSetOf<String>()
                val searchPaths = sortedMapOf<String, String>()
                for (fn in declared) {
                    val name = fn.canonicalName.substringAfterLast('.')
                    val rest = EndpointDetector.declaredIn(annotationValues[fn.canonicalName].orEmpty(), fn.file)
                        .firstOrNull { ann -> framework.repositoryMethodAnnotations.any { EndpointDetector.matches(ann.fqn, it) } }
                    if (rest?.namedValues?.get("exported")?.firstOrNull() == "false") {
                        hidden.add(name)
                        continue
                    }
                    if (fn.body == null && name !in framework.repositoryCrudMethods && "override" !in fn.modifiers) {
                        searchPaths[name] = rest?.namedValues?.get("path")?.firstOrNull()?.trim()?.trim('/')
                            ?.takeIf { it.isNotEmpty() } ?: name
                    }
                }
                // Which backing methods the repository HAS. A CRUD supertype
                // brings them all; a paging-only one brings them only in the
                // generations whose paging type still extended the CRUD one.
                val paging = framework.repositoryPagingSupertypes
                val crudSupertype = supertypes.any { st ->
                    framework.repositorySupertypes.any { EndpointDetector.matches(st, it) } &&
                        paging.none { EndpointDetector.matches(st, it) }
                }
                val all = framework.repositoryRoutes.flatMap { it.backedBy }.toSet()
                val available: Set<String> = when {
                    crudSupertype -> all
                    commonsMajor != null && commonsMajor < framework.repositoryPagingCrudBelowMajor -> all
                    else -> {
                        if (commonsMajor == null) crudUnknown.add(repository)
                        framework.repositoryPagingMethods.toSet()
                    }
                } + declared.map { it.canonicalName.substringAfterLast('.') }
                val position = Position(
                    declared.firstOrNull()?.file ?: file,
                    declared.minOfOrNull { it.line } ?: 1,
                    1,
                )
                fun add(path: String, methods: List<String>, handler: String) {
                    if (methods.isEmpty()) return
                    val template = EndpointDetector.normalizePath(path)
                    out.add(
                        EndpointDetector.Candidate(
                            framework = framework.id,
                            httpMethods = methods,
                            pathTemplate = template,
                            pathParameters = EndpointDetector.pathParametersOf(template),
                            handlerSymbol = handler,
                            foundBy = "implicit",
                            position = position,
                            exported = true,
                            permissions = emptyList(),
                            deepLinkHosts = emptyList(),
                            dataRestBase = framework.dataRestBasePathMarkers.isNotEmpty(),
                        ),
                    )
                }
                for ((routePath, routes) in framework.repositoryRoutes.groupBy { it.path }.toSortedMap()) {
                    val served = routes.filter { route ->
                        route.backedBy.isEmpty() || route.backedBy.any { it in available && it !in hidden }
                    }
                    add("/$collection$routePath", served.map { it.method }.distinct(), repository)
                }
                if (searchPaths.isNotEmpty()) {
                    add("/$collection/search", listOf("GET"), repository)
                    for ((name, path) in searchPaths) add("/$collection/search/$path", listOf("GET"), "$repository.$name")
                }
            }
        }
        return out
    }

    private fun sameFile(a: String, b: String): Boolean =
        EndpointDetector.declaredIn(listOf(EndpointDetector.DeclAnnotation("", null, 0, file = a)), b).isNotEmpty()

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
        // The SERVLET shape — class-declared routes dispatched to
        // convention-named methods — not merely "has handler names": Ratpack
        // names `handle` too, and the first such framework in pack order
        // took every web.xml mapping and matched none of its classes.
        val servlet = pack.frameworks.firstOrNull {
            it.handlerMethodNames.isNotEmpty() && it.classMappingAnnotations.isNotEmpty()
        } ?: return emptyList()
        // The descriptor's own authentication requirements: a
        // `<security-constraint>` names url-patterns and the roles that may
        // reach them — servlet spec 13.8 matching, exact / prefix / extension
        // — and every descriptor endpoint whose pattern matches carries the
        // requirement. The XML was already parsed for mappings; the
        // constraint element had been parsed past.
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
                val named = names.firstOrNull { it.name == fn.canonicalName.substringAfterLast('.') }
                val methods = named?.methods.orEmpty()
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
                            anyMethod = methods.isEmpty() && named?.anyMethod == true,
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

    /**
     * `Outer$Inner` (the manifest and Java spelling) and `Outer.Inner`
     * (the Kotlin one) are two spellings of ONE class. Comparing them
     * literally left every nested component unmatched — 37 of dagger's 42
     * unsubstantiated component names are nested test activities whose
     * class kosi had read.
     */
    private fun flatten(name: String): String = name.replace('$', '.')

    private fun manifestEndpoints(
        module: KirModule,
        manifests: List<AndroidManifestParser.Manifest>,
        pack: EndpointsPack,
        analysedDeclarations: Set<String>,
    ): List<EndpointDetector.Candidate> {
        val android = pack.frameworks.firstOrNull { it.kind == "manifest" } ?: return emptyList()
        val components = android.manifestComponents
        val analysedFlat = analysedDeclarations.mapTo(HashSet()) { flatten(it) }
        val out = mutableListOf<EndpointDetector.Candidate>()
        for (manifest in manifests) {
            for (component in manifest.components) {
                if (component.kind !in components && component.kind != "activity-alias") continue
                val lifecycle = lifecycleHandler(component.kind, module, component.className, analysedDeclarations)
                // The component's CLASS being among the analysed
                // declarations is what "kosi read this" means. A class that
                // was read but declares no lifecycle override (it inherits
                // the framework's) is substantiated WITHOUT a handler —
                // "read it, it overrides nothing" is a measurement, and
                // the rule only forbids passing "did not look" off as a
                // finding.
                val classRead = flatten(component.className) in analysedFlat
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
                        substantiated = classRead || lifecycle.isNotEmpty(),
                    ),
                )
            }
        }
        return out
    }

    private fun lifecycleHandler(
        kind: String,
        module: KirModule,
        className: String,
        analysedDeclarations: Set<String>,
    ): String {
        val methodNames = when (kind) {
            "activity", "activity-alias" -> listOf("onCreate")
            "service" -> listOf("onStartCommand", "onCreate")
            "receiver" -> listOf("onReceive")
            "provider" -> listOf("query")
            else -> return ""
        }
        val flatClass = flatten(className)
        val simple = flatClass.substringAfterLast('.')
        for (methodName in methodNames) {
            val found = module.functions.firstOrNull { fn ->
                fn.enclosingClass != null && fn.canonicalName.endsWith(".$methodName") && (
                    fn.enclosingClass == simple ||
                        flatten(fn.canonicalName).startsWith("$flatClass.") ||
                        flatClass.endsWith("." + flatten(fn.enclosingClass!!))
                    )
            } ?: continue
            return found.canonicalName
        }
        // The KIR holds Kotlin only, so a Java component's lifecycle
        // method was invisible here and a Java-only Android module reported
        // every component with an empty handler. The declaration table
        // holds both languages; it is the same fact, read where it exists.
        for (methodName in methodNames) {
            val exact = "$className.$methodName"
            if (exact in analysedDeclarations) return exact
            val found = analysedDeclarations.firstOrNull { flatten(it) == flatten(exact) } ?: continue
            return found
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
     * The DEPLOYMENT base path a framework's routes are served under, from
     * its own [io.cdxgen.kosi.models.FrameworkModel.basePathKeys]: each group
     * is a set of alternatives (first key set wins), and the groups COMPOSE
     * in order — Spring MVC serves `server.servlet.context-path` +
     * `spring.mvc.servlet.path` + the mapping; Quarkus `quarkus.http.root-path`
     * + (`quarkus.rest.path` or `@ApplicationPath`) + the resource path. A
     * key belongs to ITS framework: a Micronaut context path is not a gRPC
     * or Azure prefix, which one repo-wide first-match list made it.
     * [APPLICATION_PATH_TOKEN] in a group stands for the framework's
     * `applicationPathAnnotations` value, consulted after the group's keys
     * (the property takes precedence over the annotation).
     */
    internal fun deploymentBasePath(
        framework: io.cdxgen.kosi.models.FrameworkModel,
        table: ConfigResolver.ConfigTable,
        applicationPath: () -> String? = { null },
    ): String {
        var base = ""
        for (group in framework.basePathKeys) {
            val value = group.firstNotNullOfOrNull { key ->
                if (key == APPLICATION_PATH_TOKEN) applicationPath()
                else table[key]?.value?.trim()?.takeIf { it.isNotEmpty() && it != "/" }
            }
            if (value != null) base = joinPaths(base, value)
        }
        return base
    }

    const val APPLICATION_PATH_TOKEN = "@applicationPath"

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

    // Keyed by the `const val` NAME — deliberately name-unique: a
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
