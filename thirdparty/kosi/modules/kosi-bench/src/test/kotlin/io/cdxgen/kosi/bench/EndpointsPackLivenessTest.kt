package io.cdxgen.kosi.bench

import io.cdxgen.kosi.corpus.CorpusManifest
import io.cdxgen.kosi.endpoints.Endpoints
import io.cdxgen.kosi.front.Analyzer
import io.cdxgen.kosi.models.EndpointModels
import io.cdxgen.kosi.models.EndpointsPack
import io.cdxgen.kosi.models.FrameworkModel
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * P19 §4: the R63 gate the pack never had. "A capability no fixture
 * exercises does not exist" was argued per defect until now (R63, R80, the
 * P18 subRouter swap) — this check makes it mechanical: for EVERY entry the
 * pack carries, remove it, re-run endpoint detection over every bundled
 * fixture, and classify:
 *
 *  - LIVE — some fixture's detection RESULT changed: endpoints, services,
 *    URLs, source handlers or the config counts, compared whole so the
 *    verdict cannot be an artefact of which fields the gate looked at.
 *    The entry earns its place.
 *  - ALIAS-COVERED — removing the entry alone changes nothing, but
 *    removing its whole NAME-CLASS (same channel, same pattern last
 *    segment) does: a generation spelling beside its twin
 *    (`io.ktor.routing.get` vs `io.ktor.server.routing.get`). The class is
 *    load-bearing; this spelling is untested on fixtures. Printed, never
 *    silently passed.
 *  - INERT — nothing changes however it is removed. An inert entry either
 *    carries a RECORDED REASON ([inertAllowance] — the §0 exit, one line,
 *    reviewed in diff) or fails the gate.
 *
 * Removal is by data-class IDENTITY, not list index, so single entries and
 * whole name-classes compose without index drift. The front-end analysis
 * runs ONCE per fixture (the capture hook in [Analyzer]); the per-entry
 * loop re-runs only [Endpoints.analyze] over the captured
 * module/annotations/config, which is what makes a ~330-entry sweep over
 * the bundled fixtures a test rather than a night.
 */
class EndpointsPackLivenessTest {

    private val repoRoot: Path = run {
        var current: Path? = Path.of("").toAbsolutePath()
        while (current != null) {
            if (Files.isRegularFile(current.resolve("corpus.toml"))) return@run current
            current = current.parent
        }
        error("corpus.toml not found upward from the working directory")
    }

    private val bundledTiers = setOf("fixtures", "frameworks", "crypto", "async", "vuln")

    /** One removable pack entry: its id, its name-class key, and an identity-based removal. */
    private data class Removable(
        val id: String,
        val key: String,
        val channel: String,
        val remove: (EndpointsPack) -> EndpointsPack,
    )

    private fun <T : Any> dropFrom(list: List<T>, elem: T): List<T> = list.filterNot { it == elem }

    /**
     * [key] is the name-class (the pattern's last segment); [id] names the
     * ENTRY uniquely (the full pattern or string), so two generations of
     * the same builder share a class but not an id.
     */
    private fun <T : Any> frameworkEntry(fw: FrameworkModel, channel: String, elem: T, key: String, id: String): Removable =
        Removable(
            id = "${fw.id}.$channel[$id]",
            key = key,
            channel = "${fw.id}.$channel",
        ) { pack ->
            pack.copy(frameworks = pack.frameworks.map { f -> alter(f, fw.id, channel, elem) })
        }

    /** Rebuild [f] with [elem] dropped from [channel] when [f] is the framework being altered. */
    private fun alter(f: FrameworkModel, id: String, channel: String, elem: Any): FrameworkModel {
        if (f.id != id) return f

        @Suppress("UNCHECKED_CAST")
        fun <T : Any> drop(getter: (FrameworkModel) -> List<T>, setter: (FrameworkModel, List<T>) -> FrameworkModel): FrameworkModel =
            setter(f, dropFrom(getter(f), elem as T))
        return when (channel) {
            "dslFunctions" -> drop({ it.dslFunctions }, { x, l -> x.copy(dslFunctions = l) })
            "contextReaders" -> drop({ it.contextReaders }, { x, l -> x.copy(contextReaders = l) })
            "mappingAnnotations" -> drop({ it.mappingAnnotations }, { x, l -> x.copy(mappingAnnotations = l) })
            "parameterAnnotations" -> drop({ it.parameterAnnotations }, { x, l -> x.copy(parameterAnnotations = l) })
            "mediaAnnotations" -> drop({ it.mediaAnnotations }, { x, l -> x.copy(mediaAnnotations = l) })
            "authenticationAnnotations" -> drop({ it.authenticationAnnotations }, { x, l -> x.copy(authenticationAnnotations = l) })
            "classMarkers" -> drop({ it.classMarkers }, { x, l -> x.copy(classMarkers = l) })
            "securityConstructors" -> drop({ it.securityConstructors }, { x, l -> x.copy(securityConstructors = l) })
            "handlerMethodNames" -> drop({ it.handlerMethodNames }, { x, l -> x.copy(handlerMethodNames = l) })
            "authHandlerFactories" -> drop({ it.authHandlerFactories }, { x, l -> x.copy(authHandlerFactories = l) })
            "repositoryMethods" -> drop({ it.repositoryMethods }, { x, l -> x.copy(repositoryMethods = l) })
            "repositorySupertypes" -> drop({ it.repositorySupertypes }, { x, l -> x.copy(repositorySupertypes = l) })
            "manifestComponents" -> drop({ it.manifestComponents }, { x, l -> x.copy(manifestComponents = l) })
            "supertypeMarkers" -> drop({ it.supertypeMarkers }, { x, l -> x.copy(supertypeMarkers = l) })
            "supertypeSuffixes" -> drop({ it.supertypeSuffixes }, { x, l -> x.copy(supertypeSuffixes = l) })
            "pathPrefixAnnotations" -> drop({ it.pathPrefixAnnotations }, { x, l -> x.copy(pathPrefixAnnotations = l) })
            "classMappingAnnotations" -> drop({ it.classMappingAnnotations }, { x, l -> x.copy(classMappingAnnotations = l) })
            "dependencyMarkers" -> drop({ it.dependencyMarkers }, { x, l -> x.copy(dependencyMarkers = l) })
            "bindFunctions" -> drop({ it.bindFunctions }, { x, l -> x.copy(bindFunctions = l) })
            "authenticationDsl" -> drop({ it.authenticationDsl }, { x, l -> x.copy(authenticationDsl = l) })
            "applicationPathAnnotations" -> drop({ it.applicationPathAnnotations }, { x, l -> x.copy(applicationPathAnnotations = l) })
            "mediaDsl" -> drop({ it.mediaDsl }, { x, l -> x.copy(mediaDsl = l) })
            "contractDsl" -> drop({ it.contractDsl }, { x, l -> x.copy(contractDsl = l) })
            "routeMetaDsl" -> drop({ it.routeMetaDsl }, { x, l -> x.copy(routeMetaDsl = l) })
            "resourceAnnotations" -> drop({ it.resourceAnnotations }, { x, l -> x.copy(resourceAnnotations = l) })
            "implicitBasePathKeys" -> drop({ it.implicitBasePathKeys }, { x, l -> x.copy(implicitBasePathKeys = l) })
            "handlerDsl" -> drop({ it.handlerDsl }, { x, l -> x.copy(handlerDsl = l) })
            "mountFunctions" -> drop({ it.mountFunctions }, { x, l -> x.copy(mountFunctions = l) })
            "implicitRoutes" -> drop({ it.implicitRoutes }, { x, l -> x.copy(implicitRoutes = l) })
            // P27 §2: the three channels that state a framework's ARGUMENT
            // BINDING rule (Spring's "any other argument" fallback).
            "contextParameterTypes" -> drop({ it.contextParameterTypes }, { x, l -> x.copy(contextParameterTypes = l) })
            "nonInputAnnotations" -> drop({ it.nonInputAnnotations }, { x, l -> x.copy(nonInputAnnotations = l) })
            "simpleParameterTypes" -> drop({ it.simpleParameterTypes }, { x, l -> x.copy(simpleParameterTypes = l) })
            // Never a silent no-op: a channel this arm does not know would
            // remove NOTHING, and every one of its entries would then be
            // reported inert — the sweep would quietly stop covering a
            // whole channel the moment the pack grew one
            // ([everyPackChannelIsSwept] fails first, in the same build).
            else -> error("liveness sweep does not know channel '$channel' — add it to alter() and channelRemovables()")
        }
    }

    /**
     * The sweep covers every list-shaped channel [FrameworkModel] has.
     * Without this, a channel added to the model and forgotten here is
     * invisible twice over: [channelRemovables] never enumerates its
     * entries, so they are neither live nor inert — they are unswept, and
     * the gate's own count says nothing about them. Reflection over the
     * data class's getters is what makes "every channel" mean the model's
     * channels rather than this file's memory of them.
     */
    @Test
    fun everyPackChannelIsSwept() {
        val empty = FrameworkModel(id = "probe", kind = "dsl")
        val channels = FrameworkModel::class.java.methods
            .filter { it.parameterCount == 0 && List::class.java.isAssignableFrom(it.returnType) && it.name.startsWith("get") }
            .map { it.name.removePrefix("get").replaceFirstChar { c -> c.lowercaseChar() } }
            .toSortedSet()
        assertTrue(channels.isNotEmpty(), "no list-shaped channels found on FrameworkModel")
        // alter() errors on an unknown channel; a known one drops nothing
        // from an empty model and returns it unchanged.
        channels.forEach { channel -> alter(empty, empty.id, channel, Any()) }
        println("pack-liveness: ${channels.size} pack channels swept — ${channels.joinToString(",")}")
    }

    private fun channelRemovables(fw: FrameworkModel): List<Removable> = buildList {
        fun <T : Any> entry(channel: String, elem: T, key: String, id: String) = add(frameworkEntry(fw, channel, elem, key, id))
        fw.dslFunctions.forEach { entry("dslFunctions", it, it.pattern.substringAfterLast('.'), it.pattern) }
        fw.contextReaders.forEach { entry("contextReaders", it, it.pattern.substringAfterLast('.'), it.pattern) }
        fw.mappingAnnotations.forEach { entry("mappingAnnotations", it, it.pattern.substringAfterLast('.'), it.pattern) }
        fw.parameterAnnotations.forEach { entry("parameterAnnotations", it, it.pattern.substringAfterLast('.'), it.pattern) }
        fw.mediaAnnotations.forEach { entry("mediaAnnotations", it, it.pattern.substringAfterLast('.'), it.pattern) }
        fw.authenticationAnnotations.forEach { entry("authenticationAnnotations", it, it.pattern.substringAfterLast('.'), it.pattern) }
        fw.classMarkers.forEach { entry("classMarkers", it, it.substringAfterLast('.'), it) }
        fw.securityConstructors.forEach { entry("securityConstructors", it, it.substringAfterLast('.'), it) }
        fw.handlerMethodNames.forEach { entry("handlerMethodNames", it, it.name, it.name) }
        fw.authHandlerFactories.forEach { entry("authHandlerFactories", it, it.substringAfterLast('.'), it) }
        fw.repositoryMethods.forEach { entry("repositoryMethods", it, it, it) }
        // P27 §2: the argument-binding rule's three channels.
        fw.contextParameterTypes.forEach { entry("contextParameterTypes", it, it.substringAfterLast('.'), it) }
        fw.nonInputAnnotations.forEach { entry("nonInputAnnotations", it, it.substringAfterLast('.'), it) }
        fw.simpleParameterTypes.forEach { entry("simpleParameterTypes", it, it.substringAfterLast('.'), it) }
        fw.repositorySupertypes.forEach { entry("repositorySupertypes", it, it.substringAfterLast('.'), it) }
        fw.manifestComponents.forEach { entry("manifestComponents", it, it, it) }
        fw.supertypeMarkers.forEach { entry("supertypeMarkers", it, it, it) }
        fw.supertypeSuffixes.forEach { entry("supertypeSuffixes", it, it, it) }
        fw.pathPrefixAnnotations.forEach { entry("pathPrefixAnnotations", it, it.substringAfterLast('.'), it) }
        fw.classMappingAnnotations.forEach { entry("classMappingAnnotations", it, it.substringAfterLast('.'), it) }
        fw.dependencyMarkers.forEach { entry("dependencyMarkers", it, it, it) }
        fw.bindFunctions.forEach { entry("bindFunctions", it, it.pattern, it.pattern) }
        fw.authenticationDsl.forEach { entry("authenticationDsl", it, it.substringAfterLast('.'), it) }
        fw.applicationPathAnnotations.forEach { entry("applicationPathAnnotations", it, it.substringAfterLast('.'), it) }
        fw.mediaDsl.forEach { entry("mediaDsl", it, it.pattern.substringAfterLast('.'), it.pattern) }
        fw.contractDsl.forEach { entry("contractDsl", it, it.substringAfterLast('.'), it) }
        fw.routeMetaDsl.forEach { entry("routeMetaDsl", it, it.substringAfterLast('.'), it) }
        fw.resourceAnnotations.forEach { entry("resourceAnnotations", it, it.substringAfterLast('.'), it) }
        fw.implicitBasePathKeys.forEach { entry("implicitBasePathKeys", it, it, it) }
        fw.handlerDsl.forEach { entry("handlerDsl", it, it.substringAfterLast('.'), it) }
        fw.mountFunctions.forEach { entry("mountFunctions", it, it.substringAfterLast('.'), it) }
        fw.implicitRoutes.forEach { entry("implicitRoutes", it, it.path, it.path) }
    }

    private fun packRemovables(pack: EndpointsPack): List<Removable> =
        pack.frameworks.flatMap { channelRemovables(it) } +
            pack.outbound.map { Removable("outbound[${it.pattern}]", it.pattern, "outbound") { p -> p.copy(outbound = dropFrom(p.outbound, it)) } } +
            pack.configReaders.map { Removable("configReaders[${it.pattern}]", it.pattern, "configReaders") { p -> p.copy(configReaders = dropFrom(p.configReaders, it)) } }

    private fun detect(
        root: Path,
        capture: Analyzer.EndpointCapture,
        pack: EndpointsPack,
    ): Endpoints.Result = Endpoints.analyze(
        capture.module, root, capture.sourceTexts, capture.annotationValues,
        Endpoints.Attribution(emptyMap(), emptyMap()), includeManifests = true,
        dependencyCoordinates = capture.dependencyCoordinates, pack = pack,
    )

    @Test
    fun everyPackEntryIsLiveAliasCoveredOrRecorded() {
        val manifest = CorpusManifest.load(repoRoot.resolve("corpus.toml"))
        val entries = manifest.entries.filter { it.tier in bundledTiers && it.path != null }
        assertTrue(entries.isNotEmpty(), "no bundled corpus entries found for the liveness sweep")
        val builtin = EndpointModels.loadBuiltin()
        val removables = packRemovables(builtin)

        // One front-end analysis per fixture; a fixture whose baseline
        // carries no endpoint/service evidence cannot distinguish pack
        // entries and is skipped loudly (counted, never hidden).
        data class Captured(val root: Path, val capture: Analyzer.EndpointCapture, val baseline: Endpoints.Result)
        val captured = mutableListOf<Captured>()
        var withoutEvidence = 0
        for (entry in entries) {
            val root = repoRoot.resolve(entry.path!!)
            var held: Analyzer.EndpointCapture? = null
            Analyzer.analyze(
                root,
                AnalyzeOptions(backend = Backend.RESOLVED, classpathFile = entry.classpathFile),
                commit = "liveness",
                endpointCapture = { held = it },
            )
            val cap = held ?: continue
            val baseline = detect(root, cap, builtin)
            if (baseline.apiEndpoints.isEmpty() && baseline.services.isEmpty() &&
                baseline.urls.isEmpty() && baseline.sourceHandlers.isEmpty()
            ) {
                withoutEvidence++
                continue
            }
            captured += Captured(root, cap, baseline)
        }
        assertTrue(captured.isNotEmpty(), "no fixture produced endpoint evidence for the sweep")

        fun changesSomeFixture(minus: EndpointsPack): Set<String> {
            val hitters = sortedSetOf<String>()
            for (c in captured) {
                // The WHOLE result, not three of its six fields: an entry
                // that only seeds handler inputs is live on
                // `sourceHandlers`, and comparing the URL-shaped arrays
                // alone reported it INERT — which is how forty context
                // readers and parameter annotations came to carry a
                // recorded reason instead of a verdict (P19 review). A
                // gate that cannot see a surface must not pronounce on it.
                if (detect(c.root, c.capture, minus) != c.baseline) hitters.add(c.root.fileName.toString())
            }
            return hitters
        }

        val live = HashMap<String, Set<String>>()
        for (removable in removables) {
            val hitters = changesSomeFixture(removable.remove(builtin))
            if (hitters.isNotEmpty()) live[removable.id] = hitters
        }

        // The honest alias class is the pattern's LAST SEGMENT within one
        // channel: `io.ktor.routing.get` beside `io.ktor.server.routing.get`
        // are the same builder in two generations, and an entry is
        // ALIAS-COVERED only when removing its whole name-class changes a
        // report while removing it alone does not. A channel merely being
        // live proves nothing about an unrelated name in it.
        val aliasCovered = mutableSetOf<String>()
        val byClass = removables.groupBy { it.channel to it.key }
        for ((_, group) in byClass) {
            if (group.any { it.id in live }) continue
            val classRemoval = group.fold(builtin) { pack, r -> r.remove(pack) }
            if (changesSomeFixture(classRemoval).isNotEmpty()) group.forEach { aliasCovered += it.id }
        }

        val allowance = inertAllowance()
        val inert = removables.filter { it.id !in live && it.id !in aliasCovered }
        val unexplained = inert.filter { allowance[it.id] == null }
        println(
            "pack-liveness: ${live.size}/${removables.size} entries live over ${captured.size} evidence-bearing fixtures; " +
                "${aliasCovered.size} alias-covered (name-class live, this spelling untested); " +
                "${inert.size} inert, of which ${inert.size - unexplained.size} carry a recorded reason; " +
                "$withoutEvidence fixture(s) carried no endpoint evidence and were skipped",
        )
        live.entries.sortedBy { it.key }.forEach { (id, fixtures) -> println("pack-liveness: LIVE $id <- ${fixtures.joinToString(",")}") }
        aliasCovered.sorted().forEach { println("pack-liveness: ALIAS-COVERED $it (name-class live via a same-name sibling)") }
        inert.sortedBy { it.id }.forEach { r -> println("pack-liveness: INERT ${r.id} — ${allowance[r.id] ?: "NO RECORDED REASON"}") }
        assertTrue(
            unexplained.isEmpty(),
            "pack entries no bundled fixture exercises and nobody recorded a reason for (R63 — add a fixture, remove the entry, or record the reason in inertAllowance()):\n" +
                unexplained.joinToString("\n") { it.id },
        )
    }

    /**
     * The recorded reasons for entries left in place knowingly — the §0
     * exit for symbols whose exercise lives outside the bundled fixtures
     * (pinned corpus repos, generation spellings a same-name sibling
     * already covers on fixtures). One line each; a reason that stops
     * being true (the entry gains a fixture) is silently fine — the entry
     * becomes LIVE and the reason is dead text the next sweep prints.
     */
    private fun inertAllowance(): Map<String, String> = mapOf(
        "graphql.contextParameterTypes[graphql.schema.DataFetchingEnvironment]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.contextParameterTypes[graphql.GraphQLContext]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.contextParameterTypes[graphql.schema.DataFetchingFieldSelectionSet]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.contextParameterTypes[org.dataloader.DataLoader]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.contextParameterTypes[java.util.Locale]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.contextParameterTypes[java.security.Principal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.contextParameterTypes[org.springframework.data.domain.Sort]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "android.contextParameterTypes[android.content.Context]" to
            "P28 §2: consumed by the FLOW ENGINE's parameter seeding under handlerInput=all, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The rule it configures is pinned by fixtures/cloud-and-messaging (lambda Context arm, restore-proven: dropping the aws-lambda row makes ContextOnlyHandler report a flow the want-not forbids) and fixtures/grpc-service (observer arm, count=1 pin); the android row applies the same code path to onReceive(Context, Intent), whose real signature fixtures/android-manifest-app carries. Transcribed from developer.android.com's BroadcastReceiver reference, not from memory.",
        "aws-lambda.contextParameterTypes[com.amazonaws.services.lambda.runtime.Context]" to
            "P28 §2: consumed by the FLOW ENGINE's parameter seeding under handlerInput=all, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/cloud-and-messaging's ContextOnlyHandler: drop this entry and the handler reports a flow its want-not forbids (restore-proven). AWS Lambda's own Java docs: the context object 'is the second argument of the main handler function'.",
        "grpc.contextParameterTypes[io.grpc.stub.StreamObserver]" to
            "P28 §2: consumed by the FLOW ENGINE's parameter seeding under handlerInput=all, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/grpc-service's ObserverGreeterService: the count=1 flow want fails if the observer seeds (restore-proven the same way). grpc.io's generated-code docs show the observer as the framework's response channel.",
        "graphql.contextParameterTypes[org.springframework.graphql.data.query.ScrollSubrange]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.contextParameterTypes[org.springframework.data.domain.Subrange]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.nonInputAnnotations[org.springframework.security.core.annotation.AuthenticationPrincipal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.nonInputAnnotations[org.springframework.graphql.data.method.annotation.ContextValue]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.nonInputAnnotations[org.springframework.graphql.data.method.annotation.LocalContextValue]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Boolean]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Byte]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Char]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Short]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Int]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Long]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Float]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Double]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.String]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.CharSequence]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[kotlin.Enum]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Boolean]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Byte]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Character]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Short]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Integer]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Long]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Float]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Double]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.String]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.CharSequence]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Number]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Enum]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.lang.Class]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.math.BigDecimal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.math.BigInteger]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.util.Date]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.util.UUID]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.util.Locale]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.net.URI]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.net.URL]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.Instant]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.LocalDate]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.LocalDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.LocalTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.OffsetDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.ZonedDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.Duration]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "graphql.simpleParameterTypes[java.time.Temporal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/graphql-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.contextParameterTypes[io.micronaut.http.HttpRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.contextParameterTypes[io.micronaut.http.HttpResponse]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.contextParameterTypes[io.micronaut.http.BasicAuth]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.contextParameterTypes[io.micronaut.security.authentication.Authentication]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Boolean]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Byte]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Char]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Short]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Int]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Long]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Float]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Double]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.String]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.CharSequence]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[kotlin.Enum]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Boolean]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Byte]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Character]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Short]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Integer]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Long]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Float]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Double]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.String]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.CharSequence]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Number]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Enum]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.lang.Class]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.math.BigDecimal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.math.BigInteger]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.util.Date]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.util.UUID]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.util.Locale]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.net.URI]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.net.URL]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.Instant]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.LocalDate]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.LocalDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.LocalTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.OffsetDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.ZonedDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.Duration]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "micronaut.simpleParameterTypes[java.time.Temporal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/micronaut-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.core.UriInfo]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.core.HttpHeaders]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.core.SecurityContext]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.core.Request]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.core.Application]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.core.Configuration]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.ext.Providers]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.container.ResourceContext]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.sse.Sse]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[jakarta.ws.rs.sse.SseEventSink]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.core.UriInfo]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.core.HttpHeaders]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.core.SecurityContext]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.core.Request]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.core.Application]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.core.Configuration]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.ext.Providers]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.contextParameterTypes[javax.ws.rs.container.ResourceContext]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.nonInputAnnotations[jakarta.ws.rs.core.Context]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.nonInputAnnotations[javax.ws.rs.core.Context]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.nonInputAnnotations[jakarta.ws.rs.container.Suspended]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "quarkus.nonInputAnnotations[javax.ws.rs.container.Suspended]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/jaxrs-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-messaging.contextParameterTypes[org.springframework.messaging.Message]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/messaging-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-messaging.contextParameterTypes[org.springframework.messaging.MessageHeaders]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/messaging-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-messaging.contextParameterTypes[org.springframework.messaging.support.MessageHeaderAccessor]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/messaging-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-messaging.contextParameterTypes[org.springframework.messaging.simp.SimpMessageHeaderAccessor]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/messaging-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-messaging.contextParameterTypes[org.springframework.messaging.simp.stomp.StompHeaderAccessor]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/messaging-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-messaging.contextParameterTypes[java.security.Principal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/messaging-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.context.request.WebRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.context.request.NativeWebRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[jakarta.servlet.ServletRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[jakarta.servlet.ServletResponse]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[jakarta.servlet.http.HttpServletRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[jakarta.servlet.http.HttpServletResponse]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[jakarta.servlet.http.HttpSession]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[jakarta.servlet.http.PushBuilder]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[javax.servlet.ServletRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[javax.servlet.ServletResponse]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[javax.servlet.http.HttpServletRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[javax.servlet.http.HttpServletResponse]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[javax.servlet.http.HttpSession]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.security.Principal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.http.HttpMethod]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.util.Locale]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.util.TimeZone]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.time.ZoneId]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.io.InputStream]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.io.Reader]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.io.OutputStream]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.io.Writer]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[java.util.Map]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[kotlin.collections.Map]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[kotlin.collections.MutableMap]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.ui.Model]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.ui.ModelMap]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.servlet.mvc.support.RedirectAttributes]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.validation.Errors]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.validation.BindingResult]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.bind.support.SessionStatus]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.util.UriComponentsBuilder]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.bind.WebDataBinder]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.server.ServerWebExchange]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.http.server.reactive.ServerHttpRequest]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.http.server.reactive.ServerHttpResponse]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.contextParameterTypes[org.springframework.web.server.WebSession]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.nonInputAnnotations[org.springframework.security.core.annotation.AuthenticationPrincipal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.nonInputAnnotations[org.springframework.security.core.annotation.CurrentSecurityContext]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.nonInputAnnotations[org.springframework.web.bind.annotation.SessionAttribute]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.nonInputAnnotations[org.springframework.web.bind.annotation.RequestAttribute]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.nonInputAnnotations[org.springframework.beans.factory.annotation.Autowired]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.nonInputAnnotations[org.springframework.beans.factory.annotation.Value]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Boolean]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Byte]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Char]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Short]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Int]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Long]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Float]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Double]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.String]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.CharSequence]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[kotlin.Enum]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Boolean]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Byte]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Character]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Short]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Integer]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Long]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Float]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Double]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.String]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.CharSequence]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Number]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Enum]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.lang.Class]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.math.BigDecimal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.math.BigInteger]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.util.Date]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.util.UUID]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.util.Locale]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.net.URI]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.net.URL]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.Instant]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.LocalDate]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.LocalDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.LocalTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.OffsetDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.ZonedDateTime]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.Duration]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "spring-mvc.simpleParameterTypes[java.time.Temporal]" to
            "P27 §2: consumed by the FLOW ENGINE's parameter seeding, not by endpoint detection, so this sweep — which diffs Endpoints.Result — structurally cannot see it. The gate that does is fixtures/spring-argument-binding, whose want-nots are one per entry: drop this entry and its handler reports a finding. Transcribed from the framework's own documentation, not from memory.",
        "grpc.supertypeMarkers[GrpcKt]" to "jointly load-bearing with its Grpc twin: either substring carries the marker conjunct, and the grpcbad negative pins that SOMETHING must (a homonym ImplBase must be refused)",
        "grpc.supertypeMarkers[Grpc]" to "jointly load-bearing with its GrpcKt twin: either substring carries the marker conjunct, and the grpcbad negative pins that SOMETHING must (a homonym ImplBase must be refused)",
        "azure-functions.parameterAnnotations[com.microsoft.azure.functions.annotation.HttpTrigger]" to "kind=body parameter annotation: annotatedParameters() reads only the path/query kinds and sourceHandlers carries no per-parameter category, so neither `kind` nor `category` has a consumer here \u2014 the entry is a declaration waiting for one (P19 review), not a capability",
        "azure-functions.parameterAnnotations[com.microsoft.azure.functions.annotation.QueueTrigger]" to "kind=body parameter annotation: annotatedParameters() reads only the path/query kinds and sourceHandlers carries no per-parameter category, so neither `kind` nor `category` has a consumer here \u2014 the entry is a declaration waiting for one (P19 review), not a capability",
        "configReaders[com.typesafe.config.Config.getString]" to "config-table reader beside the exercised java.util.Properties row; one config-keyed route would make it live",
        "configReaders[io.ktor.server.config.ApplicationConfig.property]" to "config-table reader beside the exercised java.util.Properties row; one config-keyed route would make it live",
        "configReaders[java.lang.System.getProperty]" to "config-table reader beside the exercised java.util.Properties row; one config-keyed route would make it live",
        "configReaders[org.springframework.core.env.Environment.getProperty]" to "config-table reader beside the exercised java.util.Properties row; one config-keyed route would make it live",
        "graphql.classMarkers[org.springframework.stereotype.Controller]" to "plain-@Controller marker copy: this framework's endpoints come through its own mapping annotations; graphql's copy is the exercised one (cloud-and-messaging)",
        "graphql.parameterAnnotations[org.springframework.graphql.data.method.annotation.Argument]" to "kind=body parameter annotation: annotatedParameters() reads only the path/query kinds and sourceHandlers carries no per-parameter category, so neither `kind` nor `category` has a consumer here \u2014 the entry is a declaration waiting for one (P19 review), not a capability",
        "http4k.contextReaders[org.http4k.core.Request.bodyString]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "http4k.contextReaders[org.http4k.core.Request.cookie]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "http4k.contextReaders[org.http4k.core.Request.header]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "http4k.contextReaders[org.http4k.core.Request.query]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "http4k.contextReaders[org.http4k.routing.path]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.bodyAsClass]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.body]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.cookie]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.formParam]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.formParams]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.header]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.pathParam]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.queryParam]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.contextReaders[io.javalin.http.Context.queryParams]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "javalin.dslFunctions[io.javalin.Javalin.delete]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "javalin.dslFunctions[io.javalin.Javalin.patch]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "javalin.dslFunctions[io.javalin.Javalin.post]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "javalin.dslFunctions[io.javalin.Javalin.put]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "javalin.dslFunctions[io.javalin.apibuilder.ApiBuilder.get]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "javalin.dslFunctions[io.javalin.apibuilder.ApiBuilder.path]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "javalin.dslFunctions[io.javalin.apibuilder.ApiBuilder.post]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "ktor.contextReaders[io.ktor.application.ApplicationCall.parameters]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.ApplicationRequest.cookies]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.ApplicationRequest.headers]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.ApplicationRequest.queryParameters]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.header]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.queryString]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.receiveParameters]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.receiveText]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.request.receive]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.request.ApplicationRequest.cookies]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.request.ApplicationRequest.headers]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.request.header]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.request.queryString]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.request.receiveParameters]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.request.receiveText]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.request.receive]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.contextReaders[io.ktor.server.routing.RoutingCall.pathParameters]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "ktor.dslFunctions[io.ktor.routing.accept]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "ktor.dslFunctions[io.ktor.routing.route]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "ktor.dslFunctions[io.ktor.server.routing.post]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "ktor.dslFunctions[io.ktor.server.routing.route]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "micronaut.authenticationAnnotations[io.micronaut.security.Secured]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "micronaut.authenticationAnnotations[jakarta.annotation.security.RolesAllowed]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "micronaut.authenticationAnnotations[javax.annotation.security.RolesAllowed]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "micronaut.mappingAnnotations[io.micronaut.http.annotation.Delete]" to "recorded unexercised spelling (P19 §4 sweep)",
        "micronaut.mappingAnnotations[io.micronaut.http.annotation.Patch]" to "recorded unexercised spelling (P19 §4 sweep)",
        "micronaut.mappingAnnotations[io.micronaut.http.annotation.Put]" to "recorded unexercised spelling (P19 §4 sweep)",
        "micronaut.parameterAnnotations[io.micronaut.http.annotation.Body]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "micronaut.parameterAnnotations[io.micronaut.http.annotation.CookieValue]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "micronaut.parameterAnnotations[io.micronaut.http.annotation.Header]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "micronaut.parameterAnnotations[io.micronaut.http.annotation.Part]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "micronaut.parameterAnnotations[io.micronaut.http.annotation.PathVariable]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "micronaut.parameterAnnotations[io.micronaut.http.annotation.QueryValue]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.applicationPathAnnotations[jakarta.ws.rs.ApplicationPath]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "quarkus.authenticationAnnotations[jakarta.annotation.security.DenyAll]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "quarkus.authenticationAnnotations[javax.annotation.security.DenyAll]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "quarkus.authenticationAnnotations[javax.annotation.security.RolesAllowed]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "quarkus.mappingAnnotations[jakarta.ws.rs.DELETE]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "quarkus.mappingAnnotations[jakarta.ws.rs.PATCH]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "quarkus.mappingAnnotations[jakarta.ws.rs.PUT]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "quarkus.mappingAnnotations[javax.ws.rs.DELETE]" to "the javax generation beside its exercised jakarta twin (P14 modelled both; the bundled fixtures pin the jakarta half)",
        "quarkus.mappingAnnotations[javax.ws.rs.POST]" to "the javax generation beside its exercised jakarta twin (P14 modelled both; the bundled fixtures pin the jakarta half)",
        "quarkus.mappingAnnotations[javax.ws.rs.PUT]" to "the javax generation beside its exercised jakarta twin (P14 modelled both; the bundled fixtures pin the jakarta half)",
        "quarkus.mediaAnnotations[javax.ws.rs.Consumes]" to "the javax generation beside its exercised jakarta twin (P14 modelled both; the bundled fixtures pin the jakarta half)",
        "quarkus.mediaAnnotations[javax.ws.rs.Produces]" to "the javax generation beside its exercised jakarta twin (P14 modelled both; the bundled fixtures pin the jakarta half)",
        "quarkus.parameterAnnotations[jakarta.ws.rs.BeanParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[jakarta.ws.rs.CookieParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[jakarta.ws.rs.FormParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[jakarta.ws.rs.HeaderParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[jakarta.ws.rs.MatrixParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[jakarta.ws.rs.PathParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[jakarta.ws.rs.QueryParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[javax.ws.rs.BeanParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[javax.ws.rs.CookieParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[javax.ws.rs.FormParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[javax.ws.rs.HeaderParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[javax.ws.rs.MatrixParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[javax.ws.rs.PathParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "quarkus.parameterAnnotations[javax.ws.rs.QueryParam]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "servlet.classMappingAnnotations[jakarta.servlet.annotation.WebFilter]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "servlet.classMappingAnnotations[jakarta.servlet.annotation.WebServlet]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "servlet.classMarkers[jakarta.servlet.annotation.WebFilter]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "servlet.classMarkers[jakarta.servlet.annotation.WebServlet]" to "jakarta spelling recorded beside its javax twin; the exercised JAX-RS rows live in endpoint-media-auth/framework-generations",
        "servlet.classMarkers[javax.servlet.annotation.WebFilter]" to "the javax generation beside its exercised jakarta twin (P14 modelled both; the bundled fixtures pin the jakarta half)",
        "servlet.classMarkers[javax.servlet.annotation.WebServlet]" to "the javax generation beside its exercised jakarta twin (P14 modelled both; the bundled fixtures pin the jakarta half)",
        "servlet.contextReaders[jakarta.servlet.ServletRequest.getParameter]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "servlet.contextReaders[jakarta.servlet.http.HttpServletRequest.getHeader]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "servlet.contextReaders[jakarta.servlet.http.HttpServletRequest.getParameterValues]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "servlet.contextReaders[jakarta.servlet.http.HttpServletRequest.getParameter]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "servlet.contextReaders[javax.servlet.ServletRequest.getParameter]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "servlet.contextReaders[javax.servlet.http.HttpServletRequest.getHeader]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "servlet.contextReaders[javax.servlet.http.HttpServletRequest.getParameterValues]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "servlet.handlerMethodNames[doDelete]" to "servlet do-method beside the exercised doGet/doPost; one more handler in handler-input-semantics would make it live",
        "servlet.handlerMethodNames[doHead]" to "servlet do-method beside the exercised doGet/doPost; one more handler in handler-input-semantics would make it live",
        "servlet.handlerMethodNames[doOptions]" to "servlet do-method beside the exercised doGet/doPost; one more handler in handler-input-semantics would make it live",
        "servlet.handlerMethodNames[doPut]" to "servlet do-method beside the exercised doGet/doPost; one more handler in handler-input-semantics would make it live",
        "servlet.handlerMethodNames[service]" to "servlet do-method beside the exercised doGet/doPost; one more handler in handler-input-semantics would make it live",
        "sparkjava.contextReaders[spark.Request.body]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "sparkjava.contextReaders[spark.Request.cookie]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "sparkjava.contextReaders[spark.Request.headers]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "sparkjava.contextReaders[spark.Request.params]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "sparkjava.contextReaders[spark.Request.queryParams]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "sparkjava.dslFunctions[spark.Spark.delete]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "sparkjava.dslFunctions[spark.Spark.get]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "sparkjava.dslFunctions[spark.Spark.path]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "sparkjava.dslFunctions[spark.Spark.post]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "sparkjava.dslFunctions[spark.Spark.put]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "spring-actuator.dependencyMarkers[spring-boot-actuator]" to "alternative coordinate spelling beside the exercised starter-actuator marker (implicit-routes)",
        "spring-messaging.parameterAnnotations[org.springframework.messaging.handler.annotation.DestinationVariable]" to "kind=body parameter annotation: annotatedParameters() reads only the path/query kinds and sourceHandlers carries no per-parameter category, so neither `kind` nor `category` has a consumer here \u2014 the entry is a declaration waiting for one (P19 review), not a capability",
        "spring-messaging.parameterAnnotations[org.springframework.messaging.handler.annotation.Header]" to "kind=body parameter annotation: annotatedParameters() reads only the path/query kinds and sourceHandlers carries no per-parameter category, so neither `kind` nor `category` has a consumer here \u2014 the entry is a declaration waiting for one (P19 review), not a capability",
        "spring-messaging.parameterAnnotations[org.springframework.messaging.handler.annotation.Payload]" to "kind=body parameter annotation: annotatedParameters() reads only the path/query kinds and sourceHandlers carries no per-parameter category, so neither `kind` nor `category` has a consumer here \u2014 the entry is a declaration waiting for one (P19 review), not a capability",
        "spring-mvc.authenticationAnnotations[jakarta.annotation.security.RolesAllowed]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "spring-mvc.authenticationAnnotations[javax.annotation.security.RolesAllowed]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "spring-mvc.authenticationAnnotations[org.springframework.security.access.annotation.Secured]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "spring-mvc.classMarkers[org.springframework.stereotype.Controller]" to "plain-@Controller marker copy: this framework's endpoints come through its own mapping annotations; graphql's copy is the exercised one (cloud-and-messaging)",
        "spring-mvc.mappingAnnotations[org.springframework.web.bind.annotation.DeleteMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mappingAnnotations[org.springframework.web.bind.annotation.PatchMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mappingAnnotations[org.springframework.web.bind.annotation.PutMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.DeleteMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.DeleteMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.PatchMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.PatchMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.PostMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.PostMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.PutMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.mediaAnnotations[org.springframework.web.bind.annotation.PutMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-mvc.parameterAnnotations[org.springframework.web.bind.annotation.CookieValue]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "spring-mvc.parameterAnnotations[org.springframework.web.bind.annotation.MatrixVariable]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "spring-mvc.parameterAnnotations[org.springframework.web.bind.annotation.ModelAttribute]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "spring-mvc.parameterAnnotations[org.springframework.web.bind.annotation.PathVariable]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "spring-mvc.parameterAnnotations[org.springframework.web.bind.annotation.RequestBody]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "spring-mvc.parameterAnnotations[org.springframework.web.bind.annotation.RequestHeader]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "spring-mvc.parameterAnnotations[org.springframework.web.bind.annotation.RequestPart]" to "parameter-annotation spelling beside the rows endpoint-parameter-semantics exercises; the body/header kinds publish nothing into the endpoints/services/urls arrays this sweep compares",
        "spring-mvc.repositorySupertypes[org.springframework.data.jpa.repository.JpaRepository]" to "spring-data supertype beside the exercised repository shape in implicit-routes",
        "spring-mvc.repositorySupertypes[org.springframework.data.repository.ListCrudRepository]" to "spring-data supertype beside the exercised repository shape in implicit-routes",
        "spring-mvc.repositorySupertypes[org.springframework.data.repository.PagingAndSortingRepository]" to "spring-data supertype beside the exercised repository shape in implicit-routes",
        "spring-mvc.repositorySupertypes[org.springframework.data.rest.core.annotation.RepositoryRestResource]" to "spring-data supertype beside the exercised repository shape in implicit-routes",
        "spring-webflux.authenticationAnnotations[jakarta.annotation.security.RolesAllowed]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "spring-webflux.authenticationAnnotations[javax.annotation.security.RolesAllowed]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "spring-webflux.authenticationAnnotations[org.springframework.security.access.annotation.Secured]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "spring-webflux.authenticationAnnotations[org.springframework.security.access.prepost.PreAuthorize]" to "auth-annotation spelling beside the exercised sibling(s) of its framework",
        "spring-webflux.contextReaders[org.springframework.web.reactive.function.server.ServerRequest.bodyToMono]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "spring-webflux.contextReaders[org.springframework.web.reactive.function.server.ServerRequest.pathVariable]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "spring-webflux.contextReaders[org.springframework.web.reactive.function.server.ServerRequest.queryParam]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "spring-webflux.dslFunctions[org.springframework.web.reactive.function.server.RouterFunctionDsl.DELETE]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "spring-webflux.dslFunctions[org.springframework.web.reactive.function.server.RouterFunctionDsl.PUT]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "spring-webflux.dslFunctions[org.springframework.web.reactive.function.server.RouterFunctionDsl.path]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.DeleteMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.DeleteMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.GetMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.GetMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.PatchMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.PatchMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.PostMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.PostMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.PutMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.PutMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.RequestMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "spring-webflux.mediaAnnotations[org.springframework.web.bind.annotation.RequestMapping]" to "media-annotation spelling beside the exercised media rows in endpoint-media-auth",
        "vertx.authHandlerFactories[io.vertx.ext.web.handler.DigestAuthHandler.create]" to "auth-handler factory beside the exercised Basic/JWT factories; one chained route in dsl-media-auth would make it live",
        "vertx.authHandlerFactories[io.vertx.ext.web.handler.OAuth2AuthHandler.create]" to "auth-handler factory beside the exercised Basic/JWT factories; one chained route in dsl-media-auth would make it live",
        "vertx.authHandlerFactories[io.vertx.ext.web.handler.OtpAuthHandler.create]" to "auth-handler factory beside the exercised Basic/JWT factories; one chained route in dsl-media-auth would make it live",
        "vertx.authHandlerFactories[io.vertx.ext.web.handler.RedirectAuthHandler.create]" to "auth-handler factory beside the exercised Basic/JWT factories; one chained route in dsl-media-auth would make it live",
        "vertx.authHandlerFactories[io.vertx.ext.web.handler.WebAuthn4JHandler.create]" to "auth-handler factory beside the exercised Basic/JWT factories; one chained route in dsl-media-auth would make it live",
        "vertx.contextReaders[io.vertx.core.http.HttpServerRequest.getCookie]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "vertx.contextReaders[io.vertx.core.http.HttpServerRequest.getFormAttribute]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "vertx.contextReaders[io.vertx.core.http.HttpServerRequest.getHeader]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "vertx.contextReaders[io.vertx.core.http.HttpServerRequest.getParam]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "vertx.contextReaders[io.vertx.ext.web.RoutingContext.body]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "vertx.contextReaders[io.vertx.ext.web.RoutingContext.pathParam]" to "context reader beside its exercised sibling; the media fixtures' handlers read them through DELEGATED functions, where transportParameters cannot see the call",
        "vertx.dslFunctions[io.vertx.ext.web.Router.delete]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
        "vertx.dslFunctions[io.vertx.ext.web.Router.put]" to "verb/nesting builder beside its exercised sibling; one more route in the framework's fixture would make it live",
    )
}
