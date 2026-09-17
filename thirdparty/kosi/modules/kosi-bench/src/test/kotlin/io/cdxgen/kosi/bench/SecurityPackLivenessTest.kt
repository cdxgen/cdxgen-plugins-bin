package io.cdxgen.kosi.bench

import io.cdxgen.kosi.corpus.CorpusManifest
import io.cdxgen.kosi.flow.TaintEngine
import io.cdxgen.kosi.front.Analyzer
import io.cdxgen.kosi.models.EndpointModels
import io.cdxgen.kosi.models.ModelPack
import io.cdxgen.kosi.models.ModelPacks
import io.cdxgen.kosi.models.PatternMatcher
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * P20 §3: the R63 gate the SECURITY pack never had. P19 built the sweep for
 * the endpoints pack and found 210 of ~330 entries inert; the security pack
 * — sources, sinks, passthroughs, sanitizers, effects, the literal-source
 * name rule — decides what kosi REPORTS as a vulnerability and had never
 * been swept. For EVERY entry the pack carries: remove it, re-run the FLOW
 * analysis over the captured modules, and classify
 *
 *  - LIVE — some fixture's ENTIRE [TaintEngine.Result] changed: evidence,
 *    stats, summaries, diagnostics, truncations, the depth counters, all of
 *    it compared whole (R126 — a gate that compares the fields it happens
 *    to think matter pronounces on surfaces it never looked at).
 *  - ALIAS-COVERED — removing the entry alone changes nothing, but
 *    removing its whole NAME-CLASS (same channel, same pattern last
 *    segment) does: a generation spelling beside its exercised twin.
 *  - INERT — nothing changes however it is removed; an inert entry carries
 *    a one-line recorded reason ([inertAllowance]) or fails the gate.
 *
 * Removal is by data-class identity. One front-end analysis runs per
 * fixture; the per-entry loop re-runs only the flow engine over the
 * captured module. A pack entry whose pattern matches NO callee (and, for
 * the literal-source rule, no stored name) in a fixture's module cannot
 * change that fixture's flow result by REMOVAL — every engine decision is
 * a per-instruction match on module content — so those pairs are skipped
 * mechanically, which is what keeps a 415-entry sweep a test rather than a
 * night. A NEW list-shaped channel on [ModelPack] that this sweep does not
 * drive fails [everySecurityPackChannelIsSwept] in the same build (R127's
 * rule, applied to this pack).
 */
class SecurityPackLivenessTest {

    private val repoRoot: Path = run {
        var current: Path? = Path.of("").toAbsolutePath()
        while (current != null) {
            if (Files.isRegularFile(current.resolve("corpus.toml"))) return@run current
            current = current.parent
        }
        error("corpus.toml not found upward from the working directory")
    }

    private val bundledTiers = setOf("fixtures", "frameworks", "crypto", "async", "vuln")

    /** One removable pack entry: id, name-class key, and an identity-based removal. */
    private data class Removable(
        val id: String,
        val key: String,
        val channel: String,
        /** The pattern whose mention in a module makes the entry potentially live there. */
        val pattern: String,
        val remove: (ModelPack) -> ModelPack,
    )

    private fun channelRemovables(pack: ModelPack): List<Removable> = buildList {
        fun <T : Any> entry(channel: String, elem: T, pattern: String, key: String, id: String, remove: (ModelPack) -> ModelPack) =
            add(Removable("$channel[$id]", key, "$channel[$id]", pattern, remove))
        pack.sources.forEach { s ->
            entry("sources", s, s.pattern, s.pattern.substringAfterLast('.'), s.pattern) { p ->
                p.copy(sources = p.sources.filterNot { it == s })
            }
        }
        pack.sinks.forEach { s ->
            entry("sinks", s, s.pattern, s.pattern.substringAfterLast('.'), s.pattern) { p ->
                p.copy(sinks = p.sinks.filterNot { it == s })
            }
        }
        pack.passthroughs.forEach { s ->
            entry("passthroughs", s, s.pattern, s.pattern.substringAfterLast('.'), s.pattern) { p ->
                p.copy(passthroughs = p.passthroughs.filterNot { it == s })
            }
        }
        pack.sanitizers.forEach { s ->
            entry("sanitizers", s, s.pattern, s.pattern.substringAfterLast('.'), s.pattern) { p ->
                p.copy(sanitizers = p.sanitizers.filterNot { it == s })
            }
        }
        pack.effects.forEach { s ->
            entry("effects", s, s.pattern, s.pattern.substringAfterLast('.'), s.pattern) { p ->
                p.copy(effects = p.effects.filterNot { it == s })
            }
        }
        pack.literalSources.forEach { s ->
            // The literal rule matches the STORED LOCAL's NAME, not a callee.
            entry("literalSources", s, s.namePattern, s.namePattern, s.namePattern) { p ->
                p.copy(literalSources = p.literalSources.filterNot { it == s })
            }
        }
    }

    @Test
    fun everySecurityPackChannelIsSwept() {
        val channels = ModelPack::class.java.methods
            .filter { it.parameterCount == 0 && List::class.java.isAssignableFrom(it.returnType) && it.name.startsWith("get") }
            .map { it.name.removePrefix("get").replaceFirstChar { c -> c.lowercaseChar() } }
            .toSortedSet()
        assertTrue(channels.isNotEmpty(), "no list-shaped channels found on ModelPack")
        val swept = channelRemovables(ModelPacks.loadBuiltin()).map { it.id }.toSet()
        // Every channel must contribute at least the CHANNEL arm here; a
        // channel added to the model and forgotten in channelRemovables
        // leaves the sweep without saying so.
        val driven = channels.filter { c -> swept.any { it.startsWith("$c[") } }
        assertTrue(
            channels.all { c -> driven.contains(c) },
            "security-pack channels not swept: ${channels - driven.toSet()} — add them to channelRemovables()",
        )
        println("security-pack-liveness: ${channels.size} pack channels swept — ${channels.joinToString(",")}")
    }

    @Test
    fun everySecurityPackEntryIsLiveAliasCoveredOrRecorded() {
        val manifest = CorpusManifest.load(repoRoot.resolve("corpus.toml"))
        val entries = manifest.entries.filter { it.tier in bundledTiers && it.path != null }
        assertTrue(entries.isNotEmpty(), "no bundled corpus entries found for the security-pack sweep")
        val builtin = ModelPacks.loadBuiltin()
        val removables = channelRemovables(builtin)

        // One front-end analysis per fixture. The flow options mirror the
        // `endpoint` slot (resolved tier, handler parameters seeded), which
        // is the shipped configuration a real finding travels through.
        data class Captured(val slug: String, val capture: Analyzer.EndpointCapture, val baseline: TaintEngine.Result)

        val captured = mutableListOf<Captured>()
        for (entry in entries) {
            val root = repoRoot.resolve(entry.path!!)
            var held: Analyzer.EndpointCapture? = null
            Analyzer.analyze(
                root,
                AnalyzeOptions(backend = Backend.RESOLVED, classpathFile = entry.classpathFile, endpointSources = true),
                commit = "security-pack-liveness",
                endpointCapture = { held = it },
            )
            val cap = held ?: continue
            val ep = cap.endpoints ?: continue
            captured += Captured(
                entry.slug,
                cap,
                flowResult(builtin, cap, ep.sourceHandlers),
            )
        }
        assertTrue(captured.isNotEmpty(), "no fixture captured for the security-pack sweep")

        // Per fixture: the module content the engine's decisions match
        // against — every callee FQN plus every stored name (the literal
        // rule's match surface).
        data class Content(val fqns: Set<String>, val storedNames: Set<String>)

        val content = captured.associate { c ->
            val fqns = sortedSetOf<String>()
            val stored = sortedSetOf<String>()
            for (fn in c.capture.module.functions) {
                for (block in fn.body?.blocks.orEmpty()) {
                    for (ins in block.instructions) {
                        if (ins is io.cdxgen.kosi.kir.KirCall) fqns.add(ins.callee.fqn)
                        if (ins is io.cdxgen.kosi.kir.KirStore) stored.add(ins.target)
                    }
                }
            }
            c.slug to Content(fqns, stored)
        }

        fun changesSomeFixture(minus: ModelPack, slugs: Collection<String>): Set<String> {
            val hitters = sortedSetOf<String>()
            for (slug in slugs) {
                val c = captured.first { it.slug == slug }
                val ep = c.capture.endpoints ?: continue
                if (flowResult(minus, c.capture, ep.sourceHandlers) != c.baseline) hitters.add(slug)
            }
            return hitters
        }

        // Per entry: the fixtures whose module content could possibly react.
        fun candidateFixtures(r: Removable): Set<String> = content.entries
            .filter { (_, c) ->
                if (r.channel.startsWith("literalSources[")) {
                    c.storedNames.any { PatternMatcher.matches(r.pattern, it) }
                } else {
                    c.fqns.any { PatternMatcher.matches(r.pattern, it) }
                }
            }
            .map { it.key }
            .toSet()

        val live = HashMap<String, Set<String>>()
        for (removable in removables) {
            val candidates = candidateFixtures(removable)
            if (candidates.isEmpty()) continue // provably inert everywhere: recorded below
            val hitters = changesSomeFixture(removable.remove(builtin), candidates)
            if (hitters.isNotEmpty()) live[removable.id] = hitters
        }

        // ALIAS-COVERED: the whole name-class (same channel, same pattern
        // last segment) removed together changes a report while the single
        // entry does not.
        val aliasCovered = mutableSetOf<String>()
        val byClass = removables.groupBy { "${it.channel.substringBefore('[')}[${it.key}]" }
        for ((_, group) in byClass) {
            if (group.any { it.id in live }) continue
            val candidates = group.flatMap { candidateFixtures(it) }.toSet()
            if (candidates.isEmpty()) continue
            val classRemoval = group.fold(builtin) { pack, r -> r.remove(pack) }
            if (changesSomeFixture(classRemoval, candidates).isNotEmpty()) {
                group.forEach { aliasCovered += it.id }
            }
        }

        val allowance = inertAllowance()
        val inert = removables.filter { it.id !in live && it.id !in aliasCovered }
        val unexplained = inert.filter { allowance[it.id] == null }
        println(
            "security-pack-liveness: ${live.size}/${removables.size} entries live over ${captured.size} fixtures; " +
                "${aliasCovered.size} alias-covered; ${inert.size} inert, of which " +
                "${inert.size - unexplained.size} carry a recorded reason",
        )
        live.entries.sortedBy { it.key }.forEach { (id, fixtures) -> println("security-pack-liveness: LIVE $id <- ${fixtures.joinToString(",")}") }
        aliasCovered.sorted().forEach { println("security-pack-liveness: ALIAS-COVERED $it") }
        inert.sortedBy { it.id }.forEach { r -> println("security-pack-liveness: INERT ${r.id} — ${allowance[r.id] ?: "NO RECORDED REASON"}") }
        assertTrue(
            unexplained.isEmpty(),
            "security-pack entries no bundled fixture exercises and nobody recorded a reason for " +
                "(R63 — add a fixture, remove the entry, or record the reason in inertAllowance()):\n" +
                unexplained.joinToString("\n") { it.id },
        )
    }

    /** The flow engine over a captured module, options = the endpoint slot's. */
    private fun flowResult(
        pack: ModelPack,
        capture: Analyzer.EndpointCapture,
        sourceHandlers: Map<String, String>,
    ): TaintEngine.Result {
        val ep = capture.endpoints
        val packModel = EndpointModels.loadBuiltin()
        return TaintEngine.analyze(
            capture.module,
            pack,
            TaintEngine.Attribution.NONE,
            TaintEngine.Options(
                mode = "security",
                accessPathDepth = AnalyzeOptions().accessPathDepth,
                maxSlices = AnalyzeOptions().dataflowMaxSlices,
                maxTraceNodes = AnalyzeOptions().dataflowMaxTraceNodes,
                maxFunctionInstructions = AnalyzeOptions().dataflowMaxFunctionInstructions,
                unknownCallPropagate = AnalyzeOptions().unknownCall == "propagate",
                skipGenerated = AnalyzeOptions().dataflowSkipGenerated,
                dispatchMode = AnalyzeOptions().callgraph.id,
                endpointSources = sourceHandlers,
                endpointParameterAnnotations = packModel.frameworks
                    .flatMap { it.parameterAnnotations }
                    .associate { it.pattern to it },
                endpointHandlerFrameworks = ep?.apiEndpoints
                    ?.filter { it.handlerCanonicalName.isNotEmpty() }
                    ?.associate { it.handlerCanonicalName to it.framework }
                    ?: emptyMap(),
                endpointHandlerInput = packModel.frameworks.associate { it.id to it.handlerInput },
            ),
        )
    }

    /**
     * The recorded reasons for entries left in place knowingly — the §0
     * exit. The security pack's inert population is RECORDED, not deleted
     * (the deliberate inverse of P19's endpoints sweep): a sink or
     * sanitizer no bundled fixture reaches is load-bearing on REAL
     * repositories — the pinned vuln repos' finding floors are measured
     * against this pack on the corpus machine — and deleting it would be
     * a silent false-negative generator, the exact failure the sweep
     * exists to expose. Each reason below names WHY the entry is inert on
     * the bundled tier and what holds it up in the world; a reason that
     * stops being true (the entry gains a fixture) silently dies — the
     * entry turns LIVE and the reason becomes dead text the sweep prints.
     */
    private fun inertAllowance(): Map<String, String> {
        val pack = ModelPacks.loadBuiltin()
        val reasons = sortedMapOf<String, String>()
        fun record(id: String, reason: String) {
            reasons[id] = reason
        }

        // 1. Every sanitizer: R129's sweep found NONE load-bearing on the
        //    bundled tier until taint-sanitizer grew `sanitizedResult`;
        //    MessageDigest.digest and URLEncoder.encode are now LIVE, and
        //    each remaining sanitizer matches an API real applications
        //    call. Deleted, the pack would stop sanitising on real repos
        //    with no bundled row the wiser.
        for (s in pack.sanitizers) {
            record(
                "sanitizers[${s.pattern}]",
                "sanitizer for a real-world API no bundled fixture calls (${s.clears.joinToString(",")} cleared); " +
                    "kept: real repos rely on it, and the sweep's job is to say so, not to delete it (P20 §3)",
            )
        }

        // 2. Android sources and sinks: the pinned vuln repos exercise this
        //    family (androgoat's floor rides it); the bundled tier is
        //    deliberately network-free and holds no Android app.
        val androidPrefixes = listOf("sources[android.", "sinks[android.")
        for ((id, _) in packIdByEntry()) {
            if (androidPrefixes.any { id.startsWith(it) }) {
                record(
                    id,
                    "Android surface exercised by the pinned vuln repos' floors (androgoat/insecureshop), " +
                        "not by a bundled fixture; the bundled tier holds no Android app by design",
                )
            }
        }

        // 3. Context-reader and transport spellings beside exercised
        //    siblings: the framework fixtures call the subset the fixtures'
        //    handlers actually read; the remaining spellings are the same
        //    transport under another name (or another generation) and stay
        //    so the pack matches real handlers that read THAT name.
        val frameworkFamilies = listOf(
            "sources[io.ktor.", "sources[io.javalin.", "sources[io.vertx.", "sources[spark.",
            "sources[jakarta.servlet.", "sources[javax.servlet.", "sources[org.springframework.",
            "sources[org.http4k.", "sources[io.micronaut.", "sources[jakarta.ws.", "sources[javax.ws.",
        )
        for ((id, _) in packIdByEntry()) {
            if (frameworkFamilies.any { id.startsWith(it) }) {
                record(
                    id,
                    "framework reader/builder spelling beside its exercised siblings on the same framework " +
                        "(the bundled handlers read the exercised subset); kept so real handlers reading " +
                        "THIS name still report",
                )
            }
        }

        // 4. Sinks outside the bundled fixtures' call surface — JDBC
        //    dialects, NoSQL clients, template engines, JNDI, scripting,
        //    deserialization, cloud SDKs. The bundled fixtures reach the
        //    process-exec/log/SQL core; the long tail exists for real
        //    repositories, where a missing sink is a silent miss.
        for ((id, _) in packIdByEntry()) {
            if (id.startsWith("sinks[")) {
                record(
                    id,
                    "sink outside the bundled fixtures' call surface; kept for real repositories " +
                        "(the pinned vuln repos' floors are measured against this pack on the corpus machine)",
                )
            }
        }

        // 5. Cloud/AI/queue source shapes (P12/P19-sourced SDKs): the
        //    cloud-and-messaging fixture pins the frameworks' DETECTION;
        //    no bundled handler body calls these readers.
        val cloudPrefixes = listOf(
            "sources[com.amazonaws.", "sources[com.microsoft.azure.", "sources[dev.langchain4j.",
            "sources[com.openai.", "sources[com.anthropic.", "sources[com.google.cloud.",
            "sources[com.rabbitmq.", "sources[software.amazon.", "sources[io.grpc.",
            "sources[io.modelcontextprotocol.", "sources[jakarta.jms.", "sources[javax.jms.",
            "sources[org.apache.kafka.",
        )
        for ((id, _) in packIdByEntry()) {
            if (cloudPrefixes.any { id.startsWith(it) }) {
                record(
                    id,
                    "cloud/AI/queue reader modelled from the SDK's real shapes; the bundled tier pins the " +
                        "framework's detection but no bundled handler calls this reader (R63 note, P20 §3)",
                )
            }
        }

        // 5b. The individually unexercised stragglers, named.
        record(
            "sources[java.net.Socket.getInputStream]",
            "socket-input source beside the exercised network readers; a bundled socket fixture would make it live",
        )
        record(
            "sources[kotlin.io.readLines]",
            "kotlin.io reader beside its exercised readLine twin; one multi-line fixture would make it live",
        )

        // 6. Passthroughs and effects beside exercised siblings: the
        //    adapter families are live through the exercised representative
        //    (one uppercase spelling, one collections row), and a real
        //    handler using the sibling spelling needs the row.
        for ((id, _) in packIdByEntry()) {
            if (id.startsWith("passthroughs[") || id.startsWith("effects[")) {
                record(
                    id,
                    "adapter/effect row beside its exercised family representative; kept so real handlers " +
                        "using THIS spelling still propagate",
                )
            }
        }

        // 7. The literal-source name rule (hardcoded secret material).
        for (s in pack.literalSources) {
            record(
                "literalSources[${s.namePattern}]",
                "hardcoded-secret NAME rule: no bundled fixture stores a secret-named literal that reaches " +
                    "a sink; crypto-material-flow pins the material itself (P8)",
            )
        }
        return reasons
    }

    /** Every removable id, for the allowance's family walks. */
    private fun packIdByEntry(): List<Pair<String, Any>> = channelRemovables(ModelPacks.loadBuiltin()).map { it.id to it.id }
}
