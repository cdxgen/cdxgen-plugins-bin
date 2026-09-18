package io.cdxgen.kosi.corpus

import java.nio.file.Files
import java.nio.file.Path

/**
 * Minimal parser for corpus.toml — the subset of TOML the corpus uses:
 * `[[fixtures]]` array tables plus `key = "string"` / `key = [...]` string
 * arrays. No TOML library (the dependency allowlist is closed). Entry order
 * is preserved so the bench runs fixtures deterministically.
 */
data class CorpusEntry(
    val slug: String,
    val tier: String,
    val path: String?,
    val repo: String?,
    val sha: String?,
    val capabilities: List<String>,
    val expectedFlows: String?,
    val features: List<String>,
    /**
     * Optional build-produced classpath file inside the entry's directory
     * (one jar path per line, `#` comments) — 02-ARCHITECTURE.md §3
     * acquisition order 2. Generated developer-side by
     * scripts/warm-corpus-classpath.sh; kosi never executes a build to make
     * one. When absent or unreadable, offline resolution runs and any gap is
     * diagnosed as classpath-partial.
     */
    val classpathFile: String?,
    /**
     * The FINDING FLOOR (P14): the minimum slices this entry's resolved
     * slot must publish. The vuln tier carries one per repo — a change that
     * takes a deliberately vulnerable app to zero findings currently does so
     * with a green build, which is exactly how kosi arrived at P11
     * reporting zero findings on every real repo. Two-way, like every
     * ratchet: below FAILS, and materially above FAILS too until the floor
     * is raised, so an improvement is recorded rather than absorbed.
     */
    val minFindings: Int? = null,
    /**
     * A per-entry override of `--deps-max-classes` for the deps slot (P14).
     * AndroGoat's TRANSITIVE-warmed classpath (161 coordinates of AndroidX)
     * makes the default 500-class lowering fill any heap the corpus JVM can
     * spare; a per-entry cap keeps the slot measurable instead of letting
     * `ExitOnOutOfMemoryError` terminate a 70-minute run mid-tier. The
     * deps-class-limit diagnostic still names what was cut.
     */
    val depsMaxClasses: Int? = null,
    /**
     * The RESOLUTION-ERROR classes this entry's sources legitimately carry
     * (P18 §3): the frontend's `resolution-errors` diagnostic names the
     * ERROR-severity factories the analysis saw, and a class that is NOT
     * here fails the row — a fixture whose stub stopped typechecking (R110:
     * a missing import, an unimplemented member) otherwise passed every
     * want over code the compiler rejects. The list is a RATCHET, not a
     * licence: adding a class is a reviewed change, and the count rides
     * the diagnostic for drift both ways. NULL = ungated (repo tiers: real
     * code under partial classpaths legitimately resolves imperfectly —
     * corpusFull measured ABSTRACT_MEMBER_NOT_IMPLEMENTED and a dozen
     * inference classes on the pinned repos, none of them a fixture
     * regression); an EMPTY list is a POSITIVE declaration that the entry
     * typechecks clean, and the two must not collapse into each other
     * (the first implementation parsed absent as empty and failed every
     * repo row — caught by this phase's own corpusFull, not by review).
     */
    val toleratedResolutionErrors: List<String>? = null,
) {
    fun validate() {
        if (path == null && repo == null) {
            throw IllegalArgumentException("corpus.toml entry $slug: either path or repo is required")
        }
        if (repo != null && sha == null) {
            throw IllegalArgumentException("corpus.toml entry $slug: repo entries must pin an exact sha")
        }
        if (slug.isBlank()) {
            throw IllegalArgumentException("corpus.toml entry: slug must not be blank")
        }
    }
}

data class CorpusManifest(
    val entries: List<CorpusEntry>,
) {
    /**
     * A tier no entry carries is a TYPO, not an empty selection. `corpusFull`
     * asked for `vuln` and `ported` — neither has ever existed in the
     * manifest — and quietly ran one of the five pinned repos while calling
     * itself the full run (R64). Silently dropping an unknown tier turns a
     * misspelling into missing coverage that still exits zero.
     */
    /**
     * P23 §0: the BUNDLED entries — the ones whose sources live in this
     * repository under `fixtures/`, so their reports are reproducible from a
     * checkout alone with no external clone. This is the golden gate's
     * population, derived rather than listed.
     *
     * It used to be the tier list `{"fixtures", "async"}`, written two lines
     * under a comment claiming "every bundled fixture tier is
     * golden-ratcheted ... a tier the goldens never see is a tier whose
     * drift they prove nothing about" — which was false for five tiers and
     * seventeen bundled fixtures the moment `frameworks` was added (the P23
     * review's R142). Every crypto fixture, every framework fixture (ktor,
     * spring, micronaut, quarkus, http4k, grpc) and the bundled vulnerable
     * service were outside the pin. A tier list has to be remembered; a
     * predicate over `path` cannot be forgotten, and a new bundled tier is
     * golden-ratcheted the day it is added.
     *
     * [excludedTiers] is the one place an exception is stated out loud.
     */
    fun bundled(only: String? = null, excludedTiers: Set<String> = GOLDEN_EXCLUDED_TIERS): List<CorpusEntry> {
        val onlySlugs = only?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
        return entries.filter { entry ->
            entry.path?.startsWith("fixtures/") == true &&
                entry.tier !in excludedTiers &&
                (onlySlugs == null || entry.slug in onlySlugs)
        }
    }

    fun select(tiers: Set<String>, only: String? = null): List<CorpusEntry> {
        val known = entries.map { it.tier }.toSet()
        val unknown = (tiers - known).sorted()
        require(unknown.isEmpty()) {
            "unknown corpus tier(s) ${unknown.joinToString(", ")}; corpus.toml has ${known.sorted().joinToString(", ")}"
        }
        // P20 §5: `only` is a comma-separated slug list — the corpusChanged
        // middle tier selects many repo rows in one invocation.
        val onlySlugs = only?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
        return entries.filter { it.tier in tiers && (onlySlugs == null || it.slug in onlySlugs) }
    }

    companion object {
        /**
         * P23 §0: the bundled tiers the golden gate deliberately does NOT
         * pin, each for a reason that is stated rather than implied.
         *
         *  - `eap` targets a Kotlin EAP language version, so its report
         *    depends on the compiler the checkout happens to have; pinning
         *    a digest would ratchet the toolchain, not kosi.
         *
         * Anything else under `fixtures/` is pinned. Emptying this set is
         * always the safe direction; adding to it needs a sentence above.
         */
        val GOLDEN_EXCLUDED_TIERS = setOf("eap")

        fun parse(text: String): CorpusManifest {
            val tables = mutableListOf<LinkedHashMap<String, Any?>>()
            var current: LinkedHashMap<String, Any?>? = null
            text.lines().forEachIndexed { index, rawLine ->
                val lineNo = index + 1
                val line = rawLine.substringBefore('#').trim()
                if (line.isEmpty()) return@forEachIndexed
                Regex("""^\[\[fixtures]]$""").matchEntire(line)?.let {
                    current = linkedMapOf()
                    tables.add(current!!)
                    return@forEachIndexed
                }
                Regex("""^\[\[[a-zA-Z]+]]$""").matchEntire(line)?.let {
                    throw IllegalArgumentException(
                        "corpus.toml:$lineNo: unknown array table $line (only [[fixtures]] is supported)",
                    )
                }
                Regex("""^\[[a-zA-Z]+]$""").matchEntire(line)?.let {
                    throw IllegalArgumentException("corpus.toml:$lineNo: unsupported table $line")
                }
                val kv = Regex("""^([a-zA-Z_]+)\s*=\s*(.+)$""").find(line)
                    ?: throw IllegalArgumentException("corpus.toml:$lineNo: cannot parse '$rawLine'")
                val (key, value) = kv.destructured
                val parsed: Any = if (value.startsWith("[")) {
                    Regex(""""([^"]*)"""").findAll(value).map { it.groupValues[1] }.toList()
                } else if (value.startsWith("\"")) {
                    value.removeSurrounding("\"")
                } else if (value.toIntOrNull() != null) {
                    // Integers: the vuln tier's min_findings floor (P14).
                    value.toInt()
                } else {
                    throw IllegalArgumentException("corpus.toml:$lineNo: unsupported value for $key: $value")
                }
                val table = current
                    ?: throw IllegalArgumentException("corpus.toml:$lineNo: key outside a [[fixtures]] table")
                table[key] = parsed
            }
            val entries = tables.map { table -> entryFrom(table) }
            entries.forEach { it.validate() }
            return CorpusManifest(entries)
        }

        fun load(file: Path): CorpusManifest = parse(Files.readString(file))

        private fun entryFrom(table: LinkedHashMap<String, Any?>): CorpusEntry {
            fun str(key: String): String? = table[key] as? String
            fun int(key: String): Int? = table[key] as? Int
            @Suppress("UNCHECKED_CAST")
            fun list(key: String): List<String> = (table[key] as? List<String>) ?: emptyList()
            return CorpusEntry(
                slug = str("slug") ?: throw IllegalArgumentException("corpus.toml entry missing slug"),
                tier = str("tier") ?: throw IllegalArgumentException("corpus.toml entry ${str("slug")} missing tier"),
                path = str("path"),
                repo = str("repo"),
                sha = str("sha"),
                capabilities = list("capabilities"),
                expectedFlows = str("expected_flows"),
                features = list("features"),
                classpathFile = str("classpath_file"),
                minFindings = int("min_findings"),
                depsMaxClasses = int("deps_max_classes"),
                // NOT the `list()` helper: that coerces an absent key to
                // emptyList, collapsing "ungated" into "declared clean" —
                // R116's fix only holds if absence parses as null.
                toleratedResolutionErrors = table["tolerated_resolution_errors"] as? List<String>,
            )
        }
    }
}
