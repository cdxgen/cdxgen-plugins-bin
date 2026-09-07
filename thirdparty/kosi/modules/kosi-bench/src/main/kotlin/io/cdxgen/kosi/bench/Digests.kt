package io.cdxgen.kosi.bench

import io.cdxgen.kosi.schema.JsonWriter
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/**
 * Digest goldens (06-CORPUS.md §5): digests, never full reports, verified by
 * content. The digest covers a projection of the report that excludes
 * provably volatile fields (timings, peak RSS, working directory) and nothing
 * else — when a golden changes, the diff of section digests names the section,
 * and investigation compares findings, not digests (golem's lesson: a stdlib
 * source position moving between Kotlin versions once masqueraded as a
 * behavior change).
 */
object Digests {

    data class FixtureDigest(
        val slug: String,
        val slot: String,
        val sections: Map<String, String>,
    ) {
        /**
         * Stable digest over all section digests (sorted), so a single value
         * can travel in bench output/baselines while [diff] still names the
         * changed section during investigation.
         */
        val combined: String
            get() = sha256(
                sections.entries
                    .sortedBy { it.key }
                    .joinToString("\n") { "${it.key}=${it.value}" },
            )

        fun toJson(): String {
            val w = JsonWriter()
            w.beginObject()
            w.str("combinedDigest", combined)
            w.beginArray("digests")
            for (key in sections.keys.sorted()) {
                w.beginObject()
                w.str("digest", sections[key] ?: "")
                w.str("section", key)
                w.endObject()
            }
            w.endArray()
            w.str("slot", slot)
            w.str("slug", slug)
            w.endObject()
            return w.render()
        }

        companion object {
            fun fromJson(text: String): FixtureDigest {
                val obj = io.cdxgen.kosi.schema.JsonReader.parse(text).asObject()
                val sections = obj.arr("digests")?.objects()?.associate {
                    (it.str("section") ?: "") to (it.str("digest") ?: "")
                } ?: emptyMap()
                return FixtureDigest(
                    slug = obj.str("slug") ?: "",
                    slot = obj.str("slot") ?: "",
                    sections = sections,
                )
            }
        }
    }

    /**
     * Sections excluded from the digest, each because it changes without the
     * analysis changing. Everything else in the report is digested — an
     * allowlist would silently stop covering every section a later phase adds
     * (crypto, services, callGraph, dataFlow, ...).
     */
    val VOLATILE_SECTIONS = setOf(
        // tool.commit changes on every commit; runtime carries the absolute
        // working directory, the host id and the JVM version.
        "tool",
        "runtime",
    )

    /** Sections that enter the digest, computed from the rendered report JSON. */
    fun compute(reportJson: String): Map<String, String> {
        val root = io.cdxgen.kosi.schema.JsonReader.parse(reportJson).asObject()
        val sections = linkedMapOf<String, String>()
        for (section in root.members.keys.sorted()) {
            if (section in VOLATILE_SECTIONS) continue
            root[section]?.let { value ->
                sections[section] = sha256(value.toString())
            }
        }
        return sections
    }

    fun sha256(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(text.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun diff(current: FixtureDigest, golden: FixtureDigest): List<String> {
        val problems = mutableListOf<String>()
        val allSections = (current.sections.keys + golden.sections.keys).toSortedSet()
        for (section in allSections) {
            val c = current.sections[section]
            val g = golden.sections[section]
            when {
                c == null -> problems.add("golden section $section missing from current run")
                g == null -> problems.add("new section $section (no golden)")
                c != g -> problems.add("section $section changed: golden=$g current=$c")
            }
        }
        return problems
    }

    fun save(digest: FixtureDigest, file: Path) {
        Files.createDirectories(file.toAbsolutePath().parent)
        Files.writeString(file, digest.toJson() + "\n", StandardCharsets.UTF_8)
    }

    fun load(file: Path): FixtureDigest? =
        if (Files.isRegularFile(file)) FixtureDigest.fromJson(Files.readString(file)) else null
}
