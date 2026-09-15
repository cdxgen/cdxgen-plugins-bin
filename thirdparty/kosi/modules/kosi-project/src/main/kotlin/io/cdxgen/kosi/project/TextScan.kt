package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path

/**
 * Text-scanning helpers for parsing build files. kosi reads build files the
 * way an editor does — balanced-brace block extraction plus anchored regexes —
 * and never evaluates them. Kotlin DSL and Groovy DSL differ slightly in
 * assignment syntax, so the regexes accept both `= "x"` and `= "x".set(...)`
 * styles; what they intentionally do NOT accept is arbitrary code, because
 * anything dynamic is reported as unknown rather than guessed.
 */
object TextScan {

    /** Returns the full text of the first `name { ... }` block, or null. */
    fun block(text: String, name: String): String? {
        val header = Regex("""(^|[\s;}])${Regex.escape(name)}\s*(?:\(|\{)""")
        val match = header.find(text) ?: return null
        val braceStart = text.indexOf('{', match.range.first)
        if (braceStart < 0) return null
        var depth = 0
        var inString = false
        var escaped = false
        var inLineComment = false
        var inBlockComment = false
        var i = braceStart
        while (i < text.length) {
            val c = text[i]
            if (inLineComment) {
                if (c == '\n') inLineComment = false
                i++
                continue
            }
            if (inBlockComment) {
                if (c == '*' && i + 1 < text.length && text[i + 1] == '/') {
                    inBlockComment = false
                    i++
                }
                i++
                continue
            }
            when {
                inString -> {
                    if (escaped) escaped = false else if (c == '\\') escaped = true else if (c == '"') inString = false
                }
                c == '/' && i + 1 < text.length && text[i + 1] == '/' -> inLineComment = true
                c == '/' && i + 1 < text.length && text[i + 1] == '*' -> inBlockComment = true
                c == '"' -> inString = true
                c == '{' -> depth++
                c == '}' -> {
                    depth--
                    if (depth == 0) return text.substring(braceStart + 1, i)
                }
            }
            i++
        }
        return null
    }

    /** All `name { ... }` blocks in the text (e.g. every sourceSet block). */
    fun allBlocks(text: String, name: String): List<Pair<String, String>> {
        val results = mutableListOf<Pair<String, String>>()
        var searchFrom = 0
        while (true) {
            val header = Regex("""${Regex.escape(name)}\s*(?:\(|\{)""").find(text, searchFrom) ?: break
            val braceStart = text.indexOf('{', header.range.first)
            if (braceStart < 0) break
            var depth = 0
            var end = -1
            var inString = false
            var escaped = false
            for (i in braceStart until text.length) {
                val c = text[i]
                if (inString) {
                    if (escaped) escaped = false else if (c == '\\') escaped = true else if (c == '"') inString = false
                } else when {
                    c == '"' -> inString = true
                    c == '{' -> depth++
                    c == '}' -> {
                        depth--
                        if (depth == 0) {
                            end = i
                            break
                        }
                    }
                }
            }
            if (end < 0) break
            val label = text.substring(header.range.first, braceStart).trim().trim('{', '(', ' ')
            results.add(label to text.substring(braceStart + 1, end))
            searchFrom = end + 1
        }
        return results
    }

    /**
     * First match of [regex] against [text]; returns group(1) trimmed and
     * unquoted.
     */
    fun firstString(text: String, regex: Regex): String? =
        regex.find(text)?.groupValues?.get(1)?.trim()?.removeSurrounding("\"")

    /**
     * Extracts an assignment `key = value` / `key value` (Groovy) / `key =
     * expr(value)` (Kotlin DSL with `set(...)`), returning the raw value text.
     */
    fun assignment(text: String, key: String): String? {
        val patterns = listOf(
            Regex("""(?m)^\s*(?:val\s+\w+\s+)?$key\s*=\s*(.+)$"""),
            Regex("""(?m)^\s*$key\s+(\"[^\"]+\")\s*$"""),
            Regex("""(?m)^\s*$key\.set\((.+)\)\s*$"""),
        )
        for (regex in patterns) {
            val match = regex.find(text) ?: continue
            return cleanValue(match.groupValues[1])
        }
        return null
    }

    /** Strips call wrappers and quotes from `KotlinVersion.KOTLIN_1_9` / `"1.9"`. */
    fun cleanValue(raw: String): String {
        var v = raw.trim().removeSuffix(",")
        val paren = v.indexOf('(')
        if (paren >= 0 && v.endsWith(")")) v = v.substring(paren + 1, v.length - 1)
        v = v.trim()
        if (v.startsWith("\"") && v.endsWith("\"") && v.length >= 2) v = v.substring(1, v.length - 1)
        return v.trim()
    }

    /**
     * Normalizes a version-ish value: `KotlinVersion.KOTLIN_1_9` → `1.9`,
     * `"1.9"` → `1.9`, `1.9` → `1.9`. Returns null for anything unrecognised
     * (never guesses).
     */
    fun versionValue(raw: String?): String? {
        if (raw == null) return null
        val cleaned = cleanValue(raw)
        val fromEnum = Regex("""KOTLIN_(\d+)_(\d+)""").find(cleaned)
        if (fromEnum != null) return "${fromEnum.groupValues[1]}.${fromEnum.groupValues[2]}"
        if (Regex("""\d+\.\d+""").matches(cleaned)) return cleaned
        return null
    }

    fun exists(root: Path, relative: String): Boolean = Files.exists(root.resolve(relative))

    fun isDirectory(root: Path, relative: String): Boolean =
        Files.isDirectory(root.resolve(relative))
}
