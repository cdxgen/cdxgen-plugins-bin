package io.cdxgen.kosi.corpus

import java.nio.file.Files
import java.nio.file.Path

/**
 * Line-based annotation parser. It scans `//` comments directly instead of
 * going through PSI so that fixtures with deliberate parse errors (the
 * `parse-error` diagnostic fixture) still yield their annotations.
 */
object AnnotationParser {

    const val PREFIX = "kosi:"

    private val KEY_VALUE = Regex("""([a-zA-Z-]+)=([^\s]+)""")

    sealed interface ParseResult {
        val file: String
    }

    data class Success(val annotation: Annotation, override val file: String) : ParseResult

    data class Failure(val error: String, val lineText: String, override val file: String, val line: Int) :
        ParseResult

    fun parseDir(dir: Path, relativeTo: Path = dir): List<ParseResult> {
        val results = mutableListOf<ParseResult>()
        if (!Files.isDirectory(dir)) return results
        Files.walk(dir).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { p -> p.fileName.toString().endsWith(".kt") || p.fileName.toString().endsWith(".java") }
                .sorted()
                .forEach { p ->
                    val rel = relativeTo.toAbsolutePath()
                        .relativize(p.toAbsolutePath()).toString().replace('\\', '/')
                    for (res in parseFileText(Files.readString(p), rel)) {
                        results.add(res)
                    }
                }
        }
        return results
    }

    /** Parses annotations from one file's text. Line numbers are 1-based. */
    fun parseFileText(text: String, fileName: String): List<ParseResult> {
        val results = mutableListOf<ParseResult>()
        text.lines().forEachIndexed { index, lineText ->
            val trimmed = lineText.trim()
            val content = when {
                trimmed.startsWith("//") -> trimmed.removePrefix("//").trim()
                trimmed.startsWith("#") -> trimmed.removePrefix("#").trim()
                else -> return@forEachIndexed
            }
            if (!content.startsWith(PREFIX)) return@forEachIndexed
            val body = content.removePrefix(PREFIX).trim()
            val parts = body.split(Regex("\\s+"), limit = 2)
            if (parts.isEmpty()) {
                results.add(Failure("empty annotation", lineText, fileName, index + 1))
                return@forEachIndexed
            }
            val want = when (parts[0]) {
                "want" -> true
                "want-not" -> false
                else -> {
                    results.add(Failure("expected want or want-not, got '${parts[0]}'", lineText, fileName, index + 1))
                    return@forEachIndexed
                }
            }
            val rest = parts.getOrElse(1) { "" }
            val tokens = rest.split(Regex("\\s+")).filter { it.isNotBlank() }
            if (tokens.isEmpty()) {
                results.add(Failure("missing kind", lineText, fileName, index + 1))
                return@forEachIndexed
            }
            val kind = Annotation.Kind.fromId(tokens[0])
            if (kind == null) {
                results.add(Failure("unknown kind '${tokens[0]}'", lineText, fileName, index + 1))
                return@forEachIndexed
            }
            var source: String? = null
            var sink: String? = null
            var from: String? = null
            var to: String? = null
            var symbol: String? = null
            var callType: String? = null
            var name: String? = null
            var usageKind: String? = null
            var star: Boolean? = null
            var declKind: String? = null
            var platform: String? = null
            var code: String? = null
            var count: Int? = null
            var mode: String? = null
            var fn: String? = null
            var maxDepth: Int? = null
            var knownFailAll: Int? = null
            var framework: String? = null
            var path: String? = null
            var method: String? = null
            var padding: String? = null
            var form: String? = null
            var protocol: String? = null
            var resolution: String? = null
            val knownFailByBackend = linkedMapOf<String, Int>()

            for (token in tokens.drop(1)) {
                val match = KEY_VALUE.matchEntire(token)
                if (match == null) {
                    results.add(Failure("malformed key=value: '$token'", lineText, fileName, index + 1))
                    return@forEachIndexed
                }
                val (key, rawValue) = match.destructured
                when (key) {
                    "source" -> source = rawValue
                    "sink" -> sink = rawValue
                    "from" -> from = rawValue
                    "to" -> to = rawValue
                    "symbol" -> symbol = rawValue
                    "calltype" -> callType = rawValue
                    "name" -> name = rawValue
                    "kind" ->
                        when (kind) {
                            Annotation.Kind.USAGE -> usageKind = rawValue
                            Annotation.Kind.DECLARATION -> declKind = rawValue
                            else -> {
                                results.add(Failure("kind= not valid for ${kind.id}", lineText, fileName, index + 1))
                                return@forEachIndexed
                            }
                        }
                    "star" -> star = rawValue.toBooleanStrictOrNull() ?: run {
                        results.add(Failure("star must be true|false", lineText, fileName, index + 1))
                        return@forEachIndexed
                    }
                    "platform" -> platform = rawValue
                    "code" -> code = rawValue
                    "count" -> count = rawValue.toIntOrNull() ?: run {
                        results.add(Failure("count must be an integer", lineText, fileName, index + 1))
                        return@forEachIndexed
                    }
                    "mode" -> mode = rawValue
                    "fn" -> fn = rawValue
                    "framework" -> framework = rawValue
                    "path" -> path = rawValue
                    "method" -> method = rawValue
                    "padding" -> padding = rawValue
                    "form" -> form = rawValue
                    "protocol" -> protocol = rawValue
                    "resolution" -> resolution = rawValue
                    "maxdepth" -> maxDepth = rawValue.toIntOrNull() ?: run {
                        results.add(Failure("maxdepth must be an integer", lineText, fileName, index + 1))
                        return@forEachIndexed
                    }
                    "known-fail" -> {
                        val scoped = Regex("""([a-zA-Z]+):(\d+)""").matchEntire(rawValue)
                        when {
                            scoped != null -> {
                                val (backend, defect) = scoped.destructured
                                if (backend !in Annotation.KNOWN_BACKENDS) {
                                    results.add(
                                        Failure(
                                            "unknown backend '$backend' in known-fail; " +
                                                "known: ${Annotation.KNOWN_BACKENDS}",
                                            lineText,
                                            fileName,
                                            index + 1,
                                        ),
                                    )
                                    return@forEachIndexed
                                }
                                if (knownFailByBackend.containsKey(backend)) {
                                    results.add(
                                        Failure("duplicate known-fail for backend $backend", lineText, fileName, index + 1),
                                    )
                                    return@forEachIndexed
                                }
                                knownFailByBackend[backend] = defect.toInt()
                            }
                            rawValue.toIntOrNull() != null -> knownFailAll = rawValue.toInt()
                            else -> {
                                results.add(Failure("known-fail must be N or backend:N", lineText, fileName, index + 1))
                                return@forEachIndexed
                            }
                        }
                    }
                    else -> {
                        results.add(Failure("unknown key '$key'", lineText, fileName, index + 1))
                        return@forEachIndexed
                    }
                }
            }
            val annotation = Annotation(
                want = want,
                kind = kind,
                source = source,
                sink = sink,
                from = from,
                to = to,
                symbol = symbol,
                callType = callType,
                name = name,
                usageKind = usageKind,
                star = star,
                declKind = declKind,
                platform = platform,
                code = code,
                count = count,
                mode = mode,
                fn = fn,
                maxDepth = maxDepth,
                knownFailAll = knownFailAll,
                knownFailByBackend = knownFailByBackend,
                framework = framework,
                path = path,
                method = method,
                padding = padding,
                form = form,
                protocol = protocol,
                resolution = resolution,
                file = fileName,
                line = index + 1,
            )
            val validationErrors = annotation.validate()
            if (validationErrors.isNotEmpty()) {
                results.add(
                    Failure(
                        validationErrors.joinToString("; "),
                        lineText,
                        fileName,
                        index + 1,
                    ),
                )
                return@forEachIndexed
            }
            results.add(Success(annotation, fileName))
        }
        return results
    }
}
