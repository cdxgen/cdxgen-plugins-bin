package io.cdxgen.kosi.evidence

import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.SecuritySignal
import java.nio.file.Files
import java.nio.file.Path

/**
 * The forwarded-header config signal: where the code turns on handling of the
 * client-supplied `Forwarded` and `X-Forwarded-*` headers. Behind a reverse
 * proxy that passes those headers through unchanged, the client chooses the
 * IP, host and scheme the application sees; what a source scan can see is the
 * switch, never the proxy, so the signal records the switch and the
 * deployment question stays with the reader.
 *
 * The rules key on the framework's own resolved symbol (the KIR callee, type
 * or static path at its real FQN), never on an option name, and an explicitly
 * off value emits nothing: Spring's `ForwardedHeaderFilter` in remove-only
 * mode (setRemoveOnly(true)) strips the headers rather than trusting them,
 * and `server.forward-headers-strategy=none` disables the handling.
 */
object ForwardedHeaders {
    const val CODE = "trusted-proxy-config"

    private const val SPRING_FILTER = "org.springframework.web.filter.ForwardedHeaderFilter"
    private const val TOMCAT_VALVE = "org.apache.catalina.valves.RemoteIpValve"
    private const val JETTY_CUSTOMIZER = "org.eclipse.jetty.server.ForwardedRequestCustomizer"
    private const val KTOR_FORWARDED = "io.ktor.server.plugins.forwardedheaders.ForwardedHeaders"
    private const val KTOR_X_FORWARDED = "io.ktor.server.plugins.forwardedheaders.XForwardedHeaders"
    private const val KTOR_INSTALL = "io.ktor.server.application.install"
    private const val KTOR_FORWARDED_CONFIG = "io.ktor.server.plugins.forwardedheaders.ForwardedHeadersConfig"
    private const val KTOR_X_FORWARDED_CONFIG = "io.ktor.server.plugins.forwardedheaders.XForwardedHeadersConfig"

    fun collect(root: Path, module: KirModule, attribution: NativeInterop.Attribution): List<SecuritySignal> {
        val signals = mutableListOf<SecuritySignal>()
        for (function in module.functions) {
            val body = function.body ?: continue
            // Constants by register, so setRemoveOnly(true) is read by value
            // and not guessed from the call's presence.
            val consts = HashMap<String, String>()
            val calls = mutableListOf<KirCall>()
            val news = mutableListOf<KirNew>()
            for (block in body.blocks) {
                for (ins in block.instructions) {
                    when (ins) {
                        is KirLoad -> if ((ins.constant as? KirConstant.Bool)?.value == true) {
                            consts[ins.result] = "true"
                        }
                        is KirCall -> calls.add(ins)
                        is KirNew -> news.add(ins)
                        else -> Unit
                    }
                }
            }
            fun emit(fqn: String, framework: String, headers: String, line: Int) {
                val (filePath, modulePath) = attribution.byAbsoluteFilePath[function.file] ?: (function.file to "")
                signals.add(
                    SecuritySignal(
                        code = CODE,
                        message = "`${function.canonicalName}` turns on forwarded-header handling " +
                            "($framework${if (headers.isEmpty()) "" else ", $headers headers"}), so the client IP, " +
                            "host or scheme the application sees can be chosen by the client behind a proxy " +
                            "that passes the headers through",
                        modulePath = modulePath,
                        purl = attribution.purlByModulePath[modulePath].takeUnless { it.isNullOrEmpty() } ?: function.purl,
                        filePath = filePath,
                        position = Position(filePath, line.coerceAtLeast(1), 1),
                        // The function that flips the switch, as NativeInterop
                        // records it, so a corpus annotation can demand the
                        // signal on one function and its absence on a twin.
                        symbol = function.canonicalName,
                    ),
                )
            }

            // The line of the first construction of a framework type, whether
            // the lowering records it as a constructor call or a `new`.
            fun constructedAt(type: String): Int? =
                calls.firstOrNull { it.callee.fqn == type }?.line ?: news.firstOrNull { it.type == type }?.line
            calls.firstOrNull { it.callee.fqn == SPRING_FILTER }?.let { filterCall ->
                // Remove-only mode strips the forwarded headers instead of
                // deriving anything from them, so it is the off position.
                val removeOnly = calls.any { call ->
                    call.callee.fqn == "$SPRING_FILTER.setRemoveOnly" &&
                        call.args.firstOrNull()?.let { consts[it] } == "true"
                }
                if (!removeOnly) {
                    emit(SPRING_FILTER, "spring", "all", filterCall.line)
                }
            }
            constructedAt(TOMCAT_VALVE)?.let { emit(TOMCAT_VALVE, "tomcat", "x-forwarded", it) }
            constructedAt(JETTY_CUSTOMIZER)?.let { emit(JETTY_CUSTOMIZER, "jetty", "forwarded", it) }
            // Ktor 2 and 3 declare both plugins as top-level ApplicationPlugin
            // values, and Application.install is generic in the plugin's
            // config type, so the resolved type argument of the install call
            // names which plugin it installs.
            for (call in calls.filter { it.callee.fqn == KTOR_INSTALL }) {
                when {
                    call.typeArguments.any { it == KTOR_FORWARDED_CONFIG } ->
                        emit(KTOR_FORWARDED, "ktor", "forwarded", call.line)
                    call.typeArguments.any { it == KTOR_X_FORWARDED_CONFIG } ->
                        emit(KTOR_X_FORWARDED, "ktor", "x-forwarded", call.line)
                }
            }
        }
        signals.addAll(forwardHeadersStrategyConfig(root))
        return signals
    }

    /**
     * Spring Boot's `server.forward-headers-strategy`: `native` delegates to
     * the container's X-Forwarded-* handling, `framework` installs the
     * ForwardedHeaderFilter (both header families), and `none` turns the
     * handling off. The value is read from the same files Spring reads, with
     * the property spelling for `.properties` and the nested `server:` block
     * for YAML, and the signal sits on the file that sets it.
     */
    private fun forwardHeadersStrategyConfig(root: Path): List<SecuritySignal> {
        if (!Files.isDirectory(root)) return emptyList()
        val signals = mutableListOf<SecuritySignal>()
        val files = Files.walk(root).use { stream ->
            stream.filter { p -> Files.isRegularFile(p) }
                .filter { p -> !skippedConfigDir(root.relativize(p)) }
                .filter { p ->
                    val name = p.fileName.toString()
                    name.startsWith("application") && (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml"))
                }
                .sorted()
                .toList()
        }
        for (file in files) {
            val rel = root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize()).toString().replace('\\', '/')
            val lines = Files.readAllLines(file)
            var inServerBlock = false
            for ((index, line) in lines.withIndex()) {
                val trimmed = line.trim()
                if (file.fileName.toString().endsWith(".properties")) {
                    val match = Regex("^server\\.forward-headers-strategy\\s*=\\s*(\\w+)\\s*$").find(trimmed)
                    if (match != null) {
                        forwardHeadersStrategySignal(match.groupValues[1], rel, index + 1)?.let(signals::add)
                    }
                } else {
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                    // A top-level key opens or closes the `server:` block;
                    // only a key nested under it is the server property.
                    if (!line[0].isWhitespace()) inServerBlock = trimmed == "server:"
                    val flat = Regex("^server\\.forward-headers-strategy:\\s*(\\w+)\\s*$").find(trimmed)
                    val nested = if (inServerBlock && line[0].isWhitespace()) {
                        Regex("^forward-headers-strategy:\\s*(\\w+)\\s*$").find(trimmed)
                    } else {
                        null
                    }
                    (flat ?: nested)?.let { match ->
                        forwardHeadersStrategySignal(match.groupValues[1], rel, index + 1)?.let(signals::add)
                    }
                }
            }
        }
        return signals
    }

    /**
     * Test resources, build outputs and dependency trees are not the
     * application's served configuration (ConfigResolver skips test
     * resources for the same reason).
     */
    private fun skippedConfigDir(relative: Path): Boolean {
        val parts = relative.map { it.toString() }
        return parts.any { it == "build" || it == "target" || it == "node_modules" || it.startsWith(".") } ||
            parts.windowed(2).any { it == listOf("src", "test") }
    }

    private fun forwardHeadersStrategyConfigValue(value: String): Pair<String, String>? = when (value) {
        "native" -> "spring" to "x-forwarded"
        "framework" -> "spring" to "all"
        else -> null
    }

    private fun forwardHeadersStrategySignal(value: String, rel: String, line: Int): SecuritySignal? {
        val (framework, headers) = forwardHeadersStrategyConfigValue(value) ?: return null
        return SecuritySignal(
            code = CODE,
            message = "server.forward-headers-strategy=$value turns on forwarded-header handling " +
                "($framework, $headers headers), so the client IP, host or scheme the application sees " +
                "can be chosen by the client behind a proxy that passes the headers through",
            modulePath = "",
            purl = "",
            filePath = rel,
            position = Position(rel, line, 1),
            // The file that sets the property stands in for a function, so a
            // corpus annotation can tell two config files apart.
            symbol = "$rel#server.forward-headers-strategy",
        )
    }
}
