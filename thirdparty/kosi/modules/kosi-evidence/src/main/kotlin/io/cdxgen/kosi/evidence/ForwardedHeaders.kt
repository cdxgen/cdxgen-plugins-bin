package io.cdxgen.kosi.evidence

import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirFieldGet
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

    fun collect(root: Path, module: KirModule, attribution: NativeInterop.Attribution): List<SecuritySignal> {
        val signals = mutableListOf<SecuritySignal>()
        for (function in module.functions) {
            val body = function.body ?: continue
            // Constants by register, so setRemoveOnly(true) is read by value
            // and not guessed from the call's presence.
            val consts = HashMap<String, String>()
            val calls = mutableListOf<KirCall>()
            val news = mutableListOf<KirNew>()
            val fieldGets = mutableListOf<KirFieldGet>()
            for (block in body.blocks) {
                for (ins in block.instructions) {
                    when (ins) {
                        is KirLoad -> if ((ins.constant as? KirConstant.Bool)?.value == true) {
                            consts[ins.result] = "true"
                        }
                        is KirCall -> calls.add(ins)
                        is KirNew -> news.add(ins)
                        is KirFieldGet -> fieldGets.add(ins)
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
                        symbol = fqn,
                    ),
                )
            }

            val symbols = buildSet {
                addAll(calls.map { it.callee.fqn })
                addAll(news.map { it.type })
                addAll(fieldGets.map { it.path.toString() })
            }
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
            if (symbols.any { it == TOMCAT_VALVE }) {
                emit(TOMCAT_VALVE, "tomcat", "x-forwarded", function.line)
            }
            if (symbols.any { it == JETTY_CUSTOMIZER }) {
                emit(JETTY_CUSTOMIZER, "jetty", "forwarded", function.line)
            }
            // Ktor's plugin objects reach the KIR as the object reference the
            // install call receives, so any resolved mention counts.
            // The object reference can lower as the class FQN, a getter
            // call, or the JVM INSTANCE field, so any mention of the plugin
            // object's own path counts.
            if (symbols.any { it.contains(KTOR_FORWARDED) }) {
                emit(KTOR_FORWARDED, "ktor", "forwarded", function.line)
            }
            if (symbols.any { it.contains(KTOR_X_FORWARDED) }) {
                emit(KTOR_X_FORWARDED, "ktor", "x-forwarded", function.line)
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
                    if (trimmed == "server:" || trimmed.startsWith("server:")) inServerBlock = true
                    if (inServerBlock) {
                        val match = Regex("^forward-headers-strategy:\\s*(\\w+)\\s*$").find(trimmed)
                        if (match != null) {
                            forwardHeadersStrategySignal(match.groupValues[1], rel, index + 1)?.let(signals::add)
                            inServerBlock = false
                        }
                    }
                }
            }
        }
        return signals
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
            symbol = "server.forward-headers-strategy",
        )
    }
}
