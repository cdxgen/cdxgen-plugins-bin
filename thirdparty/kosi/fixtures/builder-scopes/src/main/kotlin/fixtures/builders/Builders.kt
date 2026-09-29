// A builder written inside a scope function or a standard-library builder.
// The bare `append(raw)` inside `apply { }`, `with(sb) { }` and
// `buildString { }` is a call on the lambda's receiver; `also { it.. }`
// writes through a second name of the same builder; a template renders a
// builder's or a list's contents; appendLine/insert and StringBuffer write
// the builder like StringBuilder.append does.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.builders.cleanBuildString mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.builders.cleanApply mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.builders.outerReceiverKept mode=endpoint
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaApply mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaWith mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaAlso mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaBuildString mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaBuildList mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaAppendLine mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaInsert mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaStringBuffer mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaStringBufferInsert mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaTemplate mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.builders.viaJoinToString mode=endpoint
package fixtures.builders

import java.io.BufferedReader
import java.io.InputStreamReader

fun viaApply(): String {
    val raw = readLine() ?: ""
    val command = StringBuilder().apply {
        append("echo ")
        append(raw)
    }.toString()
    return run(command)
}

fun viaWith(): String {
    val raw = readLine() ?: ""
    val sb = StringBuilder()
    with(sb) {
        append("echo ")
        append(raw)
    }
    return run(sb.toString())
}

fun viaAlso(): String {
    val raw = readLine() ?: ""
    val sb = StringBuilder("echo ").also { it.append(raw) }
    return run(sb.toString())
}

fun viaBuildString(): String {
    val raw = readLine() ?: ""
    return run(buildString { append("echo "); append(raw) })
}

fun viaBuildList(): String {
    val raw = readLine() ?: ""
    val parts = buildList { add("echo"); add(raw) }
    return run(parts.joinToString(" "))
}

fun viaAppendLine(): String {
    val raw = readLine() ?: ""
    val sb = StringBuilder()
    sb.appendLine(raw)
    return run(sb.toString())
}

fun viaInsert(): String {
    val raw = readLine() ?: ""
    val sb = StringBuilder(" --version")
    sb.insert(0, raw)
    return run(sb.toString())
}

fun viaStringBuffer(): String {
    val raw = readLine() ?: ""
    val sb = StringBuffer("echo ")
    sb.append(raw)
    return run(sb.toString())
}

fun viaStringBufferInsert(): String {
    val raw = readLine() ?: ""
    val sb = StringBuffer(" --version")
    sb.insert(0, raw)
    return run(sb.toString())
}

fun viaTemplate(): String {
    val raw = readLine() ?: ""
    val sb = StringBuilder()
    sb.append(raw)
    return run("echo $sb")
}

fun viaJoinToString(): String {
    val raw = readLine() ?: ""
    val parts = mutableListOf("echo")
    parts.add(raw)
    return run(parts.joinToString(" "))
}

fun cleanBuildString(): String {
    val raw = readLine() ?: ""
    println(raw)
    return run(buildString { append("echo "); append("ok") })
}

fun cleanApply(): String {
    val raw = readLine() ?: ""
    println(raw)
    return run(StringBuilder().apply { append("echo ok") }.toString())
}

class Holder(private val log: StringBuilder) {
    // `append(raw)` inside `apply { }` binds the LAMBDA's receiver; the bare
    // `note(raw)` still calls this class's member, which writes `log`, not
    // the builder the lambda returns.
    fun note(value: String) {
        log.append(value)
    }

    fun outerReceiverKept(): String {
        val raw = readLine() ?: ""
        val command = StringBuilder().apply { note(raw); append("echo ok") }.toString()
        return run(command)
    }
}

private fun run(command: String): String =
    BufferedReader(InputStreamReader(Runtime.getRuntime().exec(command).inputStream)).readText()
