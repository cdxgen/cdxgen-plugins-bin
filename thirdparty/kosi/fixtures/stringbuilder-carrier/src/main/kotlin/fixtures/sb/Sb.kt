// StringBuilder as a taint carrier. The statement form `sb.append(x);`
// discards the passthrough's result, so the flow rides the RECEIVER's
// element state: append is an effect writing it and toString carries it out.
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaStatement mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaChain mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanBuilder mode=endpoint
// kosi:want-not diagnostic code=parse-error
package fixtures.sb

import java.io.BufferedReader
import java.io.InputStreamReader

fun viaStatement(): String {
    val raw = readLine() ?: return ""
    val sb = StringBuilder("echo ")
    sb.append(raw)
    return run(sb.toString())
}

fun viaChain(): String {
    val raw = readLine() ?: return ""
    val joined = StringBuilder("echo ").append(raw).toString()
    return run(joined)
}

fun cleanBuilder(): String = run(StringBuilder("echo ok").toString())

private fun run(command: String): String =
    BufferedReader(InputStreamReader(Runtime.getRuntime().exec(command).inputStream)).readText()
