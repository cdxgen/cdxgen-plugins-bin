// A local ThreadLocal is a carrier within its function: set writes the
// receiver's element state, get carries it out. (A member-property
// ThreadLocal reloads the field per access and stays a documented gap.)
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaThreadLocal mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanThread mode=endpoint
// kosi:want-not diagnostic code=parse-error
package fixtures.tl

import java.io.BufferedReader
import java.io.InputStreamReader

fun viaThreadLocal(): String {
    val held = ThreadLocal<String>()
    held.set(readLine() ?: "echo")
    return run(held.get() ?: "echo")
}

fun cleanThread(): String {
    val held = ThreadLocal<String>()
    held.set("echo ok")
    return run(held.get() ?: "echo")
}

private fun run(command: String): String =
    BufferedReader(InputStreamReader(Runtime.getRuntime().exec(command).inputStream)).readText()
