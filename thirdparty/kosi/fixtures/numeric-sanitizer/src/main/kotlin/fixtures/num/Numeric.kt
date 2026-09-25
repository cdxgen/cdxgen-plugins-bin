// A value coerced to a number can no longer carry an injection payload:
// every numeric coercion (and its OrNull form) sanitizes the
// untrusted-input category on the coerced result. The direct string
// interpolation half stays a finding.
// kosi:want flow source=untrusted-input sink=process-exec fn=~rawSleep mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaInt mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaIntOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaLong mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaLongOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDouble mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDoubleOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaFloat mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaFloatOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaShort mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaShortOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaByte mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaByteOrNull mode=endpoint
// kosi:want-not diagnostic code=parse-error
package fixtures.num

import java.io.BufferedReader
import java.io.InputStreamReader

fun rawSleep(): String {
    val raw = readLine() ?: "1"
    return run("sleep $raw")
}

fun viaInt(): String {
    val seconds = (readLine() ?: "1").toInt()
    return run("sleep $seconds")
}

fun viaIntOrNull(): String {
    val seconds = (readLine() ?: "1").toIntOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaLong(): String {
    val seconds = (readLine() ?: "1").toLong()
    return run("sleep $seconds")
}

fun viaLongOrNull(): String {
    val seconds = (readLine() ?: "1").toLongOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaDouble(): String {
    val seconds = (readLine() ?: "1").toDouble()
    return run("sleep $seconds")
}

fun viaDoubleOrNull(): String {
    val seconds = (readLine() ?: "1").toDoubleOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaFloat(): String {
    val seconds = (readLine() ?: "1").toFloat()
    return run("sleep $seconds")
}

fun viaFloatOrNull(): String {
    val seconds = (readLine() ?: "1").toFloatOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaShort(): String {
    val seconds = (readLine() ?: "1").toShort()
    return run("sleep $seconds")
}

fun viaShortOrNull(): String {
    val seconds = (readLine() ?: "1").toShortOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaByte(): String {
    val seconds = (readLine() ?: "1").toByte()
    return run("sleep $seconds")
}

fun viaByteOrNull(): String {
    val seconds = (readLine() ?: "1").toByteOrNull() ?: return "bad"
    return run("sleep $seconds")
}

private fun run(command: String): String =
    BufferedReader(InputStreamReader(Runtime.getRuntime().exec(command).inputStream)).readText()
