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
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToUByte mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToUByteOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToUShort mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToUShortOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToUInt mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToUIntOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToULong mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToULongOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToBigInteger mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToBigIntegerOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToBigDecimal mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaToBigDecimalOrNull mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaByteParseByte mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaByteValueOf mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaShortParseShort mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaShortValueOf mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaIntegerParseInt mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaIntegerValueOf mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaLongParseLong mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaLongValueOf mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaFloatParseFloat mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaFloatValueOf mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDoubleParseDouble mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDoubleValueOf mode=endpoint
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

fun viaToUByte(): String {
    val seconds = (readLine() ?: "1").toUByte()
    return run("sleep $seconds")
}

fun viaToUByteOrNull(): String {
    val seconds = (readLine() ?: "1").toUByteOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaToUShort(): String {
    val seconds = (readLine() ?: "1").toUShort()
    return run("sleep $seconds")
}

fun viaToUShortOrNull(): String {
    val seconds = (readLine() ?: "1").toUShortOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaToUInt(): String {
    val seconds = (readLine() ?: "1").toUInt()
    return run("sleep $seconds")
}

fun viaToUIntOrNull(): String {
    val seconds = (readLine() ?: "1").toUIntOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaToULong(): String {
    val seconds = (readLine() ?: "1").toULong()
    return run("sleep $seconds")
}

fun viaToULongOrNull(): String {
    val seconds = (readLine() ?: "1").toULongOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaToBigInteger(): String {
    val seconds = (readLine() ?: "1").toBigInteger()
    return run("sleep $seconds")
}

fun viaToBigIntegerOrNull(): String {
    val seconds = (readLine() ?: "1").toBigIntegerOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaToBigDecimal(): String {
    val seconds = (readLine() ?: "1").toBigDecimal()
    return run("sleep $seconds")
}

fun viaToBigDecimalOrNull(): String {
    val seconds = (readLine() ?: "1").toBigDecimalOrNull() ?: return "bad"
    return run("sleep $seconds")
}

fun viaByteParseByte(): String {
    val seconds = java.lang.Byte.parseByte(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaByteValueOf(): String {
    val seconds = java.lang.Byte.valueOf(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaShortParseShort(): String {
    val seconds = java.lang.Short.parseShort(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaShortValueOf(): String {
    val seconds = java.lang.Short.valueOf(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaIntegerParseInt(): String {
    val seconds = java.lang.Integer.parseInt(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaIntegerValueOf(): String {
    val seconds = java.lang.Integer.valueOf(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaLongParseLong(): String {
    val seconds = java.lang.Long.parseLong(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaLongValueOf(): String {
    val seconds = java.lang.Long.valueOf(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaFloatParseFloat(): String {
    val seconds = java.lang.Float.parseFloat(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaFloatValueOf(): String {
    val seconds = java.lang.Float.valueOf(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaDoubleParseDouble(): String {
    val seconds = java.lang.Double.parseDouble(readLine() ?: "1")
    return run("sleep $seconds")
}

fun viaDoubleValueOf(): String {
    val seconds = java.lang.Double.valueOf(readLine() ?: "1")
    return run("sleep $seconds")
}

private fun run(command: String): String =
    BufferedReader(InputStreamReader(Runtime.getRuntime().exec(command).inputStream)).readText()
