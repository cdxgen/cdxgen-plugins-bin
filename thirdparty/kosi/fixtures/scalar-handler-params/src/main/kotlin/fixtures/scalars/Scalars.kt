// A handler parameter the framework CONVERTED to a scalar arrives parsed:
// `n: Int` is what `text.toInt()` returns, and the pack's sanitizer for that
// conversion clears it exactly as it clears the call's result. The text
// parameters stay findings, and so does a conversion the pack has no
// sanitizer for. The Boolean parses are sanitizers of their own.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.sleepInt mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.sleepNullableInt mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.sleepLong mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.sleepDouble mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.flag mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.byId mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.amount mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.pathId mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.toBooleanParsed mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.toBooleanStrictParsed mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.toBooleanStrictOrNullParsed mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.parseBooleanParsed mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.scalars.booleanValueOfParsed mode=endpoint
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.echoText mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.pathText mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.scalars.Scalars.listOfInts mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.scalars.rawText mode=endpoint
package fixtures.scalars

import java.io.BufferedReader
import java.io.InputStreamReader
import java.math.BigDecimal
import java.util.UUID
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class Scalars {
    @GetMapping("/sleep/int")
    fun sleepInt(@RequestParam n: Int): String = run("sleep $n")

    @GetMapping("/sleep/nullable")
    fun sleepNullableInt(@RequestParam n: Int?): String = run("sleep ${n ?: 1}")

    @GetMapping("/sleep/long")
    fun sleepLong(@RequestParam n: Long): String = run("sleep $n")

    @GetMapping("/sleep/double")
    fun sleepDouble(@RequestParam n: Double): String = run("sleep $n")

    @GetMapping("/flag")
    fun flag(@RequestParam verbose: Boolean): String = run("ls -l $verbose")

    @GetMapping("/by-id")
    fun byId(@RequestParam id: UUID): String = run("cat /data/$id")

    @GetMapping("/amount")
    fun amount(@RequestParam value: BigDecimal): String = run("echo $value")

    @GetMapping("/items/{id}")
    fun pathId(@PathVariable id: Long): String = run("cat /items/$id")

    @GetMapping("/echo")
    fun echoText(@RequestParam s: String): String = run("echo $s")

    @GetMapping("/files/{name}")
    fun pathText(@PathVariable name: String): String = run("cat /files/$name")

    // A list's elements are ints, but the list itself is not a converted
    // scalar: it stays seeded.
    @GetMapping("/ints")
    fun listOfInts(@RequestParam ids: List<Int>): String = run("echo $ids")
}

fun rawText(): String {
    val raw = readLine() ?: "false"
    return run("echo $raw")
}

fun toBooleanParsed(): String {
    val flag = (readLine() ?: "false").toBoolean()
    return run("echo $flag")
}

fun toBooleanStrictParsed(): String {
    val flag = (readLine() ?: "false").toBooleanStrict()
    return run("echo $flag")
}

fun toBooleanStrictOrNullParsed(): String {
    val flag = (readLine() ?: "false").toBooleanStrictOrNull() ?: false
    return run("echo $flag")
}

fun parseBooleanParsed(): String {
    val flag = java.lang.Boolean.parseBoolean(readLine() ?: "false")
    return run("echo $flag")
}

fun booleanValueOfParsed(): String {
    val flag = java.lang.Boolean.valueOf(readLine() ?: "false")
    return run("echo $flag")
}

private fun run(command: String): String =
    BufferedReader(InputStreamReader(Runtime.getRuntime().exec(command).inputStream)).readText()
