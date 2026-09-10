// Negative half first: an identical collection pipeline over clean values
// must report nothing — this is the half that stops "collections carry taint"
// from being implemented as "every collection is tainted".
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanList
// kosi:want-not diagnostic code=parse-error
//
// Positive half: taint rides THROUGH collection construction (listOf), the
// index read, and an effect-driven insert (add) into the sink. Both flows are
// expected, hence count=2 (scoped to the syntax tier, docs/KOSI.md defect 1).
// expected, hence count=2.
// kosi:want flow source=untrusted-input sink=process-exec count=2 known-fail=syntax:1
package fixtures.collections

fun viaList(): String {
    val input = readLine() ?: return ""
    val args = listOf(input)
    val first = args[0]
    val process = ProcessBuilder(first)
    return process.start().inputStream.bufferedReader().readText()
}

fun viaAdd(): String {
    val acc = mutableListOf<String>()
    acc.add(readLine() ?: "")
    val first = acc[0]
    val process = ProcessBuilder(first)
    return process.start().inputStream.bufferedReader().readText()
}

fun cleanList(): String {
    val args = listOf("status")
    val first = args[0]
    val process = ProcessBuilder(first)
    return process.start().inputStream.bufferedReader().readText()
}
