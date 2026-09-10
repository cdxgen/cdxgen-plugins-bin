// Negative half first: no JDBC call may be attributed in this fixture, and
// the functions whose templates interpolate only clean values must produce
// no flow — a concat rule that taints the template's constant parts (or the
// format() receiver) would fail the want-not halves.
// kosi:want-not usage name=~executeQuery
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~report
// kosi:want-not flow source=untrusted-input sink=log-injection fn=~greeting
// kosi:want-not diagnostic code=parse-error
//
// Positive half: string templates are Kotlin's number-one injection channel.
// The template in auditLine lowers to StringConcat over a tainted part, and
// the concatenation result reaches the sink.
// kosi:want declaration name=greeting kind=function
// kosi:want usage name=~.format
// kosi:want usage name=println
// kosi:want flow source=untrusted-input sink=log-injection fn=~auditLine known-fail=syntax:1
package fixtures.templates

fun greeting(name: String?): String = "Hello, ${name ?: "stranger"}!"

fun report(total: Int, currency: String) {
    val line = "%d %s".format(total, currency)
    println("total=$line")
}

fun auditLine() {
    val actor = readLine() ?: return
    println("AUDIT actor=$actor")
}
