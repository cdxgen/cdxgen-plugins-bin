// Negative half first: no JDBC call may be attributed in this fixture.
// kosi:want-not usage name=~executeQuery
// kosi:want-not diagnostic code=parse-error
//
// Positive half: string templates are Kotlin's number-one injection channel.
// kosi:want declaration name=greeting kind=function
// kosi:want usage name=~.format
// kosi:want usage name=println
package fixtures.templates

fun greeting(name: String?): String = "Hello, ${name ?: "stranger"}!"

fun report(total: Int, currency: String) {
    val line = "%d %s".format(total, currency)
    println("total=$line")
}
