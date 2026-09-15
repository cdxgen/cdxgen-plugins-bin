// 08-VERSION-POLICY.md §4 fixture 2: syntax from the newest stable release
// (2.4's context parameters and explicit backing fields) must resolve with
// no version diagnostic and no resolution errors attributed to the syntax.
//
// Negative half: an engine that treats context parameters as unknown syntax
// would emit parse-error or resolution-errors; one that rejects the explicit
// backing field would invent a setter declaration for the val.
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=kotlin-version
// kosi:want-not declaration name=token kind=property count=2
//
// Positive half.
// kosi:want declaration name=logValue kind=function
// kosi:want declaration name=Token kind=class
// kosi:want usage name=~println
package fixtures.modern

class Token {
    val token: String
        field = "unset"
}

context(logger: Token)
fun logValue(value: Int) {
    println("value=$value token=${logger.token}")
}
