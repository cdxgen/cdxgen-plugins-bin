// Negative half first: getValue is reached only through the synthesized
// accessor call the lowering emits (KIR), so it must not surface as a source
// usage; and the delegate's constant is data, not a usage.
// kosi:want-not usage name=~getValue
// kosi:want-not usage name=abc
// kosi:want-not diagnostic code=lowering-failed
//
// Positive half: a delegated property lowers through its getValue call, and
// the delegate expression itself stays an ordinary call.
// kosi:want declaration name=token kind=property
// kosi:want declaration name=port kind=property
// kosi:want declaration name=tokenFn kind=function
// kosi:want usage name=lazy kind=call
package fixtures.delegates

val token: String by lazy { "abc" }

class Config {
    val port: Int by lazy { 8080 }
}

fun tokenFn(): String = token
