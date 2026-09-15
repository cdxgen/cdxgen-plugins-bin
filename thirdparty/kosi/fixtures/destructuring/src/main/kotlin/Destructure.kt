// Negative half first: componentN functions are synthesized by the lowering
// (or the compiler), never declared in this file — a report that grew
// declarations for them would be inventing facts about the code.
// kosi:want-not declaration name=component1
// kosi:want-not declaration name=component2
// kosi:want-not diagnostic code=lowering-failed
//
// Positive half: destructuring lowers through componentN calls.
// kosi:want declaration name=PairReceiver kind=data-class
// kosi:want declaration name=first kind=function
// kosi:want declaration name=second kind=function
package fixtures.destructure

data class PairReceiver(val first: String, val second: Int)

fun first(pair: PairReceiver): String {
    val (a, _) = pair
    return a
}

fun second(pair: PairReceiver): Int {
    val (_, b) = pair
    return b
}
