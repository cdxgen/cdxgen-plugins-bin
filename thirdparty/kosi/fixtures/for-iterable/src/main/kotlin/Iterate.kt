// Negative half first: the while loop reads like iteration but uses none of
// the iteration protocol — a lowering that pattern-matched any loop into
// iterator/hasNext/next would emit usages this file does not contain.
// kosi:want-not usage name=~hasNext
// kosi:want-not usage name=~iterator
// kosi:want-not diagnostic code=lowering-failed
//
// Positive half: the for loop lowers through the iteration protocol.
// kosi:want declaration name=sumAll kind=function
// kosi:want declaration name=sumIndexed kind=function
package fixtures.iterate

fun sumAll(values: List<Int>): Int {
    var acc = 0
    for (v in values) {
        acc += v
    }
    return acc
}

fun sumIndexed(values: List<Int>): Int {
    var acc = 0
    var i = 0
    while (i < values.size) {
        acc += values[i]
        i += 1
    }
    return acc
}
