// R69 construct-coverage fixture: LOOP AND LABEL shapes the fixture tree
// had never contained — a labelled BREAK and CONTINUE on nested loops, a
// labelled RETURN out of a lambda, a do-while loop, the range family
// (`..`, `until`, `downTo`, `step`), and a `tailrec` function. The taint
// half pins the shape a loop-lowering change would break: the tainted
// value is read INSIDE a labelled loop and sinks AFTER the labelled exits;
// the negative sinks a literal from the same shape.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want declaration name=countdown kind=function
// kosi:want-not flow source=untrusted-input sink=~ fn=~cleanLiteralLoop known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~taintedLoop known-fail=syntax:1
package dev.kosi.loops

/** `tailrec` with a default parameter: two shapes the tree lacked. */
tailrec fun countdown(n: Int = 5, acc: Int = 0): Int =
    if (n <= 0) acc else countdown(n - 1, acc + n)

/** Labelled break and continue across two ranges, plus a do-while. */
fun labelledLoop(): String {
    var collected = ""
    outer@ for (i in 0 until 8 step 2) {
        inner@ for (j in 10 downTo 8) {
            if (i == 4) continue@outer
            if (i + j > 13) {
                collected = "stopped at $i/$j"
                break@outer
            }
        }
    }
    var beats = 0
    do {
        beats += 1
    } while (beats < 3)
    return "$collected/$beats"
}

/** A labelled RETURN out of a lambda — not a loop exit, a lambda exit. */
fun labelledReturn(input: String): Int {
    val compute = run mapper@{
        if (input.isEmpty()) return@mapper -1
        input.length
    }
    return compute
}

fun taintedLoop(): String {
    var line = ""
    scan@ for (attempt in 1..3) {
        val next = readLine()
        when {
            next == null -> continue@scan
            next.startsWith("quit") -> break@scan
            else -> line = "answer $attempt: $next"
        }
    }
    // The sink sits OUTSIDE the loop: the value must survive the labelled
    // exits, the range conditionals, and the when arms.
    ProcessBuilder(line)
    return line
}

/** The near-miss negative: identical shape, no source. */
fun cleanLiteralLoop(): String {
    var line = ""
    scan@ for (attempt in 1..3) {
        line = "answer $attempt: literal"
    }
    ProcessBuilder(line)
    return line
}
