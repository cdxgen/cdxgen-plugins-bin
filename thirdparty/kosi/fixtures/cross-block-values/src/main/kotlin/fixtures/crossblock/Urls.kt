// P20 §2 (review): the value the fold can only reach by leaving the block.
//
// §2 extended `KirValueFolder` across blocks along the dominator chain,
// with a conservative phi join. The §0 depth report then measured the
// endpoint consumers both ways — the shipped fold and `crossBlock = false`
// — and both columns read `crossBlock: 0` over all 93 bundled fixtures:
// not one asked value ever left its block, so the two columns agreed on
// every row and the baseline could not tell the extension from its own
// absence. A capability no fixture exercises does not exist (R63), and a
// baseline column that never differs from the shipped one proves nothing
// (R53's shape, one layer inside the depth report). This fixture is the
// shape that makes the distinction observable in the REPORT, not only in
// `KirValueFolderCrossBlockTest`'s hand-built IR.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The dominator walk: `endpoint` is defined once, in the block that
// dominates the use, and the use sits after a branch has closed that
// block. Pre-§2 this is UNRESOLVED; with §2 it is the literal.
// kosi:want service protocol=https name=dominating.example.com resolution=literal mode=resolved
//
// The conservative join, both verdicts. Arms that agree fold to the value
// they agree on; arms that disagree are unresolved — NOT the first arm,
// which is the failure mode a guessing join would show as a confident
// wrong host.
// kosi:want service protocol=https name=phi-agree.example.com resolution=literal mode=resolved
// kosi:want-not service protocol=~ name=phi-first.example.com mode=resolved
// kosi:want-not service protocol=~ name=phi-second.example.com mode=resolved
package fixtures.crossblock

import okhttp3.Request

fun sideEffect(value: String): Int = value.length

/** The def dominates the use and no other block defines it: folds. */
fun dominatingDefinition(flag: Boolean): Any {
    val endpoint = "https://dominating.example.com/v1/items"
    if (flag) {
        sideEffect(endpoint)
    }
    return Request.Builder().url(endpoint)
}

/** Every arm folds to the SAME value: the join folds to it. */
fun agreeingArms(flag: Boolean): Any {
    val host = if (flag) {
        "https://phi-agree.example.com/a"
    } else {
        "https://phi-agree.example.com/a"
    }
    return Request.Builder().url(host)
}

/** The arms disagree: unresolved, and neither arm is published. */
fun disagreeingArms(flag: Boolean): Any {
    val host = if (flag) {
        "https://phi-first.example.com/a"
    } else {
        "https://phi-second.example.com/b"
    }
    return Request.Builder().url(host)
}
