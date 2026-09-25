// An SCC still moving after four visits per member while a key holds over
// 256 facts switches to ADAPTIVE widening: walk's `p0.next.next.v` becomes
// `p0.next.*`. With exact lookups the widened path missed the deeper read,
// and the flow main finds was lost in default mode (atom-tools#95 review).
//
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=process-exec fn=~lostThroughAdaptive mode=resolved
//
// Negative half: the same walk with no source is clean.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanWalk
package fixtures.widened.adaptive

class Leaf(val f0: String, val f1: String, val f2: String, val f3: String, val f4: String, val f5: String, val f6: String, val f7: String, val f8: String, val f9: String, val f10: String, val f11: String, val f12: String, val f13: String, val f14: String, val f15: String, val f16: String)

class Mid(val g0: Leaf, val g1: Leaf, val g2: Leaf, val g3: Leaf, val g4: Leaf, val g5: Leaf, val g6: Leaf, val g7: Leaf, val g8: Leaf, val g9: Leaf, val g10: Leaf, val g11: Leaf, val g12: Leaf, val g13: Leaf, val g14: Leaf, val g15: Leaf, val g16: Leaf)

fun pickG(m: Mid, k: Int): Leaf = when (k) {
    0 -> m.g0
    1 -> m.g1
    2 -> m.g2
    3 -> m.g3
    4 -> m.g4
    5 -> m.g5
    6 -> m.g6
    7 -> m.g7
    8 -> m.g8
    9 -> m.g9
    10 -> m.g10
    11 -> m.g11
    12 -> m.g12
    13 -> m.g13
    14 -> m.g14
    15 -> m.g15
    else -> m.g16
}

fun pickF(l: Leaf, k: Int): String = when (k) {
    0 -> l.f0
    1 -> l.f1
    2 -> l.f2
    3 -> l.f3
    4 -> l.f4
    5 -> l.f5
    6 -> l.f6
    7 -> l.f7
    8 -> l.f8
    9 -> l.f9
    10 -> l.f10
    11 -> l.f11
    12 -> l.f12
    13 -> l.f13
    14 -> l.f14
    15 -> l.f15
    else -> l.f16
}


class Node(val v: String, val next: Node?)

/** Recursive: its field paths grow one level per SCC visit, and one key holds 17 x 17 facts. */
fun walk(n: Node, m: Mid, k: Int): String =
    if (k == 0) n.v else if (k == 1) pickF(pickG(m, k), k) else walk(n.next!!, m, k - 1)

fun lostThroughAdaptive(m: Mid) {
    val src = readLine() ?: ""
    val n = Node("", Node("", Node(src, null)))
    Runtime.getRuntime().exec(walk(n, m, 2))
}

/** The same recursive walk with no source on the path: never a flow. */
fun cleanWalk(m: Mid) {
    val n = Node("", Node("", Node("constant", null)))
    Runtime.getRuntime().exec(walk(n, m, 2))
}
