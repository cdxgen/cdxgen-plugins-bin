// the depth report's DEPTH_CAP bucket had never been non-zero —
// the budget that bounds the fold had never BIND anywhere the report
// measured, which means the budget's population was a number nobody could
// see. The chain below assigns through ten hops, one past MAX_DEPTH = 8:
// the fold walks the stores (a store is a strong update, so each hop is
// honest) and runs out of budget before it reaches the literal. The refusal
// is named — DEPTH_CAP, counted in the report — never a silent stop.
//
// The want pins the honest outcome (unresolved); the want-not pins the
// literal: if the budget or the fold ever changes so this chain resolves,
// the corpus must NOTICE — a raised budget is a behaviour change that moves
// a published number, not a silent widening.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want service protocol=https resolution=unresolved mode=resolved
// kosi:want-not service protocol=https name=~deep.example.internal mode=resolved
package fixtures.depthcap

import okhttp3.Request

fun deepChain() {
    val hop1 = "https://deep.example.internal/path"
    val hop2 = hop1
    val hop3 = hop2
    val hop4 = hop3
    val hop5 = hop4
    val hop6 = hop5
    val hop7 = hop6
    val hop8 = hop7
    val hop9 = hop8
    val hop10 = hop9
    Request.Builder().url(hop10)
}
