// Negative half first: raw operator symbols are not usable usage names —
// R18 fixed exactly this, and a regression to emitting `+` instead of the
// named function must fail here (a vacuous positive would not catch it).
// kosi:want-not usage name=+ kind=operator
// kosi:want-not usage name=* kind=operator
// kosi:want-not usage name=< kind=operator
// kosi:want-not diagnostic code=lowering-failed
//
// Positive half: operators are reported under their named functions and
// lower to the same names in the KIR (§4, operators -> named calls).
// kosi:want usage name=plus kind=operator
// kosi:want usage name=times kind=operator
// kosi:want usage name=compareTo kind=operator
// kosi:want declaration name=combine kind=function
// kosi:want declaration name=area kind=function
// kosi:want declaration name=ordered kind=function
package fixtures.operators

fun combine(a: Int, b: Int): Int = a + b

fun area(width: Int, height: Int): Int = width * height

fun ordered(a: Int, b: Int): Boolean = a < b
