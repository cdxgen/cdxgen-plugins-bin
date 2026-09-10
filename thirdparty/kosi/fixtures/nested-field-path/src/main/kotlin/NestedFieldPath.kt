// Access paths DEEPER THAN ONE FIELD, the question no fixture asked until
// the P5/P6 review (R63). `AccessPath` has carried a list of elements with a
// depth cap of 5 since P2 and both engines join those elements into the key
// they read and write — but the lowering only ever emitted paths of length
// one, so `o.inner.a = readLine()` wrote a key hanging off a temporary and
// the matching read looked at a DIFFERENT temporary. Every nested field flow
// was invisible, and taint-recall still read 1.000 because the whole corpus
// was flat.
//
// Both halves are here, because a positive alone would pass just as well by
// collapsing paths to the receiver:
//   deepTainted   the write and the read agree at depth two   -> a slice
//   deepClean     the sibling ONE LEVEL DOWN is read instead  -> silent
// Collapsing `.inner.a` to `.inner` (or to `o`) reports on deepClean and
// breaks the negative; dropping the composition entirely loses deepTainted.
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~deepTainted known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~deepAcrossCall known-fail=syntax:1
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~deepClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
package fixtures.nestedfieldpath

class Inner {
    var a: String = ""
    var b: String = ""
}

class Outer {
    var inner: Inner = Inner()
}

fun deepTainted() {
    val o = Outer()
    o.inner.a = readLine() ?: ""
    ProcessBuilder(o.inner.a)
}

fun deepClean() {
    val o = Outer()
    o.inner.a = readLine() ?: ""
    ProcessBuilder(o.inner.b)
}

fun sinkDeep(o: Outer) {
    ProcessBuilder(o.inner.a)
}

// The same depth, but the read happens in a callee: the summary has to carry
// the two-element parameter path across the boundary as well.
fun deepAcrossCall() {
    val o = Outer()
    o.inner.a = readLine() ?: ""
    sinkDeep(o)
}
