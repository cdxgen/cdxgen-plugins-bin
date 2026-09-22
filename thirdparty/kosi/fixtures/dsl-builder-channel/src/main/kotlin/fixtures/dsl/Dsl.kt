// The DSL builder channel — R158's witness and its negatives.
//
// `build { cmd = raw }` is the idiom Gradle and Android code is made of: a
// higher-order function takes an extension lambda over a builder, the block
// writes through its implicit `this`, and the builder is CONSUMED LATER —
// here by `go()`, inside the very function that ran the block. Both lowering
// halves have been right since P33 (the invoke passes the builder as the
// lambda's argument 0, the body takes it as `%r0`); the flow still died
// because the invoked-parameter summary channel carried only the lambda's
// own `sinkEffects`, never its `paramFieldWrites` feeding the callee's later
// flow. The callee now records the parametric half — argument 0 of the
// invoked block, read at `cmd`, reaches `go`'s sink — and the caller
// completes it with the block's write of its capture into that argument.
//
// The two want-nots are the precision half of the same channel: a block that
// writes a CLEAN value moves nothing, and a block that writes the WRONG
// field (the sink reads `cmd`, the block writes `label`) must not fire
// through it. If either starts reporting, the channel is over-firing — a
// false positive of the engine, not a fixture to edit.
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaDsl known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaDslValueParam known-fail=syntax:1
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDslClean
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDslOtherField
// kosi:want-not diagnostic code=parse-error
package fixtures.dsl

class Builder {
    var cmd: String = "safe"
    var label: String = "safe"

    fun go() {
        Runtime.getRuntime().exec(cmd)
    }
}

// The idiom: the block writes its CAPTURE through the receiver, the sink
// fires later in the callee that ran the block.
private fun build(block: Builder.() -> Unit) {
    val b = Builder()
    b.block()
    b.go()
}

fun viaDsl() {
    val raw = readLine() ?: ""
    build { cmd = raw }
}

// The same channel with the written value arriving as the block's own VALUE
// parameter instead of a capture — `withTwo(b, raw) { s -> cmd = s }`, the
// spelling R210's shift silently mis-bound before the receiver convention
// was made unconditional.
private fun buildWithValue(b: Builder, raw: String, block: Builder.(String) -> Unit) {
    b.block(raw)
    b.go()
}

fun viaDslValueParam() {
    val raw = readLine() ?: ""
    buildWithValue(Builder(), raw) { s -> cmd = s }
}

// Negative: the block writes, but a constant — nothing moves.
fun viaDslClean() {
    build { cmd = "constant" }
}

// Negative: the block writes the field the sink never reads.
fun viaDslOtherField() {
    val raw = readLine() ?: ""
    build { label = raw }
}
