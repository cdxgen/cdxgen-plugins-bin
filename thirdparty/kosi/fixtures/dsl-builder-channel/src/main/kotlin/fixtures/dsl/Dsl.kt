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
// The three want-nots are the precision half of the same channel: a block
// that writes a CLEAN value moves nothing, a block that writes the WRONG
// field (the sink reads `cmd`, the block writes `label`) must not fire
// through it, and a builder that CONSUMES BEFORE IT CONFIGURES must not
// either — the last one reported until the recording became order-aware, and
// it is the one that fails first if the reachability guard is removed. If any
// starts reporting, the channel is over-firing — a false positive of the
// engine, not a fixture to edit.
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaDsl known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaDslValueParam known-fail=syntax:1
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDslClean
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDslOtherField
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~viaDslAfterSink
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaDslDirectSink known-fail=syntax:1 known-fail=213
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

// Negative: ORDER. The builder consumes before it configures, so the block's
// write can never reach the sink. The channel that carries the idiom above is
// otherwise flow-insensitive — it matches an invoke of the function value
// against a sink anywhere in the same body — and reported this shape until
// the recording asked whether the invoke can REACH the sink in the CFG.
// Reachability, not site order: a loop that sinks then configures does move
// taint on the next iteration, and the back edge says so.
private fun buildLate(block: Builder.() -> Unit) {
    val b = Builder()
    b.go()
    b.block()
}

fun viaDslAfterSink() {
    val raw = readLine() ?: ""
    buildLate { cmd = raw }
}

// The same idiom with the sink in the BUILDER'S OWN body rather than in a
// callee it invokes — `exec(b.cmd)` instead of `b.go()`. Open (R213): the
// channel is recorded while applying a CALLEE's summary, so a builder that
// sinks directly records nothing. `b` is a local, not a parameter, so the
// body has no sink effect of its own to hang the argument on.
private fun buildDirect(block: Builder.() -> Unit) {
    val b = Builder()
    b.block()
    Runtime.getRuntime().exec(b.cmd)
}

fun viaDslDirectSink() {
    val raw = readLine() ?: ""
    buildDirect { cmd = raw }
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
