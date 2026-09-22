// Three levels of interface indirection: the rung (three implementations,
// one sinks), a function-valued parameter at the second level, and a SAM
// conversion at the third. Exactly one path sinks per entry point.
//
// Negative half first: the sibling entry point carries the SAME taint through
// the SAME SAM bridge into a body that does not sink - the channel must carry
// the value without inventing a finding.
//
// This used to read `bridge.cross(safe, raw)` against a lambda that called
// `target.apply(payload)`, and it was green for a reason that was not a
// result: the SAM channel was DEAD (R147), so nothing ever ran this shape.
// With R147 closed the flow is found, because `target.apply` may-dispatches
// to every implementation of `Rung` - ExecRung among them - exactly as the
// POSITIVE half below relies on. `safe` and `rung` are identically-typed
// fields of a class nothing constructs, so no amount of dispatch precision
// available today separates them; the old wording tested a distinction the
// engine cannot make and only passed while unreachable. R202 tracks the
// underlying gap: dispatch inside a function VALUE's body is resolved
// without the caller's argument types, so narrowing stops at the invoke.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~walkSafe
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the function-valued bridge and the SAM bridge, each naming
// its frames in order.
// kosi:want flow source=untrusted-input sink=process-exec fn=~walkDeep frames=6 via=fn:~Step.execute,fn:~ExecRung.apply
//
// The SAME rung reached through Kotlin's IMPLICIT lambda parameter. The
// review's probe found that the function-valued channel worked only when the
// lambda DECLARED its parameter: `{ payload -> ... }` published the flow and
// `{ ... it ... }` — the commoner spelling by far — published nothing,
// because the extraction gave a parameterless lambda no value parameter and
// the invoke-bind had nothing to address. One capability, two spellings, and
// this is the want that says so.
// kosi:want flow source=untrusted-input sink=process-exec fn=~walkImplicit frames=6 via=fn:~Step.execute,fn:~ExecRung.apply
// kosi:want flow source=untrusted-input sink=process-exec fn=~walkSam frames=5 via=fn:~ExecRung.apply
//
package fixtures.deep.ladder

interface Rung {
    fun apply(payload: String)
}

class ExecRung : Rung {
    override fun apply(payload: String) {
        Runtime.getRuntime().exec(payload)
    }
}

class LogRung : Rung {
    override fun apply(payload: String) {
        println("run: $payload")
    }
}

class NoopRung : Rung {
    override fun apply(payload: String) {}
}

/** Not a [Rung]: a concrete class, so a call on it has exactly one callee. */
class Recorder {
    fun record(payload: String) {
        println("record: $payload")
    }
}

fun interface Bridge {
    fun cross(rung: Rung, payload: String)
}

class Step(private val rung: Rung) {
    fun execute(payload: String, pass: (String) -> Unit) {
        pass(payload)
    }
}

class Ladder(private val step: Step, private val rung: Rung, private val safe: Recorder) {
    fun walkDeep() {
        val raw = readLine() ?: ""
        step.execute(raw) { payload -> rung.apply(payload) }
    }

    fun walkImplicit() {
        val raw = readLine() ?: ""
        step.execute(raw) { rung.apply(it) }
    }

    fun walkSam() {
        val raw = readLine() ?: ""
        val bridge = Bridge { target, payload -> target.apply(payload) }
        bridge.cross(rung, raw)
    }

    fun walkSafe() {
        val raw = readLine() ?: ""
        // Concrete, non-sinking, no interface dispatch: the one formulation
        // whose verdict depends on the channel rather than on a dispatch
        // precision kosi does not have.
        val bridge = Bridge { _, payload -> safe.record(payload) }
        bridge.cross(rung, raw)
    }
}
