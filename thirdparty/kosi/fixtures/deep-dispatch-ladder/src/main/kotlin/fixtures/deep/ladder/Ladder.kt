// Three levels of interface indirection: the rung (three implementations,
// one sinks), a function-valued parameter at the second level, and a SAM
// conversion at the third. Exactly one path sinks per entry point.
//
// Negative half first: the sibling entry point walks the same shape through
// a NON-sinking implementation - dispatch must not smear the finding.
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
// kosi:want flow source=untrusted-input sink=process-exec fn=~walkSam frames=5 via=fn:~ExecRung.apply known-fail=147
//
// a SAM conversion's synthesized class is invisible to the workspace
// KIR - `Bridge { ... }` has no lowered implementation, so `bridge.cross`
// resolves to nothing and the taint dies at the call. (Kotlin,
// precisely) owns the SAM lowering.
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

fun interface Bridge {
    fun cross(rung: Rung, payload: String)
}

class Step(private val rung: Rung) {
    fun execute(payload: String, pass: (String) -> Unit) {
        pass(payload)
    }
}

class Ladder(private val step: Step, private val rung: Rung, private val safe: Rung) {
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
        val bridge = Bridge { target, payload -> target.apply(payload) }
        bridge.cross(safe, raw)
    }
}
