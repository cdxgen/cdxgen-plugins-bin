// Two shapes that LOOK like the function-value spellings P33 taught the
// engine to follow, and are not. Both were false positives the phase shipped
// and the review found: the corpus had nothing that could see them, because
// every function-value fixture until now was written to be FOUND.
//
// A negative fixture for a recall feature is not optional. A channel that
// resolves an invoke to a body is only worth having if it declines the
// bodies that are not the callee, and nothing here should ever produce a
// flow — `kosi:want-not` is the whole file.
//
// kosi:want-not flow source=untrusted-input sink=process-exec
// kosi:want-not diagnostic code=parse-error
package fixtures.lookalike

// ---- R206: a member and a local that share a name -----------------------

class Holder(val f: (String) -> Unit)

// `h.f(raw)` resolves to the MEMBER. A pure-PSI name walk looking for a
// function-typed `f` in scope finds the LOCAL first and binds the taint to
// its body — a flow through a lambda this function never invokes. The local
// takes two parameters precisely so the mis-binding is visible: the tainted
// argument lands on parameter 1.
fun viaShadowedMember(h: Holder) {
    val f: (String, String) -> Unit = { _, s -> Runtime.getRuntime().exec(s) }
    h.f(readLine() ?: "")
}

// ---- R207: a factory named after its return type ------------------------

interface Handler {
    fun handle(s: String)
}

// Not a SAM conversion: an ordinary function that happens to be named after
// the interface it returns, and IGNORES the block it is handed. Kotlin's
// resolution prefers it over the interface's SAM constructor, so this is the
// call that runs. Recognising a SAM by its KIR shape — one `FunctionN`
// parameter, returning the callee's own name — cannot tell the two apart.
//
// The returned implementation must live OUTSIDE the workspace for the shape
// to be reachable at all: when the workspace implements the interface, the
// call index resolves `handle` on its own and the SAM channel never runs.
// That is the guard working — and it is why this fixture hands back an
// implementation it does not carry, which is the ordinary arrangement for a
// factory whose implementation ships in a library.
@Suppress("FunctionName")
fun Handler(block: (String) -> Unit): Handler = platformHandler()

private fun platformHandler(): Handler = TODO("supplied by the platform")

fun viaLookalikeFactory() {
    val h = Handler { s -> Runtime.getRuntime().exec(s) }
    h.handle(readLine() ?: "")
}
