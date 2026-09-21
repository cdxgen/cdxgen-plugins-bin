// — the forwarders `by`-delegation generates.
//
// `class W(private val d: I): I by d` compiles to one override per member
// of I, each body `d.member(...)`. None of them has PSI, so a PSI-driven
// lowering emits nothing at all and `wrapper.body` resolves to an interface
// method with no implementation anywhere. This is the other half of
// taught the summary to carry a source that comes back inside an
// object's FIELD, and the 22 http4k findings still did not return because
// their consumers read that field through exactly these missing forwarders.
//
// Every want below is a flow that must cross a synthesized forwarder.
//
// Positive halves:
// kosi:want flow source=untrusted-input sink=process-exec fn=~propertyThroughDelegate known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~functionThroughDelegate known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~twoWrappersDeep known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~delegateOfObject known-fail=172 known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~throughOverriddenSibling known-fail=syntax:1
//
// Negative halves:
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanThroughDelegate
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~overrideWinsOverForwarder
// kosi:want-not diagnostic code=parse-error
package fixtures.delegate

interface Payload {
    /** An abstract `val` — no backing field, so a read of it RUNS the getter. */
    val body: String

    /** A member function taking the value onward. */
    fun render(prefix: String): String

    /** The clean sibling: forwarded too, but never carries the source. */
    val label: String
}

class RealPayload(private val raw: String) : Payload {
    override val body: String get() = raw
    override fun render(prefix: String): String = prefix + raw
    override val label: String get() = "constant-label"
}

/**
 * The wrapper the JVM fills in: `body`, `render` and `label` all exist on
 * this class as generated forwarders, and the source rides in through the
 * constructor into `inner`.
 */
class ContextPayload(private val inner: Payload, val context: String) : Payload by inner

fun propertyThroughDelegate() {
    val raw = readLine() ?: ""
    val wrapped: Payload = ContextPayload(RealPayload(raw), "ctx")
    Runtime.getRuntime().exec(wrapped.body)
}

fun functionThroughDelegate() {
    val raw = readLine() ?: ""
    val wrapped: Payload = ContextPayload(RealPayload(raw), "ctx")
    Runtime.getRuntime().exec(wrapped.render("sh -c "))
}

/** Two wrappers: the forwarder must compose with itself. */
fun twoWrappersDeep() {
    val raw = readLine() ?: ""
    val once: Payload = ContextPayload(RealPayload(raw), "a")
    val twice: Payload = ContextPayload(once, "b")
    Runtime.getRuntime().exec(twice.body)
}

/**
 * The delegate is an OBJECT expression's supertype, not a class's — the same
 * generated forwarders on a different declaration shape.
 *
 * `known-fail=172`: the forwarders ARE synthesized here (the KIR
 * carries `fixtures.delegate.<anonymous>.body` and the call site resolves to
 * it), and the flow still stops — because an object LITERAL is not lowered
 * as an object at all. `object: Payload by source {}` lowers to
 * `load "object <Payload by source>"`, a string placeholder, so nothing
 * connects the literal to the `source` it captures and the delegate field is
 * never written. That is a lowering gap older and wider than delegation —
 * every capturing object expression has it — and it is 's, not a
 * delegation defect.
 */
fun delegateOfObject() {
    val raw = readLine() ?: ""
    val source = RealPayload(raw)
    val wrapped = object : Payload by source {}
    Runtime.getRuntime().exec(wrapped.body)
}

/**
 * A wrapper that overrides ONE member and forwards the rest. The override
 * must win for `label` (the negative below) and the forwarder must still be
 * synthesized for `body` (this want).
 */
class LabelOverridingPayload(private val inner: Payload) : Payload by inner {
    override val label: String get() = "overridden"
}

fun throughOverriddenSibling() {
    val raw = readLine() ?: ""
    val wrapped: Payload = LabelOverridingPayload(RealPayload(raw))
    Runtime.getRuntime().exec(wrapped.body)
}

// ---- negatives ------------------------------------------------------------

/** The forwarded CLEAN member: `label` never carries the source. */
fun cleanThroughDelegate() {
    val raw = readLine() ?: ""
    val wrapped: Payload = ContextPayload(RealPayload(raw), "ctx")
    Runtime.getRuntime().exec(wrapped.label)
}

/**
 * The declared override replaces the forwarder: `LabelOverridingPayload.label`
 * returns a constant, so no synthesized `label` forwarder may exist to carry
 * the source. A synthesis that ignored declared members would publish here.
 */
fun overrideWinsOverForwarder() {
    val raw = readLine() ?: ""
    val wrapped: Payload = LabelOverridingPayload(RealPayload(raw))
    Runtime.getRuntime().exec(wrapped.label)
}
