// — one capability, every spelling.
//
// built the channel that carries taint through a function value and
// proved it with `{ payload -> ... }`. The review found the channel dead for
// Kotlin's implicit `it`, because every fixture and every probe in the change
// spelled the parameter out. This gallery is the generalisation: one
// flow — `readLine()` to `Runtime.exec` — written in every spelling of the
// language the engine claims to handle, so a capability that holds in one
// spelling and not its sibling FAILS HERE rather than shipping.
//
// Each entry point below is one spelling. The wants say which are found; the
// known-fails say which are not, each tied to a numbered defect. There is no
// third state: a spelling that is neither wanted nor known-failed is a
// spelling nobody decided about.
//
// kosi:want-not diagnostic code=parse-error
//
// ---- lambda spellings, through a user-defined function-valued parameter
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaTrailingNamed known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaImplicitIt known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaNamedArgument known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaTwoParameters known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaUnderscoreFirst known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaDestructured known-fail=syntax:1 known-fail=154
// ---- function values
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaLocalFunReference known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaTopLevelReference known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaBoundReference known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~<anonymous> known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaLocalValueReference known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaConstructorReference known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaFunctionInField known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaFunctionInList known-fail=syntax:1
// ---- SAM and object expressions
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaFunInterface known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaJavaSam known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaObjectExpression known-fail=syntax:1 known-fail=157
// ---- receivers
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaExtensionFunction known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaApplyScope known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaExtensionLambda known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaReceiverIgnored known-fail=syntax:1
// ---- dispatch shapes
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaInterface known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaAbstractClass known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaOpenOverride known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaSealed known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaObjectSingleton known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaCompanion known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~viaJvmStatic known-fail=syntax:1
package fixtures.spelling

// ---- the shared shapes -------------------------------------------------

private fun feed(f: (String) -> Unit) {
    val raw = readLine() ?: ""
    f(raw)
}

private fun feedTwo(f: (String, Int) -> Unit) {
    val raw = readLine() ?: ""
    f(raw, 1)
}

private fun feedIntFirst(f: (Int, String) -> Unit) {
    val raw = readLine() ?: ""
    f(1, raw)
}

private fun feedPair(f: (Pair<String, Int>) -> Unit) {
    val raw = readLine() ?: ""
    f(raw to 1)
}

private fun exec(s: String) {
    Runtime.getRuntime().exec(s)
}

// ---- lambda spellings ---------------------------------------------------

fun viaTrailingNamed() = feed { s -> Runtime.getRuntime().exec(s) }

fun viaImplicitIt() = feed { Runtime.getRuntime().exec(it) }

fun viaNamedArgument() = feed(f = { s -> Runtime.getRuntime().exec(s) })

fun viaTwoParameters() = feedTwo { s, _ -> Runtime.getRuntime().exec(s) }

fun viaUnderscoreFirst() = feedIntFirst { _, s -> Runtime.getRuntime().exec(s) }

// A destructured lambda parameter binds no register the engine can
// name, so the component the taint is in is lost at the `(a, b)` binding.
fun viaDestructured() = feedPair { (s, _) -> Runtime.getRuntime().exec(s) }

// ---- function values ----------------------------------------------------

fun viaLocalFunReference() {
    // The local function's name carries the entry point's, because a local
    // `fun` is HOISTED to a package-qualified KIR function and the slice
    // names it as the sink — the want has to be able to say which spelling
    // produced the flow.
    fun viaLocalFunReferenceSink(s: String) = Runtime.getRuntime().exec(s)
    feed(::viaLocalFunReferenceSink)
}

fun viaTopLevelReferenceSink(s: String) {
    Runtime.getRuntime().exec(s)
}

fun viaTopLevelReference() = feed(::viaTopLevelReferenceSink)

class BoundRunner {
    fun viaBoundReferenceSink(s: String) {
        Runtime.getRuntime().exec(s)
    }
}

fun viaBoundReference() = feed(BoundRunner()::viaBoundReferenceSink)

fun viaAnonymousFun() = feed(fun(s: String) { Runtime.getRuntime().exec(s) })

fun viaLocalValueReference() {
    val f = ::exec
    f(readLine() ?: "")
}

// A constructor reference names `<init>`. The object it builds then has to
// reach a method ON that object, which means the invoke's RESULT is the
// `<init>` body's parameter 0 — binding it to nothing threw the new object
// away and the flow stopped at the construction.
class Command(val value: String) {
    fun run() {
        Runtime.getRuntime().exec(value)
    }
}

fun viaConstructorReference() {
    val make: (String) -> Command = ::Command
    make(readLine() ?: "").run()
}

// A function value stored in an object's field or in a collection. Both are
// invoked through a READ — `h.f` and `fs[0]` — and the lowering used to drop
// that read, handing the invoke the holder (or nothing at all) instead of the
// function. The read is the function value; the invoke takes it as receiver.
class FunctionHolder(val f: (String) -> Unit)

fun viaFunctionInField() {
    val h = FunctionHolder { s -> Runtime.getRuntime().exec(s) }
    h.f(readLine() ?: "")
}

fun viaFunctionInList() {
    val fs = listOf<(String) -> Unit>({ s -> Runtime.getRuntime().exec(s) })
    fs[0](readLine() ?: "")
}

// ---- SAM and object expressions -----------------------------------------

fun interface Bridge {
    fun cross(s: String)
}

// A SAM conversion is an identity on the function value: the object runs
// exactly the lambda it was handed, so the token survives the conversion and
// `b.cross` resolves to the lambda even though `Bridge` has no workspace
// implementation.
fun viaFunInterface() {
    val b = Bridge { s -> Runtime.getRuntime().exec(s) }
    b.cross(readLine() ?: "")
}

fun viaJavaSam() {
    val raw = readLine() ?: ""
    val r = Runnable { Runtime.getRuntime().exec(raw) }
    r.run()
}

// An anonymous object still lowers to a STRING PLACEHOLDER — `load "object
// <Writer>"` — and the call on it has no callee name at all. Its members lower
// as functions, but nothing connects the literal to them. Counted since P33 in
// `stats.unnameableInvokes`, so the miss is visible even while it is open.
interface Writer {
    fun write(s: String)
}

fun viaObjectExpression() {
    val w = object : Writer {
        override fun write(s: String) {
            Runtime.getRuntime().exec(s)
        }
    }
    w.write(readLine() ?: "")
}

// ---- receivers ----------------------------------------------------------

fun String.sinkExtension() {
    Runtime.getRuntime().exec(this)
}

fun viaExtensionFunction() = (readLine() ?: "").sinkExtension()

class Builder {
    var cmd: String = ""

    fun go() {
        Runtime.getRuntime().exec(cmd)
    }
}

fun viaApplyScope() {
    val raw = readLine() ?: ""
    Builder().apply { cmd = raw }.go()
}

// An extension lambda's receiver is a parameter with no name at the
// call, so a write through `this` inside the block reaches no caller object.
private fun build(block: Builder.() -> Unit) {
    val b = Builder()
    b.block()
    b.go()
}

fun viaExtensionLambda() {
    val raw = readLine() ?: ""
    build { cmd = raw }
}

// The same extension-lambda receiver, IGNORED: the block declares a value
// parameter and never touches `this`. The invoke passes the receiver as its
// argument 0 regardless, so a body that declined the receiver parameter
// bound every value argument one position off — the tainted string landed on
// a parameter the block's own receiver should have occupied, and the flow
// was silent while the writing spelling above was found. The receiver
// convention lives on KirLambda; this spelling pins the ignoring half of it.
private fun withExt(b: Builder, raw: String, block: Builder.(String) -> Unit) {
    b.block(raw)
}

fun viaReceiverIgnored() {
    val raw = readLine() ?: ""
    withExt(Builder(), raw) { s -> exec(s) }
}

// ---- dispatch shapes ----------------------------------------------------

interface Sink {
    fun write(s: String)
}

class ExecSink : Sink {
    override fun write(s: String) {
        Runtime.getRuntime().exec(s)
    }
}

fun viaInterface(sink: Sink = ExecSink()) = sink.write(readLine() ?: "")

abstract class AbstractBase {
    abstract fun write(s: String)
}

class ExecAbstract : AbstractBase() {
    override fun write(s: String) {
        Runtime.getRuntime().exec(s)
    }
}

fun viaAbstractClass(b: AbstractBase = ExecAbstract()) = b.write(readLine() ?: "")

open class OpenBase {
    open fun write(s: String) {}
}

class ExecOpen : OpenBase() {
    override fun write(s: String) {
        Runtime.getRuntime().exec(s)
    }
}

fun viaOpenOverride(b: OpenBase = ExecOpen()) = b.write(readLine() ?: "")

sealed class SealedCmd {
    abstract fun write(s: String)
}

class ExecSealed : SealedCmd() {
    override fun write(s: String) {
        Runtime.getRuntime().exec(s)
    }
}

fun viaSealed(c: SealedCmd = ExecSealed()) = c.write(readLine() ?: "")

object SingletonSink {
    fun write(s: String) {
        Runtime.getRuntime().exec(s)
    }
}

fun viaObjectSingleton() = SingletonSink.write(readLine() ?: "")

class WithCompanion {
    companion object {
        fun write(s: String) {
            Runtime.getRuntime().exec(s)
        }
    }
}

fun viaCompanion() = WithCompanion.write(readLine() ?: "")

class WithJvmStatic {
    companion object {
        @JvmStatic
        fun write(s: String) {
            Runtime.getRuntime().exec(s)
        }
    }
}

fun viaJvmStatic() = WithJvmStatic.write(readLine() ?: "")
