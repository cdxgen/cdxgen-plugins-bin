// construct-coverage fixture: EXPRESSION AND LITERAL shapes the
// fixture tree had never contained — a raw string, the not-null assertion
// (`!!`), a safe cast (`as?`), `try` used as an EXPRESSION, `runCatching`,
// a reflection literal over a class and over a function reference, and a
// `suspend` lambda type. The flow half pins `!!` on a taint path: the
// assertion is a desugaring the lowering must render as a branch, not as
// a taint cut; the negative is the safe-cast sibling that absorbs null.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want declaration name=loadConfig kind=function
// kosi:want-not flow source=untrusted-input sink=~ fn=~safeCastPath known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~assertedPath known-fail=syntax:1
package dev.kosi.expressions

/** The class a `::class` literal names. */
class Config(val seed: String)

/** A suspend lambda type: a functional shape the tree never carried. */
typealias AsyncStep = suspend (String) -> Int

fun loadConfig(): Config {
    // A raw string with an interpolated expression inside.
    val banner = """
        config for ${Config::class.simpleName}
    """.trimIndent()
    Config(banner.trim().length.toString())
    // A function-reference literal.
    val ref = ::loadConfig
    return ref()
}

fun assertedPath(): String {
    val raw = readLine()
    // `!!` must lower as a branch that PRESERVES the value's taint, never
    // as a cut: the slice must exist on the far side of the assertion.
    val seed = raw!!.trim()
    ProcessBuilder("seed:$seed")
    return seed
}

/** The `as?` half: the cast shapes the value, and this function SINKS
    NOTHING — the want-not pins that no flow leaves here. (A sink after an
    `as?` on a tainted value would be a real flow: a may-analysis cannot
    know a cast arm is dead.) The flow-bearing sibling is `assertedPath`'s
    `!!`, which must PRESERVE taint across the assertion. */
fun safeCastPath(): String {
    val raw: Any? = readLine()
    val value = raw as? String ?: "absent"
    return value.trim()
}

/** `try` as an expression beside `runCatching`. */
fun resilientParse(raw: String): Int =
    try {
        raw.length
    } catch (state: IllegalStateException) {
        -1
    } finally {
        Config("closed")
    }

fun catchingPath(raw: String): Int = runCatching { resilientParse(raw) }.getOrDefault(-2)

/** The suspend lambda value: created, stored, never run here. */
val step: AsyncStep = { input -> input.length }
