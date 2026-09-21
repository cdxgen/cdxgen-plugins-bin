// construct-coverage fixture: GENERIC SHAPES the fixture tree had never
// contained. Swept from the grammar, not from memory: declaration-site
// variance (`out`/`in`), star projections, `where` clauses on one type
// parameter, annotations ON a type argument, a `fun interface` (the
// Kotlin-side SAM), a `typealias` over a function type, a `@JvmInline`
// value class, and nested generic arguments. The flow annotations pin the
// shapes a type-heavy lowering must not lose; the negative is the clean
// sibling through the same generic helper.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want declaration name=Token kind=class
// kosi:want declaration name=Mapper kind=interface
// kosi:want-not flow source=untrusted-input sink=~ fn=~cleanViaSam known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~taintedViaSam known-fail=syntax:1
package dev.kosi.shapes

/** A TYPE-position annotation: parsed only in annotation-on-type-arg code. */
@Target(
    AnnotationTarget.TYPE,
    AnnotationTarget.VALUE_PARAMETER,
    AnnotationTarget.CLASS,
)
annotation class Tagged(val stage: String)

/** Declaration-site variance, the producer half. */
class Box<out T>(private val value: T) {
    fun get(): T = value
}

/** The consumer half, so `in`-variance is in the tree too. */
class Sink<in T> {
    fun accept(value: @Tagged("in") T) {
        last = value
    }

    var last: @Tagged("field") T? = null
}

/** A Kotlin SAM: one abstract method, invoked through the fun interface. */
fun interface Mapper {
    fun map(raw: String): Int
}

/** A typealias over a function type. */
typealias Handler = (String) -> Int

/** The value-class shape (an inline class under the hood). */
@JvmInline
value class Token(val raw: String)

/**
 * A `where` clause with two bounds and a STAR PROJECTION beside nested
 * generic arguments — four type shapes in one signature.
 */
fun <T> transfer(
    source: Box<T>,
    target: Box<out CharSequence>,
    table: Map<String, List<Int>>,
) where T : CharSequence, T : Comparable<T> {
    ProcessBuilder(source.get().toString())
}

fun taintedViaSam(): Int {
    val raw = readLine() ?: ""
    val mapper = Mapper { input -> input.length }
    val width = mapper.map("token:$raw")
    ProcessBuilder("token:$raw")
    return width
}

/** The near-miss negative: the same SAM, a literal only. */
fun cleanViaSam(): Int {
    val mapper = Mapper { input -> input.length }
    return mapper.map("literal")
}
