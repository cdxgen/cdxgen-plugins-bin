// construct-coverage fixture: CLASS-SHAPE declarations the fixture
// tree had never contained — an `init` block, an `inner` class, an
// anonymous object expression, a `data object`, `protected` members, a
// `lateinit var`, a property with a custom getter and setter over its
// backing field, named arguments at a call site, `@Deprecated` with named
// annotation arguments, and the `@JvmName`/`@JvmStatic`/`@JvmField`/
// `@JvmOverloads` family. The flow annotations keep the shapes honest: a
// taint chain through the custom setter's backing field, and the clean
// sibling that must stay silent.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want declaration name=Registry kind=class
// kosi:want-not flow source=untrusted-input sink=~ fn=~cleanLookup known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=process-exec fn=~storeThenRun known-fail=syntax:1
package dev.kosi.classes

/**
 * The annotated-API surface: each annotation below is a PSI shape the
 * native image had never been asked to resolve.
 */
@Deprecated(message = "use Registry2", replaceWith = ReplaceWith("Registry2"))
class Registry {

    /** `init` blocks run between the primary constructor and members. */
    init {
        Opened.registry = this
    }

    /** A custom getter/setter over the BACKING FIELD. */
    var origin: String = "unset"
        get() = "origin:$field"
        set(value) {
            field = value.trim()
        }

    /** Assigned later: `lateinit`. */
    lateinit var label: String

    /** `protected` visibility — absent from every earlier fixture. */
    protected fun secure(): String = "protected"

    /** Named arguments at the call site. */
    fun describe(id: Int = 0, note: String = "none"): String = "$id=$note"

    /** A JVM-overloads surface: defaults compile to synthetic bridges. */
    @JvmOverloads
    fun open(port: Int = 8080, host: String = "localhost"): String = "$host:$port"
}

/** The anonymous-object carrier the mock-application shape needs. */
interface Opened {
    var registry: Registry?

    companion object {
        /** `@JvmField` on a companion member. */
        @JvmField
        var opened: Int = 0
    }
}

/** A `data object` (Kotlin 2.0+) next to an `inner` class. */
data object DefaultRegistry : Opened {
    override var registry: Registry? = null
}

class Group(val name: String) {

    /** `inner`: carries the outer receiver into its bodies. */
    inner class Member(val id: Int) {
        fun render(): String = "$name#$id"
    }
}

/** `@JvmStatic` and `@JvmName` on facade members. */
object Factories {
    var constructed = 0
        @JvmName("constructedCount") get

    @JvmStatic
    fun newRegistry(): Registry {
        constructed += 1
        return Registry()
    }
}

fun storeThenRun(): String {
    val registry = Factories.newRegistry()
    registry.origin = readLine() ?: "unset"
    val member = Group("g").Member(7)
    val observer = object : Runnable {
        override fun run() {
            registry.label = "observed"
        }
    }
    observer.run()
    ProcessBuilder(registry.origin)
    return member.render()
}

/** The near-miss negative: same writes, no source. */
fun cleanLookup(): String {
    val registry = Factories.newRegistry()
    registry.origin = "literal"
    ProcessBuilder(registry.origin)
    return registry.describe(id = 3, note = "clean")
}
