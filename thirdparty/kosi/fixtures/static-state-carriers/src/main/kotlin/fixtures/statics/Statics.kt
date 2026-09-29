// State that outlives a call. A static field — an `object`'s, a companion's,
// the file's top level — has no scope: what one function stores there any
// other reads, so the store seeds every read of the field. A container
// singleton's fields are shared the same way across the handlers it serves.
// A plain class's field belongs to one instance, and a prototype-scoped bean
// is constructed per use: neither carries between unrelated calls.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.statics.useOther mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.statics.Plain.use mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.statics.PrototypeHandlers.use mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.statics.Handlers.useClean mode=endpoint
// kosi:want-not flow source=untrusted-input sink=process-exec fn=fixtures.statics.useBoxSibling mode=endpoint
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.useObject mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.useTopLevel mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.Session.use mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.readCommand mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.useCopied mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.Context.use mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.Context.sameFunction mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.Handlers.use mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.Plain.store mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=fixtures.statics.useBox mode=endpoint
package fixtures.statics

import java.io.BufferedReader
import java.io.InputStreamReader
import org.springframework.context.annotation.Scope
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

object Registry {
    var command: String = ""
    var other: String = "echo ok"
}

var lastCommand: String = ""

object Copy {
    var held: String = ""
}

fun storeObject() {
    Registry.command = readLine() ?: ""
}

fun useObject(): String = run(Registry.command)

fun useOther(): String = run(Registry.other)

fun storeTopLevel() {
    lastCommand = readLine() ?: ""
}

fun useTopLevel(): String = run(lastCommand)

// The helper's read is where the seed births; the slice starts there.
fun readCommand(): String = Registry.command

fun useThroughHelper(): String = run(readCommand())

fun copyAcross() {
    Copy.held = Registry.command
}

fun useCopied(): String = run(Copy.held)

// A field of the object a static holds: `Shelf.box.label` written and read
// through the static, whichever way the chain is spelled.
class Box {
    var label: String = ""
    var other: String = "echo ok"
}

object Shelf {
    val box = Box()
}

fun storeBox() {
    Shelf.box.label = readLine() ?: ""
}

fun useBox(): String = run(Shelf.box.label)

fun useBoxSibling(): String = run(Shelf.box.other)

class Session {
    companion object {
        var token: String = ""
    }

    fun store() {
        token = readLine() ?: ""
    }

    fun use(): String = run(token)
}

class Context {
    private val current = ThreadLocal<String>()

    companion object {
        val shared = ThreadLocal<String>()
    }

    fun store() {
        shared.set(readLine() ?: "echo")
    }

    fun use(): String = run(shared.get() ?: "echo")

    // A member ThreadLocal read twice in one function is one object.
    fun sameFunction(): String {
        current.set(readLine() ?: "echo")
        return run(current.get() ?: "echo")
    }
}

@RestController
class Handlers {
    private var last: String = ""
    private var clean: String = "echo ok"

    @GetMapping("/store")
    fun store(@RequestParam value: String): String {
        last = value
        return "stored"
    }

    @GetMapping("/use")
    fun use(): String = run(last)

    @GetMapping("/clean")
    fun useClean(): String = run(clean)
}

@RestController
@Scope("prototype")
class PrototypeHandlers {
    private var last: String = ""

    @GetMapping("/p/store")
    fun store(@RequestParam value: String): String {
        last = value
        return "stored"
    }

    @GetMapping("/p/use")
    fun use(): String = run(last)
}

class Plain {
    var last: String = ""

    fun store() {
        last = readLine() ?: ""
    }

    fun use(): String = run(last)

    // One instance, both calls: the summaries carry `last` from `store` to
    // `use`, so the slice starts at `store`'s read.
    fun caller(): String {
        val other = Plain()
        other.store()
        return other.use()
    }
}

private fun run(command: String): String =
    BufferedReader(InputStreamReader(Runtime.getRuntime().exec(command).inputStream)).readText()
