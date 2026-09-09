// Negative half first.
// kosi:want-not diagnostic code=parse-error
// kosi:want-not usage name=java.util.Scanner
//
// Positive half: the Java file is discovery evidence (files[], language=java),
// and the Kotlin side shows the call into it. The resolved tier parses Java
// PSI through the same symbols (P1), so Greeter and greet exist as
// declarations there; the syntax tier does not parse Java, which is
// docs/KOSI.md defect 2, scoped to that backend.
// kosi:want declaration name=main kind=function
// kosi:want usage name=Greeter
// kosi:want usage name=~.greet
// kosi:want declaration name=Greeter kind=class known-fail=syntax:2
// kosi:want declaration name=greet kind=method known-fail=syntax:2
package fixtures.interop

fun main(): String {
    val greeter = Greeter()
    return greeter.greet("kosi")
}
