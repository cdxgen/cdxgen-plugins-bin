// Negative half first.
// kosi:want-not diagnostic code=parse-error
// kosi:want-not usage name=java.util.Scanner
//
// Positive half: the Java file is discovery evidence (files[], language=java
// at the syntax tier; Java PSI parsing lands with the resolved tier), and the
// Kotlin side shows the call into it.
// kosi:want declaration name=main kind=function
// kosi:want usage name=Greeter
// kosi:want usage name=~.greet
package fixtures.interop

fun main(): String {
    val greeter = Greeter()
    return greeter.greet("kosi")
}
