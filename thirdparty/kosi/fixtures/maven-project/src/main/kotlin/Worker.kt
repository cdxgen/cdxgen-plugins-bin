// Negative half first.
// kosi:want-not diagnostic code=parse-error
// kosi:want-not module name=phantom-module
//
// Positive half.
// kosi:want module name=maven-fixture platform=jvm
// kosi:want declaration name=Worker kind=class
// kosi:want declaration name=work kind=method
// kosi:want usage name=~.uppercase
package fixtures.maven

class Worker {
    fun work(input: String): String = input.uppercase()
}
