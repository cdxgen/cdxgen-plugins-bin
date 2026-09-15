// Negative half first. Each negative names what a specific over-broad
// implementation would get wrong, per the P0 review standard:
// - a resolver that invents declarations for coordinates it could not find
//   would make the missing library's class look like a fact about the code;
// - an implementation that reports unresolved calls as parse errors would
//   drown the report in parse-error diagnostics;
// - an implementation that drops evidence it cannot resolve would hide the
//   GoneClient call from usages[] entirely (the plausible-looking small
//   graph this fixture exists to catch).
// kosi:want-not declaration name=GoneClient kind=class
// kosi:want-not diagnostic code=parse-error
//
// Positive half. classpath-partial carries known-fail=syntax:2 because the
// syntax backend does not resolve at all (docs/KOSI.md defect 2); the
// resolved backend must name the missing coordinate and still report the
// local code and the unresolvable call.
// kosi:want diagnostic code=classpath-partial known-fail=syntax:2
// kosi:want usage name=GoneClient.connect
// kosi:want usage name=~lineSeparator
// kosi:want declaration name=localHelper kind=method
// kosi:want declaration name=Report kind=class
package fixtures.emptycp

import com.example.unresolvable.gone.GoneClient

class Report {
    fun render(): String {
        val client = GoneClient.connect("localhost")
        return localHelper(client.summary()) + System.lineSeparator()
    }

    fun localHelper(value: String): String = "report: $value"
}
