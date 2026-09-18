// P23 §3: R63 applied to a VOCABULARY. The const folder records WHY a value
// defined by a call could not be folded — the producer bucket's arms — and
// P22 §3 published the breakdown. But the folder recorded twelve arms and
// the corpus drove five: seven were names in the code with no measurement
// behind them, which is the same "declared but never reached" state R63 is
// about, one level up from a capability.
//
// This fixture drives every workspace REFUSAL arm through
// `Analyzer.analyze`, so each is a corpus fact. Each call below is a URL
// argument, which is what makes the folder run at all — a refusal nobody
// asks for is not measured either.
//
// kosi:want-not diagnostic code=parse-error
//
// Every one of these sites must publish UNRESOLVED: the arms ARE the
// refusals, and a fold here would mean the folder guessed.
// kosi:want-not service protocol=https name=~arms.example.com mode=resolved
// kosi:want-not service protocol=https name=~first.example.com mode=resolved
// kosi:want-not service protocol=https name=~second.example.com mode=resolved
// kosi:want-not service protocol=https name=~override.example.com mode=resolved
package fixtures.arms

import java.net.URL
import java.util.Properties

/** virtual-open: an override can hide in a jar, so no candidate is exact. */
open class Gateway {
    open fun host(): String = "https://arms.example.com/open"
}

/** returns-disagree: two return sites, two constants, no single provenance. */
fun disagreeing(flag: Boolean): String {
    if (flag) return "https://first.example.com/a"
    return "https://second.example.com/b"
}

/** recursion: a cycle has no single provenance. */
fun recursive(depth: Int): String =
    if (depth <= 0) "https://arms.example.com/base" else recursive(depth - 1)

/** parameter-return: the value belongs to the CALLER, not this body. */
fun echo(host: String): String = host

/**
 * no-return-site: blocks, but no return instruction anywhere. A `throw` is
 * NOT this shape — the lowering gives it a return site whose value is the
 * exception, which the folder then refuses as return-unprovable. A body
 * that never terminates has no return site at all.
 */
@Suppress("ControlFlowWithEmptyBody")
fun spins(): String {
    while (true) {
    }
}

fun openHostUrl(g: Gateway): URL = URL(g.host())

fun disagreeingUrl(flag: Boolean): URL = URL(disagreeing(flag))

fun recursiveUrl(): URL = URL(recursive(3))

fun parameterUrl(caller: String): URL = URL(echo(caller))

fun spinningUrl(): URL = URL(spins())

/** config-unresolved: the config reader's KEY argument does not fold. */
fun dynamicConfigUrl(props: Properties, key: String): URL = URL(props.getProperty(key))
