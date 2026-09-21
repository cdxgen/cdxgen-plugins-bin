// the BARE-NAME read of an accessor-backed property — 's
// sibling. fixed `a.b` where `b` is an accessor property; the same
// property read by BARE NAME (an implicit-receiver member, which is what
// `parameters` is inside an extension on ApplicationCall) still lowered
// as `fieldget vthis vthis.parameters`, hiding the callee from every
// pack. Nothing modelled such a property as a source yet, so this was
// latent — the fix is correctness, not a findings change.
//
// The fix follows the rule exactly: resolve the reference, and lower as
// a call ONLY when the property demonstrably has NO backing field. A
// property WITH a backing field keeps its access path, so field
// sensitivity is untouched — the backing-field half below pins that.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// The accessor read, by bare name, through the implicit extension
// receiver: the callee is the pack's own Ktor source pattern, at its real
// FQN.
// kosi:want flow source=untrusted-input sink=ssrf fn=~queryEcho mode=resolved
//
// The backing-field half: a bare read of a stored member (through an
// inlined `with` receiver) still flows through its ACCESS PATH, and the
// clean sibling stays clean — an implementation that collapsed backing
// fields into calls would lose the first, and one that tainted the whole
// receiver would fail the second.
// kosi:want flow source=untrusted-input sink=ssrf fn=~bareStored mode=resolved
// kosi:want-not flow source=~ sink=ssrf fn=~bareCleanSibling
package fixtures.bareaccess

import io.ktor.server.application.ApplicationCall
import java.net.URI

/**
 * `parameters` here is read by BARE NAME: the implicit receiver of the
 * extension function, an accessor property with no backing field. Before
 * this lowered as a field read whose path was the RECEIVER's own
 * register, and no pack could see the source at all.
 */
fun ApplicationCall.queryEcho(): URI = URI.create(parameters["target"].orEmpty())

/** Stored members: a backing field each, one tainted, one clean. */
class Panel {
    var query: String = ""
    var label: String = "name"
}

fun bareStored(panel: Panel): URI {
    panel.query = readLine() ?: ""
    return with(panel) {
        // `query` is a BARE-NAME read of a backing-field member through the
        // inlined receiver: it must stay a FIELD read, or the write above
        // never meets it.
        URI.create(query)
    }
}

fun bareCleanSibling(panel: Panel): URI {
    panel.query = readLine() ?: ""
    return with(panel) {
        URI.create(label)
    }
}
