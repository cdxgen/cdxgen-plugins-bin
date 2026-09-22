// The same value reached through three names for one object: a second
// reference, an object stored in another object's field, and a data class
// copied with copy(). Every hop is at depth - the reaching functions are
// layers, not locals - and the clean SIBLING field of the same object must
// stay clean (the negative, now at depth).
//
// Negative half first: label is a sibling field of the SAME tainted object
// and must never reach the sink.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~sinkLabel
// kosi:want-not diagnostic code=parse-error
//
// Positive half.
// kosi:want flow source=untrusted-input sink=process-exec fn=~sinkThroughSecondReference frames=6
// kosi:want flow source=untrusted-input sink=process-exec fn=~sinkThroughContainerField frames=6
// kosi:want flow source=untrusted-input sink=process-exec fn=~sinkThroughCopy frames=5
package fixtures.deep.alias

data class Session(val token: String, val label: String = "ok")

class Box(var inner: Session? = null)

class SessionStore {
    fun load(raw: String): Session = Session(token = raw)
}

class Relay(private val store: SessionStore) {
    fun throughSecondReference(raw: String): Session {
        val first = store.load(raw)
        val second = first
        return second
    }

    fun throughContainerField(raw: String): Session {
        val box = Box()
        box.inner = store.load(raw)
        return box.inner!!
    }

    fun throughCopy(raw: String): Session {
        return store.load(raw).copy()
    }
}

fun sinkThroughSecondReference(relay: Relay) {
    val session = relay.throughSecondReference(readLine() ?: "")
    Runtime.getRuntime().exec(session.token)
}

fun sinkThroughContainerField(relay: Relay) {
    val session = relay.throughContainerField(readLine() ?: "")
    Runtime.getRuntime().exec(session.token)
}

fun sinkThroughCopy(relay: Relay) {
    val session = relay.throughCopy(readLine() ?: "")
    Runtime.getRuntime().exec(session.token)
}

fun sinkLabel(relay: Relay) {
    val session = relay.throughSecondReference(readLine() ?: "")
    Runtime.getRuntime().exec(session.label)
}
