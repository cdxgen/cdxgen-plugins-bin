// P26 §0 — the source that comes back inside an object.
//
// R161's shape: the source is born INSIDE a factory callee and stored into
// the constructed object's FIELD. P24's primary-constructor synthesis writes
// source facts into constructed objects' fields — which is where they belong
// — but the summary's return channel probed only the bare return key, so the
// summary said "returns nothing tainted", every caller went clean, and 22
// http4k findings disappeared between the P23 and P24 builds with no gate
// watching. The channel is `sourceReturnFields` (category -> access path),
// the RETURN mirror of P24's own paramToReturnFields.
//
// Positive half: the field read in the caller must reach the sink.
// kosi:want flow source=untrusted-input sink=sql-query fn=~consume known-fail=syntax:1
//
// Negative halves: a CONSTANT factory's object carries nothing, and the clean
// sibling field must stay clean (the channel is field-sensitive, not a
// blanket re-introduction of the pre-P24 propagation).
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~consumeLabel
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~consumeClean
// kosi:want-not diagnostic code=parse-error
package fixtures.flow

class Wrapped(val inner: String, val label: String = "fixed")

// The source (readLine) is born in THIS body; the fact lands at the
// constructed object's .inner field, and crosses the boundary through the
// sourceReturnFields channel.
fun make(): Wrapped = Wrapped(readLine() ?: "")

fun consume() {
    // Both consumer spellings must fire: the direct read of the call result,
    // and the store-mediated one through a local (the commoner code shape —
    // the alias class carries the field fact across the copy).
    val direct = make().inner
    val w = make()
    val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:factory")
    conn.createStatement().executeQuery("SELECT * FROM t WHERE x = '" + w.inner + direct + "'")
}

// The clean sibling: the same object, the same read shape, the clean field.
// A channel that taints the whole object would report this too.
fun consumeLabel() {
    val w = make()
    val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:factory")
    conn.createStatement().executeQuery("SELECT * FROM t WHERE l = '" + w.label + "'")
}

// A constant factory carries no source at all.
fun makeClean(): Wrapped = Wrapped("constant")

fun consumeClean() {
    val w = makeClean()
    val conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:factory")
    conn.createStatement().executeQuery("SELECT * FROM t WHERE x = '" + w.inner + "'")
}
