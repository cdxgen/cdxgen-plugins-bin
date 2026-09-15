// The corpus had no fixture whose reachability travels an EDGE: every
// reached node in every other fixture is a root at distance 0, so the
// edge-connectivity gate confirmed 62 nodes without once following an
// edge. This fixture is the denominator that gate needs — one public
// entry point and a chain of non-public helpers only reachable through it.
//
// Negative half first: the orphan is non-public AND uncalled, so no root
// can reach it. If the walk ever claims it, reachability is inventing
// execution rather than following calls.
// kosi:want-not reachable symbol=~orphanHelper mode=exported
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the chain. `sanitize` and `format` are one hop from the
// root, `trimTail` is two — the only nodes in the corpus whose reachability
// is a fact about edges rather than about being declared public.
// kosi:want reachable symbol=~fixtures.depth.entryPoint mode=exported
// kosi:want reachable symbol=~fixtures.depth.sanitize mode=exported
// kosi:want reachable symbol=~fixtures.depth.format mode=exported
// kosi:want reachable symbol=~fixtures.depth.trimTail mode=exported
// kosi:want edge from=~entryPoint to=~sanitize mode=exported
// kosi:want edge from=~sanitize to=~trimTail mode=exported
package fixtures.depth

public fun entryPoint(raw: String): String = format(sanitize(raw))

internal fun sanitize(value: String): String = trimTail(value)

private fun trimTail(value: String): String = value.trimEnd()

private fun format(value: String): String = "[" + value + "]"

private fun orphanHelper(): Int = 42
