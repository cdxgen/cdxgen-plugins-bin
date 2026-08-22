// Provenance of this directory.
//
// rta.go and element.go are copies of golang.org/x/tools at the version
// named by upstreamVersion below — go/callgraph/rta/rta.go and
// internal/typesinternal/element.go — carrying their original BSD
// licence, reproduced here in LICENSE. They are not golem code; treat
// them as upstream and keep the delta at what vendor_test.go allows.
//
// Why the copy exists: rta.Analyze put a nil *ssa.Function on its
// worklist — and visitFunc then dereferenced f.Blocks — whenever a
// runtime type's method set contained a Go 1.27 generic method (a
// method declaring its own type parameters), because
// ssa.Program.MethodValue returns nil for methods it cannot lower to
// SSA. static and rta's fingerprint gained guards against generic
// methods in CL 788520 (golang/go#77549) and vta already nil-checked;
// the two rta call sites fixed here were missed (golang/go#80973).
//
// The delta from upstream is insert-only, and vendor_test.go keeps it
// that way: two early returns marked "#80973" — in addReachable, which
// drops the nil wherever it is produced, and in addInvokeEdge, where a
// nil callee would also reach callgraph.CreateNode and leave a node
// with no function — plus comments, the package clause, and the
// ForEachElement copy that importing an x/tools-internal package would
// otherwise require. No upstream line is altered or removed.
//
// To retire it: when an x/tools release carries the fix, delete this
// directory and restore the golang.org/x/tools/go/callgraph/rta import
// in internal/analyzer/callgraph.go. vendor_test.go fails as soon as
// that release is the one in go.mod, so the copy cannot outlive its
// reason silently.

package rta

// upstreamVersion is the x/tools release rta.go and element.go were
// copied from. vendor_test.go requires it to match go.mod: bumping
// x/tools without re-vendoring would leave golem running an older RTA
// than the rest of x/tools it is compiled against.
const upstreamVersion = "v0.49.0"
