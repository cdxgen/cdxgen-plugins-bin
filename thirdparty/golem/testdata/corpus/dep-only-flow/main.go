package deponlyflow

import (
	"net/http"

	"example.com/golem/corpusdep/lib"
)

// Dep-only-flow: source and sink are both inside the dependency.
// The local caller just calls a dependency function that internally does source→sink.
// In security mode neither engine reports this. Legacy computes no summary for
// any dependency function at all. SEAM does summarise it, and could report it,
// but a flow contained wholly inside a library with no local frame on its route
// is materialised only under --dataflow all: reporting every one of them costs
// about six times the wall clock and halves precision on this corpus.
// golem:want flow source=http-input sink=command-execution mode=all
// golem:want flow source=http-input sink=command-execution mode=security known-fail=legacy:8
func Handler(r *http.Request) {
	// This dependency function internally reads from the request and executes a command.
	lib.HelperFromRequest(r)
}
