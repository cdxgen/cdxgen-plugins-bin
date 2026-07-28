package depdropstaint

import (
	"net/http"
	"os/exec"

	"example.com/golem/corpusdep/lib"
)

// A dependency function that discards its argument and returns a constant must
// not carry taint to the caller's sink. This is the negative half of
// dep-transitive-2-hops: that case only proves a flow is reported, not that the
// dependency was understood, and a blanket "assume every call returns its
// arguments" rule satisfies it for the wrong reason.
// In security mode the dependency is excluded from analysis altogether, so no
// flow is reported and the expectation holds for the wrong reason (defect 8).
// Under --dataflow all the blanket propagation rule invents the flow.
// golem:want-not flow source=http-input sink=command-execution mode=security
//
// Under --dataflow all the expectation has to name the function it is about.
// The shared dependency module also contains lib.HelperFromRequest, which
// really does reach exec.Command, and materialising the dependency reports it
// even though nothing here calls it. Both flows are http-input ->
// command-execution, so an unscoped annotation cannot tell the real one from
// the invented one, and an unscoped `want` is satisfied by either — which is
// how this case briefly came to assert the very bug it exists to forbid.
// golem:want-not flow source=http-input sink=command-execution sourcefn=~depdropstaint.Handler mode=all
// golem:want flow source=http-input sink=command-execution sourcefn=~lib.HelperFromRequest mode=all
func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	safe := lib.Drop(v)
	_ = exec.Command("sh", "-c", safe)
}
