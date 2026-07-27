package funcfielddispatch

import (
	"net/http"
	"os/exec"
)

// Dispatch through a function value held in a struct field. This is how a
// great deal of real Go routes work — a handler per route, a next link per
// middleware, a callback per registered plugin — and in SSA it is neither a
// static call nor an interface invoke:
//
//	t1 = &h.run    // FieldAddr
//	t2 = *t1       // UnOp MUL
//	t3 = t2(input) // Call with no StaticCallee
//
// SEAM builds its call graph in "static" mode, which resolves no dynamic call
// at all, so before funcfield.go nothing past such a call was reachable and
// taint stopped at the field read. Contrast Security's go-test-bench reaches
// all nine of its declared vulnerabilities exactly this way.
//
// golem:want flow source=http-input sink=command-execution known-fail=legacy:32
type handler struct {
	run func(string)
}

func runCommand(payload string) {
	_ = exec.Command("sh", "-c", payload)
}

func Handle(r *http.Request) {
	h := &handler{run: runCommand}
	h.run(r.FormValue("cmd"))
}
