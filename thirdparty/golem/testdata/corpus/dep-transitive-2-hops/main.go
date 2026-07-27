package deptransitive

import (
	"net/http"
	"os/exec"

	"example.com/golem/corpusdep/lib"
)

// Dep-transitive-2-hops: source → local function → dependency passthrough → local sink.
// Taint should propagate through the dependency function.
// golem:want flow source=http-input sink=command-execution
// golem:want edge from=~dep-transitive-2-hops.Handler to=~corpusdep/lib.Passthrough
func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	// Pass through the dependency function
	intermediate := lib.Passthrough(v)
	_ = exec.Command("sh", "-c", intermediate)
}

func init() {
	// Ensure Handler is reachable for RTA tracing.
	var r *http.Request
	Handler(r)
}
