package unrelatedvalue

import (
	"net/http"
	"os/exec"
)

// Two independent values: the tainted one is discarded and a constant reaches
// the sink. Reporting this would mean taint is attached to the function rather
// than to the value.
// golem:want-not flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	tainted := r.FormValue("cmd")
	_ = len(tainted)
	safe := "ls -la"
	_ = exec.Command("sh", "-c", safe)
}
