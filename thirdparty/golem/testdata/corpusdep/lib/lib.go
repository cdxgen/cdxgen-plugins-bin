package lib

import (
	"net/http"
	"os/exec"
)

// HelperFromRequest extracts and runs a command from the request.
// This simulates a vulnerable function inside a dependency.
func HelperFromRequest(r *http.Request) {
	v := r.FormValue("cmd")
	RunCommand(v)
}

// RunCommand is a sink wrapper inside the dependency.
func RunCommand(s string) {
	_ = exec.Command("sh", "-c", s)
}

// Passthrough passes a value through without modification.
// It should propagate taint when called from local code.
func Passthrough(s string) string {
	return s
}

// Drop takes a value and returns a constant, so nothing it is given can reach a
// caller's sink. A propagation rule that assumes every unresolved call returns
// its arguments reports a flow through this function that cannot exist.
func Drop(s string) string {
	_ = len(s)
	return "safe-constant"
}
