package defertaint

import (
	"net/http"
	"os/exec"
)

// Defer taint: deferred function captures tainted value.
// golem:want flow source=http-input sink=command-execution known-fail=legacy:7
func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	defer func() {
		_ = exec.Command("echo", v)
	}()
}
