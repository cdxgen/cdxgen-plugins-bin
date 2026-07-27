package closurecapture

import (
	"net/http"
	"os/exec"
)

// Closure capture: taint captured in a closure and executed later.
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	f := func() string { return v }
	_ = exec.Command("echo", f())
}
