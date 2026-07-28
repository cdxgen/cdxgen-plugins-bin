package directflow

import (
	"net/http"
	"os/exec"
)

// Simple direct flow: HTTP input → command execution.
// golem:want flow source=http-input sink=command-execution
// golem:want-not flow sink=filesystem
func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	_ = exec.Command("sh", "-c", v)
}
