package pluginopen

import (
	"net/http"
	"os/exec"
	"plugin"
)

// Loading a plugin whose path came from a request is arbitrary code execution.
// Loading one from a constant path is not, and running a fixed command in the
// same function is not either — which is what makes the negative below worth
// asserting rather than vacuous.
//
// golem:want flow source=http-input sink=dynamic-loading count=1
// golem:want-not flow source=http-input sink=command-execution

func Handler(r *http.Request) {
	path := r.FormValue("pluginPath")
	_, _ = plugin.Open(path)

	_, _ = plugin.Open("/usr/lib/golem/builtin.so")
	_ = exec.Command("sh", "-c", "true")
}
