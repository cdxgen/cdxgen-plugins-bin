package globalvarcarrier

import (
	"net/http"
	"os/exec"
)

// Global variable carrier: taint stored in a package-level variable and read elsewhere.
// golem:want flow source=http-input sink=command-execution known-fail=legacy:19
var globalCmd string

func SaveToGlobal(r *http.Request) {
	globalCmd = r.FormValue("cmd")
}

func ExecuteGlobal() {
	if globalCmd != "" {
		_ = exec.Command("sh", "-c", globalCmd)
	}
}

func Handler(r *http.Request) {
	SaveToGlobal(r)
	ExecuteGlobal()
}
