package recursion

import (
	"net/http"
	"os/exec"
)

// Recursion: taint flows through a recursive helper.
// golem:want flow source=http-input sink=command-execution
func recurse(s string, depth int) {
	if depth <= 0 {
		_ = exec.Command("sh", "-c", s)
		return
	}
	recurse(s, depth-1)
}

func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	recurse(v, 3)
}
