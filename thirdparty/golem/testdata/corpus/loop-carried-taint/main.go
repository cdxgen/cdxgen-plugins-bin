package looptaint

import (
	"net/http"
	"os/exec"
)

// Slice iteration taint works: each element of the slice is tracked individually.
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	commands := []string{r.FormValue("a"), r.FormValue("b")}
	for _, cmd := range commands {
		if cmd != "" {
			_ = exec.Command("sh", "-c", cmd)
		}
	}
}
