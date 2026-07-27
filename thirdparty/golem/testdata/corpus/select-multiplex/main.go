package selectmultiplex

import (
	"net/http"
	"os/exec"
)

// Select multiplex: taint flows through a select statement.
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	ch := make(chan string, 1)
	ch <- r.FormValue("cmd")
	select {
	case v := <-ch:
		_ = exec.Command("sh", "-c", v)
	default:
	}
}
