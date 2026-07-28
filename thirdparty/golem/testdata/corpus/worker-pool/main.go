package workerpool

import (
	"net/http"
	"os/exec"
)

// Worker pool: taint flows through a simple worker pool pattern with channels.
// golem:want flow source=http-input sink=command-execution known-fail=legacy:7
func Handler(w http.ResponseWriter, r *http.Request) {
	jobs := make(chan string, 1)
	results := make(chan string, 1)

	// Worker
	go func() {
		for cmd := range jobs {
			_ = exec.Command("sh", "-c", cmd)
			results <- "done"
		}
	}()

	jobs <- r.FormValue("cmd")
	<-results
}
