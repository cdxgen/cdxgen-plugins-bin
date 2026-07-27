package errorwrapping

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
)

// Error wrapping: taint flows through fmt.Errorf with %w.
// errors/fmt.Errorf are not in the shouldPropagate allowlist.
// golem:want flow source=http-input sink=command-execution
func buildErr(input string) error {
	return fmt.Errorf("input was: %w", errors.New(input))
}

func Handler(r *http.Request) {
	err := buildErr(r.FormValue("cmd"))
	// Extract and use the tainted value
	_ = exec.Command("sh", "-c", err.Error())
}
