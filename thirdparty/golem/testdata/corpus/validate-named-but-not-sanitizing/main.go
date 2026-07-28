package validatenotinsanitize

import (
	"net/http"
	"os/exec"
)

// validate-named-but-not-sanitizing: a function named "validateAndBuildQuery" should NOT
// be treated as a sanitizer just because its name contains "validate".
// golem:want flow source=http-input sink=command-execution
func validateAndBuildQuery(input string) string {
	return input // no actual sanitization
}

func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	q := validateAndBuildQuery(v)
	_ = exec.Command("sh", "-c", q)
}
