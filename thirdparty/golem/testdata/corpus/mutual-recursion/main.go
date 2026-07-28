package mutualrecursion

import (
	"net/http"
	"os/exec"
)

// Mutual recursion: two functions call each other.
// golem:want flow source=http-input sink=command-execution
func isEven(s string, n int) string {
	if n <= 0 {
		return s
	}
	return isOdd(s, n-1)
}

func isOdd(s string, n int) string {
	if n <= 0 {
		_ = exec.Command("sh", "-c", s)
		return ""
	}
	return isEven(s, n-1)
}

func Handler(r *http.Request) {
	isEven(r.FormValue("cmd"), 4)
}
