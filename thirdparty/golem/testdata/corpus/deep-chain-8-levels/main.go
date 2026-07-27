package deepchain

import (
	"net/http"
	"os/exec"
)

// Deep chain: 8 levels of helper functions passing taint through.
// golem:want flow source=http-input sink=command-execution known-fail=legacy:11
func Handler(r *http.Request) {
	v := r.FormValue("cmd")
	h1(v)
}

func h1(s string) { h2(s) }
func h2(s string) { h3(s) }
func h3(s string) { h4(s) }
func h4(s string) { h5(s) }
func h5(s string) { h6(s) }
func h6(s string) { h7(s) }
func h7(s string) { h8(s) }
func h8(s string) {
	_ = exec.Command("sh", "-c", s)
}
