package main

import (
	"net/http"
	"os/exec"
)

// A module path with no dot in its first element (`go mod init myapp`) has the
// shape of a standard library path. Classifying the standard library by that
// shape made SEAM treat this whole module as the standard library: nothing in
// it materialised under the default local scope, and the flow below was
// reported by the legacy engine only.
// golem:want flow source=http-input sink=command-execution sinkFn=dotlessapp.Handler
// golem:want-not flow sink=filesystem
func Handler(r *http.Request) {
	_ = exec.Command("sh", "-c", r.FormValue("cmd"))
}

func main() {}
