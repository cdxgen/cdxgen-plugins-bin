package main

import (
	"net/http"
	"os/exec"

	"simd/local/scrub"
)

// A module may legally be named simd/…, the shape of Go's simd experiment
// packages. It is user code: its bodies are walked like any other, so the sink
// inside scrub.Run is found and scrub.Clean, which discards its input, is not
// approximated as a value-propagating simd intrinsic.

// golem:want flow source=http-input sink=command-execution sinkFn=~scrub.Run known-fail=legacy:42
func Sink(r *http.Request) { scrub.Run(r.FormValue("cmd")) }

// golem:want-not flow source=http-input sink=command-execution sinkFn=~Cleaned known-fail=legacy:42
func Cleaned(r *http.Request) { _ = exec.Command("sh", "-c", scrub.Clean(r.FormValue("cmd"))) }

func main() {}
