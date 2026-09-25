package main

import (
	"net/http"

	"dotlessdep/scrub"
)

// The sink lives in a sub-package of a dot-less module. Classified by path
// shape, dotlessdep/scrub was the standard library too, so its callees were
// never expanded and scrub.Run was never a place a flow could materialise.
// golem:want flow source=http-input sink=command-execution
// golem:want flow source=parameter sink=command-execution sinkFn=dotlessdep/scrub.Run
// golem:want-not flow sink=filesystem
func Handler(r *http.Request) {
	scrub.Run(r.FormValue("cmd"))
}

func main() {}
