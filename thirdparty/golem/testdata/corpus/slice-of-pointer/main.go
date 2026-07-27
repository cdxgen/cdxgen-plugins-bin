package sliceofpointer

import (
	"net/http"
	"os/exec"
)

// Slice of pointer: taint flows through a slice of pointers.
// golem:want flow source=http-input sink=command-execution known-fail=legacy:21
type CmdRec struct {
	Cmd string
}

func Handler(r *http.Request) {
	recs := []*CmdRec{{Cmd: r.FormValue("cmd")}}
	_ = exec.Command("sh", "-c", recs[0].Cmd)
}
