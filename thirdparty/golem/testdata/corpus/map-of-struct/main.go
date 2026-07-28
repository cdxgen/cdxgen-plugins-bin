package mapofstruct

import (
	"net/http"
	"os/exec"
)

// Map of struct: taint flows through a map whose values are struct pointers.
// golem:want flow source=http-input sink=command-execution
type CmdEntry struct {
	Cmd string
}

func Handler(r *http.Request) {
	m := map[string]*CmdEntry{"k": {}}
	m["k"].Cmd = r.FormValue("cmd")
	_ = exec.Command("sh", "-c", m["k"].Cmd)
}
