package interfacedispatch

import (
	"net/http"
	"os/exec"
)

// Interface dispatch: taint flows through an interface method call.
// golem:want flow source=http-input sink=command-execution known-fail=legacy:3
type Runner interface {
	Run(string)
}

type ShellRunner struct{}

func (ShellRunner) Run(v string) {
	_ = exec.Command("sh", "-c", v)
}

func Handler(r *http.Request) {
	var runner Runner = ShellRunner{}
	runner.Run(r.FormValue("cmd"))
}
