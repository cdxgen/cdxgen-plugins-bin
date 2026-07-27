package genericconstraintmethod

import (
	"net/http"
	"os/exec"
)

// Generic constraint method: taint flows through a method called on a value
// whose type is a type parameter constrained by an interface.
//
// Inside the generic Execute the call c.Run(v) is an invoke against the
// constraint and cannot be resolved; in the instantiation
// Execute[string, ShellCmd] it is a static call to ShellCmd.Run. SEAM finds it
// by preferring an instantiation's own summary over its origin's. Legacy keys
// summaries per instantiation and never finds one at all.
//
// golem:want flow source=http-input sink=command-execution known-fail=legacy:22

type Commander[T any] interface {
	Run(T)
}

type ShellCmd struct{}

func (ShellCmd) Run(v string) {
	_ = exec.Command("sh", "-c", v)
}

func Execute[T any, C Commander[T]](c C, v T) {
	c.Run(v)
}

func Handler(r *http.Request) {
	Execute(ShellCmd{}, r.FormValue("cmd"))
}
