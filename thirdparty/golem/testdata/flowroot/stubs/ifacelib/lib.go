// Package ifacelib is reached only through interface dispatch: main holds a
// Runner and never names the concrete type, so a static call graph has no edge
// into shell.Run while RTA does.
package ifacelib

import (
	"fmt"
	"os/exec"
)

// Runner is the interface main calls through.
type Runner interface{ Run(cmd string) }

type shell struct{}

func (shell) Run(cmd string) {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Println(string(out))
}

// New returns the concrete runner behind the interface.
func New() Runner { return shell{} }
