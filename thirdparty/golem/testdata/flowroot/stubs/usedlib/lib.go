// Package usedlib is the CALLED half of the flowroot fixture: main reaches
// Run, so any slice inside this package must be reported as rooted.
package usedlib

import (
	"fmt"
	"os/exec"
)

// Run turns a caller-controlled command into an execution sink. The parameter
// name matches the engine's parameter-source rules.
func Run(cmd string) {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Println(string(out))
}
