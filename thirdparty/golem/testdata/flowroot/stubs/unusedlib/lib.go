// Package unusedlib is the NEVER-CALLED half of the flowroot fixture: the app
// blank-imports it (its init runs) but no root reaches Run, so slices inside
// this package must be reported as not rooted while still being kept by
// --include-all-flows.
package unusedlib

import (
	"fmt"
	"os/exec"
)

// Run has the same parameter-to-sink shape as usedlib.Run.
func Run(cmd string) {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Println(string(out))
}
