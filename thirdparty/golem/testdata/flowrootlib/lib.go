// Package flowrootlib is a library with no main: its only roots are package
// initializers, so golem must withhold the per-slice reachability verdict
// rather than report its exported API as unreachable.
package flowrootlib

import (
	"fmt"
	"os/exec"
)

// Exec is the library's public API.
func Exec(cmd string) {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Println(string(out))
}
