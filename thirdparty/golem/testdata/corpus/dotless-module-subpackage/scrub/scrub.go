package scrub

import "os/exec"

// Run executes cmd through a shell.
func Run(cmd string) {
	_ = exec.Command("sh", "-c", cmd)
}
