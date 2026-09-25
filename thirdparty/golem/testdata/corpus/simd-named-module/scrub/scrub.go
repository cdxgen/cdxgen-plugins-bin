package scrub

import "os/exec"

// Clean discards its input.
func Clean(string) string { return "ls" }

// Run executes cmd through a shell.
func Run(cmd string) { _ = exec.Command("sh", "-c", cmd) }
