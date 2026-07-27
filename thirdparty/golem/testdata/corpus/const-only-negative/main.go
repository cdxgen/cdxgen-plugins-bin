package constonlynegative

import (
	"os/exec"
)

// Constant-only negative: hardcoded string constants should not produce a flow.
// golem:want-not flow sink=command-execution
func Handler() {
	const cmd = "ls"
	_ = exec.Command("sh", "-c", cmd)
}
