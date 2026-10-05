// Package fnvallib is reached only through a function value looked up in a
// map, which a static call graph cannot follow.
package fnvallib

import (
	"fmt"
	"os/exec"
)

func run(cmd string) {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Println(string(out))
}

// Handlers maps a verb to its implementation.
var Handlers = map[string]func(cmd string){"run": run}
