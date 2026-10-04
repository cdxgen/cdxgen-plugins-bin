// Package flowroot is the fixture for per-slice root reachability: main calls
// one local replacement library and blank-imports another, so both libraries
// carry an identical parameter-to-sink flow while only one of them is
// reachable from the resolved roots.
package main

import (
	"os"

	"example.com/usedlib"

	_ "example.com/unusedlib"
)

func main() {
	if len(os.Args) > 1 {
		usedlib.Run(os.Args[1])
	}
}
