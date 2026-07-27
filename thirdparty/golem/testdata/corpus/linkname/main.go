package linkname

import (
	"net/http"
	"os/exec"

	_ "unsafe" // required for //go:linkname
)

// A pull //go:linkname: runCommand is declared without a body and is given the
// implementation of runCmd by the linker. Neither the type information nor SSA
// records that connection, so the call in Handler leads into an empty function
// unless the pragma itself is read.
//
// The alias edge is the capability under test. SEAM crosses it too: when a
// callee has no body it follows the directive to the implementing function,
// using the same mapping the call graph draws the edge from. Legacy has no
// equivalent and still stops at the empty declaration.
//
// golem:want edge from=~.runCommand to=~.runCmd calltype=linkname
// golem:want flow source=http-input sink=command-execution known-fail=legacy:25

//go:linkname runCommand example.com/golem/corpus/linkname.runCmd
func runCommand(s string)

func runCmd(s string) {
	_ = exec.Command("sh", "-c", s)
}

func Handler(r *http.Request) {
	runCommand(r.FormValue("cmd"))
}
