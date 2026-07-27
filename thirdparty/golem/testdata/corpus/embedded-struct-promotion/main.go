package embeddedstructpromotion

import (
	"net/http"
	"os/exec"
)

// Embedded struct promotion: taint flows through an embedded struct's field.
// golem:want flow source=http-input sink=command-execution
type Base struct {
	Cmd string
}

type Wrapper struct {
	Base
}

func Handler(r *http.Request) {
	w := &Wrapper{}
	w.Cmd = r.FormValue("cmd") // promoted field
	_ = exec.Command("sh", "-c", w.Cmd)
}
