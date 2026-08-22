package valuereceiverfield

import (
	"net/http"
	"os"
	"os/exec"
)

// Value receiver carrying a tainted field. Every other struct fixture uses a
// pointer receiver, where the write and the read address the same allocation.
// A value receiver is copied twice — once by the composite literal, once by the
// call — and SSA spills the receiver into a local before reading the field, so
// the taint has to survive two by-value aggregate copies.
//
// golem:want flow source=http-input sink=command-execution
type Carrier struct {
	raw string
}

func (c Carrier) Raw() string { return c.raw }

func Handler(r *http.Request) {
	c := Carrier{raw: r.FormValue("cmd")}
	_ = exec.Command("sh", "-c", c.Raw())
}

// A clean field of the same struct must not pick up the tainted one's label,
// and the clean field has to reach an actual sink for the expectation to mean
// anything.
// golem:want-not flow source=http-input sink=filesystem
type pair struct {
	tainted string
	clean   string
}

func (p pair) Clean() string { return p.clean }

func Discriminates(r *http.Request) {
	p := pair{tainted: r.FormValue("path"), clean: "static"}
	_, _ = os.ReadFile(p.Clean())
}
