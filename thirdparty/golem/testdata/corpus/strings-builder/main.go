package stringsbuilder

import (
	"net/http"
	"os/exec"
	"strings"
)

// Strings builder: taint flows through strings.Builder, which is a very common pattern
// in Go code, carried by the writes-to-argument models on its methods.
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	var b strings.Builder
	b.WriteString("prefix:")
	b.WriteString(r.FormValue("cmd"))
	_ = exec.Command("sh", "-c", b.String())
}
