package iocopy

import (
	"io"
	"net/http"
	"os/exec"
	"strings"
)

// IO copy: taint flows through io.Copy's writes-to-argument model.
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	src := strings.NewReader(r.FormValue("cmd"))
	var dst strings.Builder
	_, _ = io.Copy(&dst, src)
	_ = exec.Command("sh", "-c", dst.String())
}
