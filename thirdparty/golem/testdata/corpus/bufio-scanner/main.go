package bufioscanner

import (
	"bufio"
	"net/http"
	"os/exec"
	"strings"
)

// Bufio scanner: taint flows through bufio.Scanner.
// bufio.NewScanner/Text are explicit passthrough models.
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	scanner := bufio.NewScanner(strings.NewReader(r.FormValue("data")))
	for scanner.Scan() {
		_ = exec.Command("echo", scanner.Text())
		break
	}
}
