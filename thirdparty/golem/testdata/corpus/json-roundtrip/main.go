package jsonroundtrip

import (
	"encoding/json"
	"net/http"
	"os/exec"
)

// JSON roundtrip: taint flows through json.Unmarshal into a struct field.
// encoding/json is not in the shouldPropagate allowlist.
// golem:want flow source=http-input sink=data
// golem:want flow source=http-input sink=command-execution
type Payload struct {
	Cmd string
}

func Handler(r *http.Request) {
	var p Payload
	body := r.FormValue("body")
	_ = json.Unmarshal([]byte(body), &p)
	_ = exec.Command("sh", "-c", p.Cmd)
}
