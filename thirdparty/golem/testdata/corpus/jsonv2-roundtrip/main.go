package jsonv2roundtrip

import (
	json "encoding/json/v2"
	"net/http"
	"os/exec"
)

// encoding/json/v2 is the default JSON implementation from Go 1.27 on, so an
// unmodelled Unmarshal there loses every flow that json-roundtrip catches.
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

// golem:want flow source=http-input sink=data
func ReaderHandler(r *http.Request) {
	var p Payload
	_ = json.UnmarshalRead(r.Body, &p)
	_ = exec.Command("sh", "-c", p.Cmd)
}
