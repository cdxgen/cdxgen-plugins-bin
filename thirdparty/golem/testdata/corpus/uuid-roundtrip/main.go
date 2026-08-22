package uuidroundtrip

import (
	"net/http"
	"os"
	"uuid"
)

// uuid joined the standard library in Go 1.27. Parse and the text forms are
// modelled as taint carriers — the same shape as the json round-trip models —
// so a request-supplied UUID survives being parsed and re-rendered on its way
// to a sink.
//
// golem:want flow source=http-input sink=filesystem
func Handler(r *http.Request) {
	id := r.FormValue("id")
	u, err := uuid.Parse(id)
	if err != nil {
		return
	}
	_, _ = os.ReadFile("/items/" + u.String())
}

// The generators are crypto/rand-backed (New is NewV4, NewV7 reads crypto/rand
// for its random bits), so they are deliberately not insecure-random sources:
// a fresh UUID at a sink must not be flagged as weak randomness.
//
// golem:want-not flow source=insecure-random sink=filesystem
func Fresh() {
	u := uuid.New()
	_, _ = os.ReadFile("/items/" + u.String())
}
