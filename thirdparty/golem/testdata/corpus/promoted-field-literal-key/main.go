package promotedfieldliteralkey

import (
	"crypto/tls"
	"net/http"
	"os/exec"
)

// Promoted field keys in struct literals (Go 1.27): a key may be any valid
// field selector for the struct type, so a composite literal can initialise a
// field reached through embedding, two levels down here.
//
// A value-typed literal compiles to a store into a scratch allocation, a load
// of the whole struct, and a store of that value into the variable, so the
// field-qualified taint has to survive a by-value aggregate copy. See
// value-receiver-field for the same requirement without any 1.27 syntax.
// golem:want flow source=http-input sink=command-execution
type Base struct {
	Cmd string
}

type Mid struct {
	Base
	Arg string
}

type Wrapper struct {
	Mid
	Shell string
}

func Handler(r *http.Request) {
	// Cmd is promoted through Mid -> Base, two levels of embedding.
	w := Wrapper{Cmd: r.FormValue("cmd"), Shell: "sh"}
	_ = exec.Command(w.Shell, "-c", w.Cmd)
}

// The tls-insecure signal is recognised from an ast.KeyValueExpr key, so a
// promoted key is the form that evades an unqualified key-name match.
type baseConfig struct {
	tls.Config
}

func InsecureClient() *http.Client {
	cfg := &baseConfig{InsecureSkipVerify: true}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &cfg.Config}}
}
