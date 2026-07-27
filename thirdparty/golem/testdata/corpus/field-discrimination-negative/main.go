package fielddiscrimination

import (
	"net/http"
	"os/exec"
)

// One struct, two fields: the tainted value is stored in Cmd and the sink reads
// Safe. Distinguishing them needs field-sensitive access paths; collapsing a
// struct to a single taint bit would report a flow that does not exist. The
// one-level field sensitivity golem has today is enough for this shape, so this
// case locks that behaviour in against the access-path rewrite.
// golem:want-not flow source=http-input sink=command-execution
type Config struct {
	Cmd  string
	Safe string
}

func Handler(r *http.Request) {
	cfg := &Config{Safe: "ls"}
	cfg.Cmd = r.FormValue("cmd")
	_ = exec.Command("sh", "-c", cfg.Safe)
}
