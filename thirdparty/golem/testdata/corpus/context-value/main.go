package contextvalue

import (
	"context"
	"net/http"
	"os/exec"
)

// Context value: taint flows through context.WithValue/Value.
// context is not in the shouldPropagate allowlist.
// golem:want flow source=http-input sink=command-execution
type ctxKey string

func Handler(r *http.Request) {
	ctx := context.WithValue(r.Context(), ctxKey("cmd"), r.FormValue("cmd"))
	v, _ := ctx.Value(ctxKey("cmd")).(string)
	_ = exec.Command("sh", "-c", v)
}
