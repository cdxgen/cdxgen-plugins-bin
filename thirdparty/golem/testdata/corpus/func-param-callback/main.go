package funcparamcallback

import (
	"net/http"
	"os"
	"os/exec"
)

// A call through a function-valued parameter. The target is supplied by the
// caller, so no static resolution names it; the result must still carry the
// taint of what was passed in, or every callback-shaped API drops taint. This
// is the pre-generics form of the shape generic-method exercises.
//
// golem:want flow source=http-input sink=command-execution known-fail=legacy:33
type Carrier struct {
	raw string
}

func (c Carrier) Unwrap(f func(string) string) string { return f(c.raw) }

func Handler(r *http.Request) {
	c := Carrier{raw: r.FormValue("cmd")}
	_ = exec.Command("sh", "-c", c.Unwrap(func(s string) string { return s }))
}

// Same shape through a generic top-level function, legal since Go 1.18. A
// distinct sink category so this expectation cannot be satisfied by Handler's
// slice.
// golem:want flow source=http-input sink=filesystem known-fail=legacy:33
func Unwrap[T any](c Carrier, f func(string) T) T { return f(c.raw) }

func GenericHandler(r *http.Request) {
	c := Carrier{raw: r.FormValue("path")}
	_, _ = os.ReadFile(Unwrap(c, func(s string) string { return s }))
}
