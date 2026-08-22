package genericmethod

import (
	"net/http"
	"os"
	"os/exec"
)

// Generic methods (Go 1.27): a method declares its own type parameters, so the
// method's type parameter list is disjoint from the receiver's. Taint has to
// cross the method boundary, the SSA instantiation, and the call through the
// method's function-valued parameter.
// golem:want flow source=http-input sink=command-execution
type Box[T any] struct {
	Value T
}

// Map is a generic method: U belongs to the method, T to the receiver.
func (b Box[T]) Map[U any](f func(T) U) Box[U] {
	return Box[U]{Value: f(b.Value)}
}

// Carrier is a non-generic type with a generic method, the shape that was
// impossible before Go 1.27.
type Carrier struct {
	raw string
}

func (c Carrier) Unwrap[T any](f func(string) T) T {
	return f(c.raw)
}

func Handler(r *http.Request) {
	b := Box[string]{Value: r.FormValue("cmd")}
	out := b.Map(func(s string) string { return s })
	_ = exec.Command("sh", "-c", out.Value)
}

// A distinct sink category so this expectation cannot be satisfied by the slice
// Handler produces.
// golem:want flow source=http-input sink=filesystem
func CarrierHandler(r *http.Request) {
	c := Carrier{raw: r.FormValue("path")}
	path := c.Unwrap(func(s string) string { return s })
	_, _ = os.ReadFile(path)
}
