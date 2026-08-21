package genericmethod

import (
	"net/http"
	"os/exec"
)

// Generic methods (Go 1.27): a method declares its own type parameters, so the
// method's type parameter list is disjoint from the receiver's. Taint must
// still cross the method boundary and the SSA instantiation of the method.
// golem:want flow source=http-input sink=command-execution known-fail=33
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

// golem:want flow source=http-input sink=command-execution known-fail=33
func CarrierHandler(r *http.Request) {
	c := Carrier{raw: r.FormValue("cmd")}
	cmd := c.Unwrap(func(s string) string { return s })
	_ = exec.Command("sh", "-c", cmd)
}
