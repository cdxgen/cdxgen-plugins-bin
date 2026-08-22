package genericcontainer

import (
	"net/http"
	"os/exec"
)

// Generic container: taint flows through a generic type.
// golem:want flow source=http-input sink=command-execution
type Container[T any] struct {
	Value T
}

func (c *Container[T]) Set(v T) {
	c.Value = v
}

func (c *Container[T]) Get() T {
	return c.Value
}

func Handler(r *http.Request) {
	c := &Container[string]{}
	c.Set(r.FormValue("cmd"))
	_ = exec.Command("sh", "-c", c.Get())
}
