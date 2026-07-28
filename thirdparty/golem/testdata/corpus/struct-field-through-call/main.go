package structfieldthroughcall

import (
	"net/http"
	"os"
)

// Struct field through call: taint stored in struct field, then read back and used as sink.
// golem:want flow source=http-input sink=filesystem
type carrier struct {
	value string
}

func (c *carrier) Set(v string) {
	c.value = v
}

func (c *carrier) Value() string {
	return c.value
}

func Handler(r *http.Request) {
	c := &carrier{}
	c.Set(r.PostFormValue("name"))
	_ = os.WriteFile(c.Value(), []byte("x"), 0o600)
}
