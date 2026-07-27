package reflectcall

import (
	"net/http"
	"os/exec"
	"reflect"
)

// Reflection call: taint flows through a reflect call.
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	rv := reflect.ValueOf(r.FormValue("cmd"))
	s, _ := rv.Interface().(string)
	_ = exec.Command("sh", "-c", s)
}
