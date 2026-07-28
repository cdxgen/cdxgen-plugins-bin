package cgoroundtrip

/*
#include <stdlib.h>
*/
import "C"
import (
	"net/http"
	"os/exec"
	"unsafe"
)

// Cgo string roundtrip: taint flows through C.CString → C.GoString.
// golem:want flow source=http-input sink=native-interop
// golem:want flow source=http-input sink=command-execution
func Handler(r *http.Request) {
	// CGo roundtrip: Go string → C string → Go string
	v := r.FormValue("cmd")
	cs := C.CString(v)
	copy := C.GoString(cs)
	C.free(unsafe.Pointer(cs))
	_ = exec.Command("sh", "-c", copy)
}
