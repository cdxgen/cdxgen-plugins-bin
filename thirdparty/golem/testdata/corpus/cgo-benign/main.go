package cgabenign

/*
#cgo CFLAGS: -DPROBE_MARKER=1
#include <stdlib.h>
*/
import "C"
import (
	"net/http"
	"unsafe"
)

// A cgo package with an ordinary flag: -DPROBE_MARKER names a macro and
// carries no path and no value that must stay out of a report. The flow below
// crosses into C through C.CString, which is the boundary the analysis must
// report whether or not the load compiled the cgo preamble.
//
// golem:want flow source=http-input sink=native-interop
func Handler(r *http.Request) {
	cs := C.CString(r.FormValue("cmd"))
	defer C.free(unsafe.Pointer(cs))
	_ = C.GoString(cs)
}
