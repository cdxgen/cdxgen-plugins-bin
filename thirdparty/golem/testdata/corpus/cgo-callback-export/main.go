package callbackexport

/*
#include <stdlib.h>
*/
import "C"
import (
	"os/exec"
	"unsafe"
)

// A Go function called from C, and a Go function that calls into C. Both
// directions of the boundary appear in one package; internal/native asserts
// that both are recognised.
//
// A buffer handed to us by the C side is untrusted: nothing in Go checked it,
// and the analysis cannot see where C obtained it. C.GoString is therefore a
// source, and the string it produces reaching exec.Command is a real finding.
//
// In RunFromC the string arrives as a parameter, so the flow is attributed to
// the parameter rather than to the conversion — the conversion only carries it.
//
// golem:want flow source=native-conversion sink=command-execution
// golem:want flow source=parameter sink=command-execution

//export RunFromC
func RunFromC(cmd *C.char) {
	// Entry point invoked by C. The argument crossed the boundary, so its
	// contents are outside anything Go can vouch for.
	_ = exec.Command("sh", "-c", C.GoString(cmd))
}

// CallIntoC hands a Go string to C and reads the result back.
func CallIntoC() {
	cs := C.CString("/bin/ls")
	defer C.free(unsafe.Pointer(cs))
	_ = exec.Command("sh", "-c", C.GoString(cs))
}
