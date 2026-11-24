package dockergocheck

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
*/
import "C"

import "unsafe"

// The Dockerfile in this module turns cgo pointer checking off with
// GODEBUG=cgocheck=0, so the untyped checks cgo still emits are the only
// guard left, and the configuration itself is the finding. The signal is
// reported at the ENV line in the Dockerfile, from the configuration scan.
//
// golem:want signal category=cgocheck-disabled line=4 symbol=GODEBUG
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=20
func Hide(data []byte) {
	p := unsafe.Pointer(&data[0])
	C.take(p)
}
