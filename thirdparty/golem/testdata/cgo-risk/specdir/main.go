package specdir

/*
#cgo LDFLAGS: -L ${SRCDIR}/specs
*/
import "C"

func Marker() { _ = C.int(0) }
