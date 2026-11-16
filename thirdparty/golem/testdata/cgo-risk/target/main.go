package target

/*
#cgo CFLAGS: -target x86_64-evil
*/
import "C"

func Marker() { _ = C.int(0) }
