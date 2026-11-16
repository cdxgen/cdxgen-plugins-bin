package gnat

/*
#cgo CFLAGS: -gnatO /tmp/out.o
*/
import "C"

func Marker() { _ = C.int(0) }
