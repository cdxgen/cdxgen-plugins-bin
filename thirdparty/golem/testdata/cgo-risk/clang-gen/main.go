package clanggen

/*
#cgo CFLAGS: -gen-cdb-fragment-path /tmp
*/
import "C"

func Marker() { _ = C.int(0) }
