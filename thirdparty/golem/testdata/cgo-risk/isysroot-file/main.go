package isysrootfile

/*
#cgo CFLAGS: -isysroot main.go
*/
import "C"

func Marker() { _ = C.int(0) }
