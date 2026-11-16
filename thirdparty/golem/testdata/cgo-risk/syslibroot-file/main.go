package syslibrootfile

/*
#cgo LDFLAGS: -Wl,-syslibroot,main.go
*/
import "C"

func Marker() { _ = C.int(0) }
