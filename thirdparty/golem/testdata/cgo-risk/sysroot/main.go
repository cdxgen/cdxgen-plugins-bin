package sysroot

/*
#cgo CFLAGS: --sysroot /opt/evil-sysroot
*/
import "C"

func Marker() { _ = C.int(0) }
