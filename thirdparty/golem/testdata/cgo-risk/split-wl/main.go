package splitwl

/*
#cgo LDFLAGS: -Wl,-rpath /opt/evil/lib
*/
import "C"

func Marker() { _ = C.int(0) }
