package pkgconfigrefused

/*
#cgo pkg-config: --with-path=/tmp --personality=/tmp/x.pc openssl
*/
import "C"

func Marker() { _ = C.int(0) }
