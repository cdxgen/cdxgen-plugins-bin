package macosloader

/*
#cgo LDFLAGS: -lazy_library /tmp/libevil -lto_library /tmp/liblto -load_hidden /tmp/libhidden -library-path /tmp/libdir
*/
import "C"

func Marker() { _ = C.int(0) }
