package dataflow

/*
#include <stdlib.h>
static void native_sink(char *s) { free(s); }
*/
import "C"

import (
	"crypto/aes"
	"net/http"
	"os"
	"os/exec"
	"unsafe"
)

type carrier struct {
	value string
}

func requestValue(r *http.Request) string {
	return r.FormValue("q")
}

func runCommand(v string) {
	_ = exec.Command("sh", "-c", v)
}

func Interprocedural(r *http.Request) {
	runCommand(requestValue(r))
}

func FieldFlow(r *http.Request) {
	c := &carrier{}
	c.value = r.PostFormValue("name")
	_ = os.WriteFile(c.value, []byte("x"), 0o600)
}

func ChannelFlow(r *http.Request) {
	ch := make(chan string, 1)
	ch <- r.Header.Get("X-Path")
	v := <-ch
	_ = os.WriteFile(v, []byte("x"), 0o600)
}

func ClosureFlow(r *http.Request) {
	v := r.FormValue("cmd")
	f := func() string { return v }
	_ = exec.Command("echo", f())
}

func CryptoFlow() {
	key := os.Getenv("APP_KEY")
	_, _ = aes.NewCipher([]byte(key))
}

func NativeFlow(r *http.Request) {
	v := r.FormValue("native")
	cs := C.CString(v)
	defer C.free(unsafe.Pointer(cs))
	C.native_sink(cs)
}
