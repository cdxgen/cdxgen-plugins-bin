package dataflow

/*
#include <stdlib.h>
static void native_sink(char *s) { free(s); }
*/
import "C"

import (
	"crypto/aes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"
)

type carrier struct {
	value string
}

type Runner interface {
	Run(string)
}

type ShellRunner struct{}

func (ShellRunner) Run(v string) {
	_ = exec.Command("sh", "-c", v)
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

func InterfaceFlow(r *http.Request) {
	var runner Runner = ShellRunner{}
	runner.Run(r.FormValue("cmd"))
}

func FieldFlow(r *http.Request) {
	c := &carrier{}
	c.value = r.PostFormValue("name")
	_ = os.WriteFile(c.value, []byte("x"), 0o600)
}

func SanitizedPathFlow(r *http.Request) {
	safe := filepath.Base(r.FormValue("file"))
	_ = os.WriteFile(safe, []byte("x"), 0o600)
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

func Handler(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	_, _ = fmt.Fprintf(w, q)
}

func RegisterEndpoints() {
	http.HandleFunc("/search", Handler)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/exec", Handler)
	_ = http.ListenAndServe(":8080", mux)
	_ = "https://api.example.com/v1/search?token=redacted#fragment"
}
