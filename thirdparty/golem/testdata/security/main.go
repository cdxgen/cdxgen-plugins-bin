//go:build darwin || linux
// +build darwin linux

package security

//go:generate go run ./cmd/generate -out generated.go
import (
	"crypto/md5"
	"crypto/tls"
	_ "embed"
	"math/rand"
	"net/http"
	"os/exec"
	"unsafe"
)

//go:embed config/test.pem
var config []byte

func Risky(input string) {
	_, _ = exec.Command("echo", input).Output()
	_ = md5.Sum(config)
	_ = rand.Int()
	_ = unsafe.Sizeof(input)
	_, _ = http.Get("https://example.com")
	_ = &tls.Config{InsecureSkipVerify: true}
}
