package sanitizernotonpath

import (
	"net/http"
	"os"
	"path/filepath"
)

// Sanitizer not on path: sanitizer exists but is NOT on the path from source to sink.
// The flow should still be reported.
// golem:want flow source=http-input sink=filesystem
func Sanitize(s string) string {
	return filepath.Base(s) // sanitizer, but not called on the source path
}

func Handler(r *http.Request) {
	v := r.FormValue("file")
	// Note: Sanitize is NOT called on the path to os.WriteFile
	_ = os.WriteFile(v, []byte("x"), 0o600)
}
