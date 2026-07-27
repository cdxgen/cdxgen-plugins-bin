package sanitizerdominates

import (
	"net/http"
	"os"
	"path/filepath"
)

// Sanitizer dominates: the sanitizer (filepath.Base) dominates the path to the sink.
// The flow should be suppressed.
// golem:want-not flow source=http-input sink=filesystem
func Handler(r *http.Request) {
	safe := filepath.Base(r.FormValue("file"))
	_ = os.WriteFile(safe, []byte("x"), 0o600)
}
