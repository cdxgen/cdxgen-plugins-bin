package sanitizeronpath

import (
	"net/http"
	"os"
	"path/filepath"
)

// The positive control for sanitizers: filepath.Base is genuinely on the path
// from source to sink, so the filesystem flow must be suppressed. Paired with
// sanitizer-not-on-path-negative, which requires the flow to survive when the
// sanitizer is merely present in the package.
// golem:want-not flow source=http-input sink=filesystem
func Handler(r *http.Request) {
	name := filepath.Base(r.FormValue("file"))
	_ = os.WriteFile(name, []byte("x"), 0o600)
}
