package handlerfuncvalue

import (
	"net/http"
)

// A handler closure with NO captured variables: the request arrives as a
// parameter, not a free variable. In SSA this is a *ssa.Function referenced
// directly (often via ChangeType to http.HandlerFunc), not a MakeClosure.
// Without scanning operands for *ssa.Function references, this handler is
// invisible to the engine.
//
// golem:want flow source=http-input sink=redirect

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/x", http.StatusMovedPermanently)
	})
}
