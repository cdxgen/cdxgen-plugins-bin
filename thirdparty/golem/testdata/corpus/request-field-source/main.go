package requestfieldsource

import (
	"log"
	"net/http"
)

// The request itself is the source, reached by field access rather than by a
// modelled accessor: r.URL.Path is user-controlled without any call to
// FormValue, Header.Get or friends. This is the dominant shape in real HTTP
// libraries — go-chi's middleware reaches http.Redirect and the logger from
// exactly here — and it is the one case the rest of the corpus did not cover,
// because every other fixture taints through a modelled method call. The
// engine's parameter-type source model is the only thing that can see it, and
// deleting that single model entry took a real library from seven findings to
// zero while every fixture here stayed green.
//
// golem:want flow source=http-input sink=redirect
// golem:want flow source=http-input sink=logging
func Middleware(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path
	log.Printf("serving %s", target)
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
