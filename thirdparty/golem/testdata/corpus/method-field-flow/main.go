package methodfieldflow

import (
	"net/http"
	"net/url"
)

// Taint flows through a method body that accesses request fields and passes
// them through stdlib helpers (url.URL.String, url.Parse) before reaching a
// redirect sink. This exercises: method collection (the sink is inside a
// method on a named type), field-path propagation (r.URL), and url.Parse
// passthrough.
//
// golem:want flow source=http-input sink=redirect
// The bogus logging flow this once recorded came from modelling fmt.Fprintf
// as a logging sink and then descending into http.Redirect, which uses it to
// write the Location header. Both causes are fixed: fmt.Fprint* is
// formatted-output only, and a modelled sink is no longer descended into.
// golem:want-not flow source=http-input sink=logging

type resolver struct{}

func (resolver) resolve(r *http.Request) {
	u, _ := url.Parse(r.URL.String())
	http.Redirect(nil, r, u.String(), http.StatusMovedPermanently)
}

func Handler(r *http.Request) {
	resolver{}.resolve(r)
}
