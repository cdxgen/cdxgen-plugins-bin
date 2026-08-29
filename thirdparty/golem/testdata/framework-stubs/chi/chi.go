// A hermetic stub of github.com/go-chi/chi covering the surface golem's
// endpoint detector and handler-signature extractor recognize. Fixtures
// depend on it through a filesystem `replace` so the import path stays
// github.com/go-chi/chi.
package chi

import "net/http"

// URLParam returns the URL parameter matched by the {name} wildcard.
// The extractor reads its second argument to recover path parameters.
func URLParam(r *http.Request, key string) string { return "" }

type Mux struct{}

func NewRouter() *Mux { return &Mux{} }

func (m *Mux) Use(middleware ...func(http.Handler) http.Handler) {}

func (m *Mux) Group(fn func(r *Mux)) *Mux { return m }

func (m *Mux) Get(pattern string, handlerFn http.HandlerFunc)    {}
func (m *Mux) Post(pattern string, handlerFn http.HandlerFunc)   {}
func (m *Mux) Put(pattern string, handlerFn http.HandlerFunc)    {}
func (m *Mux) Patch(pattern string, handlerFn http.HandlerFunc)  {}
func (m *Mux) Delete(pattern string, handlerFn http.HandlerFunc) {}

// ServeHTTP lets a *Mux be passed to http.ListenAndServe, as the real Mux
// does.
func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {}
