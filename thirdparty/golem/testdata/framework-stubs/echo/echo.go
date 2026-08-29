// A hermetic stub of github.com/labstack/echo covering the surface golem's
// endpoint detector and handler-signature extractor recognize. Fixtures
// depend on it through a filesystem `replace` so the import path stays
// github.com/labstack/echo. Echo's Context is an interface and handlers
// receive it by value, matching the real library.
package echo

// Map is echo's ad-hoc JSON map alias. shortTypeName collapses it to
// "object".
type Map map[string]any

type Context interface {
	Param(name string) string
	QueryParam(name string) string
	Bind(i any) error
	BindJSON(i any) error
	JSON(code int, i any) error
	JSONPretty(code int, i any, indent string) error
}

type HandlerFunc func(c Context) error

type MiddlewareFunc func(next HandlerFunc) HandlerFunc

type Group struct{}

func (g *Group) GET(path string, h HandlerFunc, middleware ...MiddlewareFunc) {}
func (g *Group) POST(path string, h HandlerFunc, middleware ...MiddlewareFunc) {}

type Echo struct{}

func New() *Echo { return &Echo{} }

func (e *Echo) Group(prefix string, m ...MiddlewareFunc) *Group { return &Group{} }

func (e *Echo) GET(path string, h HandlerFunc, middleware ...MiddlewareFunc)    {}
func (e *Echo) POST(path string, h HandlerFunc, middleware ...MiddlewareFunc)   {}
func (e *Echo) PUT(path string, h HandlerFunc, middleware ...MiddlewareFunc)    {}
func (e *Echo) PATCH(path string, h HandlerFunc, middleware ...MiddlewareFunc)  {}
func (e *Echo) DELETE(path string, h HandlerFunc, middleware ...MiddlewareFunc) {}

func (e *Echo) Start(addr string) error { return nil }
