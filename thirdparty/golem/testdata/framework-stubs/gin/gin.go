// A hermetic stub of github.com/gin-gonic/gin covering the API surface
// golem's endpoint detector and handler-signature extractor recognize.
// Fixtures depend on it through a filesystem `replace`, so the module path
// stays github.com/gin-gonic/gin — golem classifies frameworks by resolved
// import path, not by file location. Nothing here is executable; the
// analyzer reads source, it never runs the fixture.
package gin

// H is gin's ad-hoc JSON map alias. shortTypeName collapses it to "object"
// so downstream OpenAPI generators emit a free-form object schema instead
// of a $ref to a type with no declaration.
type H map[string]any

type Context struct{}

func (c *Context) Param(name string) string { return "" }

func (c *Context) Query(name string) string { return "" }

func (c *Context) DefaultQuery(name, defaultValue string) string { return defaultValue }

func (c *Context) GetQuery(name string) (string, bool) { return "", false }

func (c *Context) ShouldBindJSON(obj any) error { return nil }

func (c *Context) BindJSON(obj any) error { return nil }

func (c *Context) ShouldBind(obj any) error { return nil }

func (c *Context) Bind(obj any) error { return nil }

func (c *Context) JSON(status int, obj any) {}

func (c *Context) AbortWithStatusJSON(status int, obj any) {}

func (c *Context) Status(status int) {}

// ClientIP returns the client address as gin resolves it, honouring
// Engine.ForwardedByClientIP and Engine.RemoteIPHeaders.
func (c *Context) ClientIP() string { return "" }

// RemoteIP splits the address from Request.RemoteAddr without consulting
// any header, matching the real library.
func (c *Context) RemoteIP() string { return "" }

// GetHeader reads a request header by name.
func (c *Context) GetHeader(key string) string { return "" }

type HandlerFunc func(c *Context)

type Engine struct {
	// ForwardedByClientIP decides whether ClientIP consults the forwarded
	// headers instead of the socket address.
	ForwardedByClientIP bool
	// RemoteIPHeaders lists the headers ClientIP reads, in order.
	RemoteIPHeaders []string
}

// SetTrustedProxies bounds which proxy addresses gin believes when it reads
// the forwarded headers.
func (e *Engine) SetTrustedProxies(trustedProxies []string) error { return nil }

type RouterGroup struct{}

func Default() *Engine { return &Engine{} }

func (e *Engine) Group(prefix string, handlers ...HandlerFunc) *RouterGroup { return &RouterGroup{} }

func (e *Engine) GET(path string, handlers ...HandlerFunc)    {}
func (e *Engine) POST(path string, handlers ...HandlerFunc)   {}
func (e *Engine) PUT(path string, handlers ...HandlerFunc)    {}
func (e *Engine) PATCH(path string, handlers ...HandlerFunc)  {}
func (e *Engine) DELETE(path string, handlers ...HandlerFunc) {}
func (e *Engine) Run(addr ...string) error                    { return nil }

func (r *RouterGroup) Group(prefix string, handlers ...HandlerFunc) *RouterGroup {
	return &RouterGroup{}
}

func (r *RouterGroup) GET(path string, handlers ...HandlerFunc)    {}
func (r *RouterGroup) POST(path string, handlers ...HandlerFunc)   {}
func (r *RouterGroup) PUT(path string, handlers ...HandlerFunc)    {}
func (r *RouterGroup) PATCH(path string, handlers ...HandlerFunc)  {}
func (r *RouterGroup) DELETE(path string, handlers ...HandlerFunc) {}
