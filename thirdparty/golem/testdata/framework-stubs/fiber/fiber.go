// A hermetic stub of github.com/gofiber/fiber/v2 covering the Ctx accessors
// and Config fields golem's forwarded-header rules recognise. Fixtures depend
// on it through a filesystem `replace`, so the module path stays
// github.com/gofiber/fiber/v2 — the versioned module path real fiber projects
// import.
package fiber

// Config mirrors the fields of fiber's Config that decide how the client
// address is resolved.
type Config struct {
	// ProxyHeader names the header Ctx.IP reads instead of the socket
	// address.
	ProxyHeader string
	// EnableTrustedProxyCheck bounds ProxyHeader handling to trusted
	// proxy addresses.
	EnableTrustedProxyCheck bool
}

type Ctx struct{}

// IP returns the client address fiber resolves from Config.ProxyHeader when
// the proxy is trusted, matching the real accessor.
func (c *Ctx) IP() string { return "" }

// IPs returns every address in X-Forwarded-For, matching the real accessor.
func (c *Ctx) IPs() []string { return nil }

type HandlerFunc func(c *Ctx) error

type App struct{}

func New(config ...Config) *App { return &App{} }

func (a *App) Get(route string, handlers ...HandlerFunc) {}
