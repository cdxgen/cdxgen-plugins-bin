package analyzer

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
)

// Authentication evidence for an HTTP route, recorded from the middleware the
// route actually carries.
//
// Every signature below was read from the framework's own reference, because
// the three of them disagree in exactly the place that matters — WHERE the
// handler sits among the variadic arguments — and a wrong guess names a
// middleware as the handler:
//
//	gin    func (*RouterGroup) GET(relativePath string, handlers ...HandlerFunc) IRoutes
//	       func (*RouterGroup) Group(relativePath string, handlers ...HandlerFunc) *RouterGroup
//	       func (*RouterGroup) Use(middleware ...HandlerFunc) IRoutes
//	       "the distinction is conventional, not enforced by signature": the
//	       LAST handler is the endpoint, everything before it is middleware.
//
//	fiber  func (*App) Get(path string, handlers ...Handler) Router
//	       func (*App) Group(prefix string, handlers ...Handler) Router
//	       same shape as gin: the final handler is conventionally the endpoint.
//
//	echo   func (*Echo) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route
//	       func (*Echo) Group(prefix string, m ...MiddlewareFunc) (g *Group)
//	       func (*Echo) Use(middleware ...MiddlewareFunc)
//	       the OPPOSITE of gin: the handler is argument 1 and middleware
//	       FOLLOWS it.
//
//	chi    Get(pattern string, h http.HandlerFunc)
//	       Use(middlewares ...func(http.Handler) http.Handler)
//	       With(middlewares ...func(http.Handler) http.Handler) Router
//	       no route-level middleware at all; it arrives via Use/With/Group.
//
// Frameworks whose signatures have not been read this way (gorilla/mux, iris,
// beego, buffalo) are deliberately left out rather than assumed into: see
// [routeMiddlewareShape].

// authTokens are the name fragments that make a middleware an AUTHENTICATION
// middleware rather than logging, CORS or recovery. Matching is on the
// lower-cased callee name.
//
// This list is the honest weak point of the detection and is treated as such:
// a hit produces evidence naming the middleware, so a reader can judge it, and
// a miss produces NOTHING rather than "anonymous" — an empty result is never a
// denial (the exposure contract's first rule).
var authTokens = []string{
	"auth", "authn", "authz", "jwt", "oauth", "oidc", "bearer", "token",
	"login", "session", "principal", "identity", "claims", "rbac", "casbin",
	"permission", "requireuser", "requireadmin", "requirerole", "protected",
	"authenticate", "authorize", "basicauth", "keyauth", "apikey",
}

// authExcludeTokens are names that contain an auth token but are not an
// authentication requirement. `NoAuth`/`SkipAuth` are the inverse marker and
// must never read as a requirement.
var authExcludeTokens = []string{"noauth", "skipauth", "withoutauth", "unauthenticated", "anonymous"}

// isAuthMiddlewareName reports whether a middleware's name declares an
// authentication requirement.
func isAuthMiddlewareName(name string) bool {
	// Separators are stripped before matching: `skip_auth`, `skip-auth` and
	// `SkipAuth` are one name in three spellings, and an exclusion list that
	// only knew the third would read the other two as a REQUIREMENT — the
	// exact inversion this list exists to prevent.
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	lower := b.String()
	if lower == "" {
		return false
	}
	for _, bad := range authExcludeTokens {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	for _, tok := range authTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// middlewareName renders the callee of a middleware argument. Both spellings
// occur: a bare reference (`authMiddleware`) and a constructor call
// (`middleware.JWT(secret)`, `gin.BasicAuth(accounts)`).
func middlewareName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if e.Sel == nil {
			return ""
		}
		if x, ok := e.X.(*ast.Ident); ok {
			return x.Name + "." + e.Sel.Name
		}
		return e.Sel.Name
	case *ast.CallExpr:
		return middlewareName(e.Fun)
	case *ast.IndexExpr:
		return middlewareName(e.X)
	}
	return ""
}

// routeMiddlewareShape says, for one framework, where the endpoint handler
// sits among a route call's arguments and which of the rest are middleware.
//
// handlerLast: the handler is the final variadic argument and everything
// between the path and it is middleware (gin, fiber).
// middlewareFrom >= 0: the handler is at handlerArg and middleware starts at
// this index (echo).
// Neither: the framework carries no route-level middleware (chi, net/http),
// or its signature has not been verified, in which case nothing is claimed.
type routeMiddlewareShape struct {
	handlerLast    bool
	middlewareFrom int
}

func shapeForFramework(framework string) routeMiddlewareShape {
	switch framework {
	case "gin", "fiber":
		return routeMiddlewareShape{handlerLast: true, middlewareFrom: -1}
	case "echo":
		return routeMiddlewareShape{middlewareFrom: 2}
	default:
		return routeMiddlewareShape{middlewareFrom: -1}
	}
}

// authFromExprs collects the authentication declarations carried by a set of
// middleware argument expressions.
func authFromExprs(exprs []ast.Expr) []string {
	var out []string
	for _, expr := range exprs {
		name := middlewareName(expr)
		if isAuthMiddlewareName(name) {
			out = append(out, fmt.Sprintf("middleware(%s)", name))
		}
	}
	return out
}

// dedupeAuth returns the sorted, de-duplicated declarations.
func dedupeAuth(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// recordGroupMiddleware records the auth middleware a group declaration
// carries, keyed by the variable the group is assigned to.
//
//	api := r.Group("/api", RequireAuth)   // gin, fiber
//	api := e.Group("/api", middleware.JWT(k)) // echo
//
// The group's own inherited middleware is carried forward, because a subgroup
// of an authenticated group is authenticated.
func (a *Analyzer) recordGroupMiddleware(call *ast.CallExpr, receiver string, groupAuth map[string][]string) []string {
	inherited := append([]string(nil), groupAuth[receiver]...)
	if len(call.Args) > 1 {
		inherited = append(inherited, authFromExprs(call.Args[1:])...)
	}
	return dedupeAuth(inherited)
}

// authForRoute is the whole conclusion for one route call: what the group it
// belongs to declares, plus what the call itself carries.
func authForRoute(
	framework string,
	receiver string,
	call *ast.CallExpr,
	handlerArg int,
	groupAuth map[string][]string,
	useAuth []string,
) ([]string, string) {
	var decls []string
	sources := map[string]bool{}

	if inherited := groupAuth[receiver]; len(inherited) > 0 {
		decls = append(decls, inherited...)
		sources["group"] = true
	}
	if len(useAuth) > 0 {
		decls = append(decls, useAuth...)
		sources["use"] = true
	}

	shape := shapeForFramework(framework)
	var mw []ast.Expr
	switch {
	case shape.handlerLast && len(call.Args) > 2:
		// gin/fiber: everything between the path and the final handler.
		mw = call.Args[1 : len(call.Args)-1]
	case shape.middlewareFrom >= 0 && len(call.Args) > shape.middlewareFrom:
		// echo: everything after the handler.
		mw = call.Args[shape.middlewareFrom:]
	}
	if found := authFromExprs(mw); len(found) > 0 {
		decls = append(decls, found...)
		sources["route"] = true
	}

	decls = dedupeAuth(decls)
	if len(decls) == 0 {
		// Nothing declared. NOT a statement that the route is anonymous:
		// the caller emits no field at all, which reads as unknown.
		return nil, ""
	}
	keys := make([]string, 0, len(sources))
	for k := range sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return decls, framework + "-" + strings.Join(keys, "+")
}
