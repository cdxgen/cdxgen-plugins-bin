package analyzer

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// Framework import paths the handler-signature extractor is phrased
// against. Matching on resolved package paths (via the type checker) keeps
// the extractor working under aliased or renamed imports.
const (
	ginImportPath     = "github.com/gin-gonic/gin"
	chiImportPath     = "github.com/go-chi/chi"
	renderImportPath  = "github.com/go-chi/render"
	echoImportPath    = "github.com/labstack/echo"
	nethttpImportPath = "net/http"
	jsonImportPath    = "encoding/json"
)

// handlerSignatureExtractor walks HTTP-handler function bodies and lifts
// framework-specific helper calls into structured [model.EndpointParameter]
// values plus request-body and response types. It turns what the endpoint
// detector recorded (framework + method + path + handler name) into the
// shape information downstream tooling needs to generate OpenAPI schemas.
//
// Supported patterns, keyed on resolved package paths and the handler's
// parameter types rather than identifier spellings:
//
//   - gin (github.com/gin-gonic/gin): `c.Param("name")` for path params;
//     `c.Query("name")`, `c.DefaultQuery`, `c.GetQuery` for query params;
//     `c.ShouldBindJSON(&x)` and friends for the request body; `c.JSON(status,
//     expr)` and its variants for the response.
//   - chi (github.com/go-chi/chi): `chi.URLParam(r, "name")` for path params;
//     `render.DecodeJSON(r.Body, &x)` / `render.Bind(r, &x)` for the request
//     body; `render.JSON(w, r, expr)` / `render.Respond` for the response.
//   - echo (github.com/labstack/echo): `c.Param("name")` for path params;
//     `c.QueryParam("name")` for query params; `c.Bind(&x)` / `c.BindJSON(&x)`
//     for the request body; `c.JSON(status, expr)` / `c.JSONPretty` for the
//     response.
//   - net/http and chi handlers: `r.PathValue("id")` for path params;
//     `r.URL.Query().Get("q")` for query params; `json.NewDecoder(r.Body)
//     .Decode(&x)` for the request body; `json.NewEncoder(w).Encode(expr)`
//     for the response.
//
// Known limitations, all deliberate: handlers defined in a different package
// than the one that registered the route contribute no enrichment (the
// handler index is per package); calls routed through package-level helper
// functions are not followed; response emitters behind unrecognized wrappers
// are missed. Extraction is best-effort — a wrong parameter type is worse
// than a missing one, since downstream tools will happily generate the wrong
// schema.
type handlerSignatureExtractor struct {
	pkg      *packages.Package
	handlers map[string]*ast.FuncDecl
}

func newHandlerSignatureExtractor(pkg *packages.Package) *handlerSignatureExtractor {
	e := &handlerSignatureExtractor{pkg: pkg, handlers: map[string]*ast.FuncDecl{}}
	if pkg == nil {
		return e
	}
	// Index handler-shaped function declarations by their short name so we
	// can resolve endpoint.handler back to a *ast.FuncDecl without
	// re-walking the AST per endpoint. Endpoint handlers only carry the
	// short name (method expressions surface as "svc.Ping"), so the
	// short-name key is the join column that matches. Collisions across
	// declarations are resolved last-wins; the enrichment still errs on the
	// side of omission when the chosen body matches no known pattern.
	for _, file := range pkg.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			e.handlers[fn.Name.Name] = fn
		}
	}
	return e
}

// handlerRoles records which handler parameters carry the framework objects
// the recognized helper patterns are phrased against. A gin/echo context is
// a ctx role; chi and net/http handlers use request and response roles.
type handlerRoles struct {
	ctx      map[string]bool
	request  map[string]bool
	response map[string]bool
}

func (r handlerRoles) empty() bool {
	return len(r.ctx) == 0 && len(r.request) == 0 && len(r.response) == 0
}

// endpointSignature accumulates what one handler body taught us. The error
// response is kept apart from the primary response and only promoted when
// the handler never emits a successful shape.
type endpointSignature struct {
	parameters        []model.EndpointParameter
	requestBodyType   string
	responseType      string
	errorResponseType string
	seenPath          map[string]bool
	seenQuery         map[string]bool
}

func (sig *endpointSignature) addParam(name, location, typeName string) {
	seen := sig.seenQuery
	if location == "path" {
		seen = sig.seenPath
	}
	if seen[name] {
		return
	}
	seen[name] = true
	sig.parameters = append(sig.parameters, model.EndpointParameter{Name: name, Location: location, TypeName: typeName})
}

// enrich populates [model.APIEndpoint.Parameters], RequestBodyType, and
// ResponseType by walking the handler's function body. Called once per
// endpoint after endpointForCall has done the framework/method/path work.
func (e *handlerSignatureExtractor) enrich(endpoint *model.APIEndpoint) {
	if endpoint == nil || endpoint.Kind != "http-route" || endpoint.Handler == "" || e.pkg == nil || e.pkg.TypesInfo == nil {
		return
	}
	fn, ok := e.handlers[handlerShortName(endpoint.Handler)]
	if !ok || fn.Body == nil {
		return
	}
	roles := e.handlerRolesFor(fn, endpoint.Framework)
	if roles.empty() {
		return
	}
	sig := &endpointSignature{seenPath: map[string]bool{}, seenQuery: map[string]bool{}}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		e.inspectCall(call, roles, sig)
		return true
	})
	// A handler whose every response is an error still deserves a schema:
	// promote the first observed error shape, but never let it displace a
	// successful one.
	if sig.responseType == "" {
		sig.responseType = sig.errorResponseType
	}
	endpoint.Parameters = sig.parameters
	endpoint.RequestBodyType = sig.requestBodyType
	endpoint.ResponseType = sig.responseType
}

// handlerRolesFor classifies the handler's parameters by resolved type:
// the framework context objects for gin/echo, and *http.Request /
// http.ResponseWriter for chi and net/http handlers. Falls back to source
// text when the type checker has no entry for the parameter.
func (e *handlerSignatureExtractor) handlerRolesFor(fn *ast.FuncDecl, framework string) handlerRoles {
	roles := handlerRoles{ctx: map[string]bool{}, request: map[string]bool{}, response: map[string]bool{}}
	if fn.Type == nil || fn.Type.Params == nil {
		return roles
	}
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			continue
		}
		role := ""
		if named := e.namedTypeOf(field.Type); named != nil {
			role = roleForNamedType(named)
		}
		if role == "" {
			role = roleForTypeText(exprTypeText(field.Type), framework)
		}
		if role == "" {
			continue
		}
		for _, ident := range field.Names {
			switch role {
			case "ctx":
				roles.ctx[ident.Name] = true
			case "request":
				roles.request[ident.Name] = true
			case "response":
				roles.response[ident.Name] = true
			}
		}
	}
	return roles
}

func roleForNamedType(named *types.Named) string {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return ""
	}
	path := named.Obj().Pkg().Path()
	name := named.Obj().Name()
	switch {
	case path == ginImportPath && name == "Context", path == echoImportPath && name == "Context":
		return "ctx"
	case path == nethttpImportPath && name == "Request":
		return "request"
	case path == nethttpImportPath && name == "ResponseWriter":
		return "response"
	}
	return ""
}

// roleForTypeText is the fallback when type info is unavailable; it matches
// the source spelling, so it only helps the non-aliased case.
func roleForTypeText(text, framework string) string {
	switch framework {
	case "gin":
		if strings.Contains(text, "gin.Context") {
			return "ctx"
		}
	case "echo":
		if strings.Contains(text, "echo.Context") {
			return "ctx"
		}
	}
	if strings.Contains(text, "http.Request") {
		return "request"
	}
	if strings.Contains(text, "http.ResponseWriter") {
		return "response"
	}
	return ""
}

// inspectCall matches one call expression inside a handler body against the
// supported patterns. Each branch returns after the first match so a call
// contributes to at most one slot.
func (e *handlerSignatureExtractor) inspectCall(call *ast.CallExpr, roles handlerRoles, sig *endpointSignature) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	// Package-qualified helpers: chi.URLParam, render.DecodeJSON, render.JSON.
	if pkgPath, method := e.packageSelector(sel); pkgPath != "" {
		e.inspectPackageCall(call, pkgPath, method, roles, sig)
		return
	}
	// json.NewDecoder(r.Body).Decode(&x) and json.NewEncoder(w).Encode(expr):
	// chained calls whose receiver is a constructor invocation.
	switch sel.Sel.Name {
	case "Decode":
		if e.isJSONCodecConstruction(sel.X, "NewDecoder", roles.request) {
			e.recordRequestBody(call.Args, sig)
		}
		return
	case "Encode":
		if e.isJSONCodecConstruction(sel.X, "NewEncoder", roles.response) {
			e.recordResponse(call.Args, sig, 0)
		}
		return
	}
	// Method calls on the handler's framework objects.
	if ident, ok := sel.X.(*ast.Ident); ok {
		switch {
		case roles.ctx[ident.Name]:
			e.inspectContextMethod(call, sel.Sel.Name, sig)
		case roles.request[ident.Name]:
			e.inspectRequestMethod(call, sel.Sel.Name, sig)
		}
		return
	}
	// r.URL.Query().Get("q") — a chained accessor ending in Get on a
	// request-derived url.Values expression.
	if sel.Sel.Name == "Get" && len(call.Args) > 0 && e.isRequestValuesExpr(sel.X, roles) {
		if name, ok := stringLiteral(call.Args[len(call.Args)-1]); ok {
			sig.addParam(name, "query", "string")
		}
	}
}

// inspectPackageCall handles helper calls qualified by an imported package.
func (e *handlerSignatureExtractor) inspectPackageCall(call *ast.CallExpr, pkgPath, method string, roles handlerRoles, sig *endpointSignature) {
	switch pkgPath {
	case chiImportPath:
		if method == "URLParam" {
			// chi.URLParam(r, "id") — only trust the name when the receiver
			// argument is one of the handler's request parameters.
			if name, ok := e.paramNameAt(call, roles.request, 0, 1); ok {
				sig.addParam(name, "path", "string")
			}
		}
	case renderImportPath:
		switch method {
		case "DecodeJSON", "Bind":
			// render.DecodeJSON(r.Body, &req) / render.Bind(r, &req)
			e.recordRequestBody(call.Args, sig)
		case "JSON", "Respond":
			// render.JSON(w, r, expr)
			if len(call.Args) >= 3 {
				e.recordResponse(call.Args, sig, 2)
			}
		}
	}
}

// inspectContextMethod handles method calls on a gin/echo context object.
// Both frameworks share method shapes, so one switch serves them.
func (e *handlerSignatureExtractor) inspectContextMethod(call *ast.CallExpr, method string, sig *endpointSignature) {
	switch method {
	case "Param":
		if name, ok := stringFirstArg(call); ok {
			sig.addParam(name, "path", "string")
		}
	case "Query", "DefaultQuery", "GetQuery", "QueryParam":
		if name, ok := stringFirstArg(call); ok {
			sig.addParam(name, "query", "string")
		}
	case "ShouldBindJSON", "BindJSON", "ShouldBind", "Bind",
		"ShouldBindWith", "BindWith", "ShouldBindBodyWith",
		"ShouldBindXML", "BindXML", "ShouldBindYAML", "BindYAML":
		e.recordRequestBody(call.Args, sig)
	case "ShouldBindQuery", "BindQuery":
		// Binds query parameters into a struct: no request body is read, and
		// lifting the struct's form tags into parameters is a separate
		// extraction problem. Deliberately unhandled.
	case "JSON", "JSONP", "IndentedJSON", "SecureJSON", "PureJSON", "AsciiJSON", "JSONPretty":
		e.recordStatusResponse(call, sig)
	case "AbortWithStatusJSON":
		// Error-path helper; its payload only surfaces when the handler has
		// no successful response at all (see recordStatusResponse).
		e.recordStatusResponse(call, sig)
	}
}

// inspectRequestMethod handles method calls on an *http.Request parameter.
func (e *handlerSignatureExtractor) inspectRequestMethod(call *ast.CallExpr, method string, sig *endpointSignature) {
	if method == "PathValue" {
		// Go 1.22+ wildcard segments: r.PathValue("id").
		if name, ok := stringFirstArg(call); ok {
			sig.addParam(name, "path", "string")
		}
	}
}

// paramNameAt extracts the string-literal parameter name at args[nameArg] of
// a helper like chi.URLParam(r, "id"), and only trusts it when the receiver
// argument at args[receiverArg] is one of the handler's request parameters.
// When no request parameter could be resolved at all, the check is lenient.
func (e *handlerSignatureExtractor) paramNameAt(call *ast.CallExpr, allowed map[string]bool, receiverArg, nameArg int) (string, bool) {
	if nameArg >= len(call.Args) || receiverArg >= len(call.Args) {
		return "", false
	}
	if ident, ok := call.Args[receiverArg].(*ast.Ident); ok && len(allowed) > 0 && !allowed[ident.Name] {
		return "", false
	}
	return stringLiteral(call.Args[nameArg])
}

// isJSONCodecConstruction reports whether expr is `json.NewDecoder(...)` or
// `json.NewEncoder(...)` (resolved by package path, so import aliases work)
// whose argument is the matching handler parameter: a request body for a
// decoder, a response writer for an encoder.
func (e *handlerSignatureExtractor) isJSONCodecConstruction(expr ast.Expr, constructor string, allowed map[string]bool) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != constructor {
		return false
	}
	if pkgPath, _ := e.packageSelector(sel); pkgPath != jsonImportPath {
		return false
	}
	// The codec must be built on the handler's own parameter: the request
	// body for a decoder (json.NewDecoder(r.Body)) or the response writer
	// for an encoder (json.NewEncoder(w)).
	switch arg := call.Args[0].(type) {
	case *ast.Ident:
		return allowed[arg.Name]
	case *ast.SelectorExpr:
		ident, ok := arg.X.(*ast.Ident)
		return ok && allowed[ident.Name]
	}
	return false
}

// isRequestValuesExpr reports whether expr is a request-derived url.Values
// expression — `r.URL.Query()`.
func (e *handlerSignatureExtractor) isRequestValuesExpr(expr ast.Expr, roles handlerRoles) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Query" {
		return false
	}
	// Accept both `r.URL.Query()` and `u := r.URL; u.Query()`.
	switch x := sel.X.(type) {
	case *ast.SelectorExpr:
		if ident, ok := x.X.(*ast.Ident); ok {
			return roles.request[ident.Name]
		}
	case *ast.Ident:
		return roles.request[x.Name]
	}
	return false
}

// packageSelector resolves a selector whose receiver is a package name to
// the imported package's path, so `chi.URLParam` and `c "github.com/go-chi/chi"`
// aliased references both resolve to github.com/go-chi/chi.
func (e *handlerSignatureExtractor) packageSelector(sel *ast.SelectorExpr) (string, string) {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", ""
	}
	if obj, ok := e.pkg.TypesInfo.Uses[ident].(*types.PkgName); ok && obj.Imported() != nil {
		return obj.Imported().Path(), sel.Sel.Name
	}
	return "", ""
}

// ─── request body / response extraction ─────────────────────────────────

// recordRequestBody records the type a bind helper binds. The bind target
// is the last argument that is either an `&x` expression or an identifier
// of pointer type — scanning from the end keeps leading arguments like the
// chi `r` or `r.Body` from being mistaken for the target.
func (e *handlerSignatureExtractor) recordRequestBody(args []ast.Expr, sig *endpointSignature) {
	if sig.requestBodyType != "" {
		return
	}
	for i := len(args) - 1; i >= 0; i-- {
		arg := args[i]
		if unary, ok := arg.(*ast.UnaryExpr); ok && unary.Op == token.AND {
			if name := e.typeNameOf(unary.X); name != "" {
				sig.requestBodyType = name
			}
			return
		}
		if ident, ok := arg.(*ast.Ident); ok && e.isPointerExpr(ident) {
			if name := e.typeNameOf(ident); name != "" {
				sig.requestBodyType = name
			}
			return
		}
	}
}

// recordStatusResponse handles the (status, expr) response shape shared by
// gin's and echo's context emitters. A 4xx/5xx status marks the payload as
// the error shape: it is remembered separately and only promoted to the
// endpoint's response type when the handler never emits a successful
// response. The error payload is not the operation's primary schema, but it
// beats reporting nothing for handlers whose every path is an error.
func (e *handlerSignatureExtractor) recordStatusResponse(call *ast.CallExpr, sig *endpointSignature) {
	if len(call.Args) < 2 {
		return
	}
	if e.isErrorStatusExpr(call.Args[0]) {
		if sig.errorResponseType == "" {
			sig.errorResponseType = e.typeNameOf(call.Args[1])
		}
		return
	}
	e.recordResponse(call.Args, sig, 1)
}

func (e *handlerSignatureExtractor) recordResponse(args []ast.Expr, sig *endpointSignature, exprArg int) {
	if sig.responseType != "" || len(args) <= exprArg {
		return
	}
	if name := e.typeNameOf(args[exprArg]); name != "" {
		sig.responseType = name
	}
}

// ─── type helpers ────────────────────────────────────────────────────────

func (e *handlerSignatureExtractor) namedTypeOf(expr ast.Expr) *types.Named {
	typ := e.typeOf(expr)
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, _ := typ.(*types.Named)
	return named
}

func (e *handlerSignatureExtractor) typeOf(expr ast.Expr) types.Type {
	if e.pkg == nil || e.pkg.TypesInfo == nil || expr == nil {
		return nil
	}
	return e.pkg.TypesInfo.TypeOf(expr)
}

func (e *handlerSignatureExtractor) isPointerExpr(expr ast.Expr) bool {
	_, ok := e.typeOf(expr).(*types.Pointer)
	return ok
}

// typeNameOf resolves an expression to the short schema name of its type,
// dereferencing pointers so `&req` and `req` (a *T variable) both yield T.
func (e *handlerSignatureExtractor) typeNameOf(expr ast.Expr) string {
	typ := e.typeOf(expr)
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	return shortTypeName(typ)
}

// freeFormObjectTypePaths lists framework-provided ad-hoc map aliases by
// package path and type name. They carry no schema beyond "object" — they
// are map[string]any under a friendlier name — and matching on the package
// path (not the identifier spelled at the callsite) keeps a user's own type
// named H or Map from collapsing.
var freeFormObjectTypePaths = map[string]bool{
	"github.com/gin-gonic/gin.H":      true,
	"github.com/labstack/echo.Map":    true,
	"github.com/gofiber/fiber/v2.Map": true,
}

// shortTypeName strips package qualifiers so the emitted name is what
// downstream OpenAPI generators expect — `User` rather than
// `github.com/acme/api/models.User`. Slice multiplicity is preserved
// (`[]User`), pointers are dereferenced, framework map aliases and plain
// maps collapse to `object`, and the empty interface becomes `any`.
func shortTypeName(t types.Type) string {
	if t == nil {
		return ""
	}
	switch typ := t.(type) {
	case *types.Pointer:
		return shortTypeName(typ.Elem())
	case *types.Slice:
		inner := shortTypeName(typ.Elem())
		if inner == "" {
			return ""
		}
		return "[]" + inner
	case *types.Array:
		inner := shortTypeName(typ.Elem())
		if inner == "" {
			return ""
		}
		// Fixed-size arrays surface as arrays, without their length.
		return "[]" + inner
	case *types.Named:
		obj := typ.Obj()
		if obj == nil {
			return ""
		}
		if obj.Pkg() != nil && freeFormObjectTypePaths[obj.Pkg().Path()+"."+obj.Name()] {
			return "object"
		}
		return obj.Name()
	case *types.Basic:
		return typ.Name()
	case *types.Interface:
		if typ.Empty() {
			return "any"
		}
		return ""
	case *types.Map:
		return "object"
	}
	return ""
}

// handlerShortName strips leading package or receiver qualifiers from a
// handler string so it matches the file-level FuncDecl index. Registrations
// that pass method values (e.g. `svc.CreateUser`) surface as "CreateUser".
func handlerShortName(handler string) string {
	if handler == "" {
		return ""
	}
	if idx := strings.LastIndex(handler, "."); idx >= 0 {
		return handler[idx+1:]
	}
	return handler
}

// ─── status classification ───────────────────────────────────────────────

// isErrorStatusExpr reports whether a response-emitter status argument names
// a 4xx or 5xx code: integer literals, any integer constant the type checker
// resolved (covering http.StatusBadRequest and framework status wrappers),
// and, when no constant value is available, the well-known net/http status
// names.
func (e *handlerSignatureExtractor) isErrorStatusExpr(expr ast.Expr) bool {
	if lit, ok := expr.(*ast.BasicLit); ok {
		if value, err := strconv.Atoi(lit.Value); err == nil {
			return value >= 400 && value < 600
		}
		return false
	}
	if e.pkg.TypesInfo != nil {
		if tv, ok := e.pkg.TypesInfo.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int {
			if value, ok := constant.Int64Val(tv.Value); ok {
				return value >= 400 && value < 600
			}
		}
	}
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		return isErrorStatusName(v.Sel.Name)
	case *ast.Ident:
		return isErrorStatusName(v.Name)
	}
	return false
}

func isErrorStatusName(name string) bool {
	// Only names known for certain to be 4xx/5xx; anything else falls
	// through, which is the safe default (assume success).
	switch name {
	case "StatusBadRequest", "StatusUnauthorized", "StatusPaymentRequired",
		"StatusForbidden", "StatusNotFound", "StatusMethodNotAllowed",
		"StatusNotAcceptable", "StatusProxyAuthRequired", "StatusRequestTimeout",
		"StatusConflict", "StatusGone", "StatusLengthRequired",
		"StatusPreconditionFailed", "StatusRequestEntityTooLarge",
		"StatusRequestURITooLong", "StatusUnsupportedMediaType",
		"StatusRequestedRangeNotSatisfiable", "StatusExpectationFailed",
		"StatusTeapot", "StatusMisdirectedRequest", "StatusUnprocessableEntity",
		"StatusLocked", "StatusFailedDependency", "StatusTooEarly",
		"StatusUpgradeRequired", "StatusPreconditionRequired",
		"StatusTooManyRequests", "StatusRequestHeaderFieldsTooLarge",
		"StatusUnavailableForLegalReasons",
		"StatusInternalServerError", "StatusNotImplemented",
		"StatusBadGateway", "StatusServiceUnavailable",
		"StatusGatewayTimeout", "StatusHTTPVersionNotSupported",
		"StatusVariantAlsoNegotiates", "StatusInsufficientStorage",
		"StatusLoopDetected", "StatusNotExtended",
		"StatusNetworkAuthenticationRequired":
		return true
	}
	return false
}

// ─── small AST helpers ───────────────────────────────────────────────────

func stringFirstArg(call *ast.CallExpr) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	return stringLiteral(call.Args[0])
}

// exprTypeText renders a type expression back to its source-level text as a
// lightweight fallback for spotting framework types when type info is
// unavailable for a parameter.
func exprTypeText(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprTypeText(t.X)
	case *ast.SelectorExpr:
		return exprTypeText(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprTypeText(t.Elt)
	}
	return ""
}
