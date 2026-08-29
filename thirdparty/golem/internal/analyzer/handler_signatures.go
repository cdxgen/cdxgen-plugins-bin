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
// against, in their canonical (major-version-stripped) spelling. Matching
// always goes through normalizeModulePath, so the versioned module paths
// real projects import — github.com/go-chi/chi/v5, github.com/labstack/echo/v4,
// github.com/gofiber/fiber/v2 — compare equal to these constants.
const (
	ginImportPath     = "github.com/gin-gonic/gin"
	chiImportPath     = "github.com/go-chi/chi"
	renderImportPath  = "github.com/go-chi/render"
	echoImportPath    = "github.com/labstack/echo"
	nethttpImportPath = "net/http"
	jsonImportPath    = "encoding/json"
)

// normalizeModulePath strips a trailing major-version segment (/v2 … /v999,
// per the Go module path spec) so versioned import paths compare equal to
// their unversioned spelling. Anything else — gopkg.in/yaml.v2,
// example.com/v2api — is returned unchanged.
func normalizeModulePath(path string) string {
	if idx := strings.LastIndex(path, "/v"); idx >= 0 {
		rest := path[idx+2:]
		if rest != "" && len(rest) <= 3 && isAllDigits(rest) {
			return path[:idx]
		}
	}
	return path
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// handlerSignatureExtractor walks HTTP-handler bodies and lifts
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
// Handlers may be named functions, method expressions (`svc.Ping`), or
// inline func literals at the registration site.
//
// Known limitations, all deliberate: a short name declared more than once
// in the registering package (methods on different receiver types, or a
// method and a free function) is left unenriched, because the handler
// string does not carry the receiver and enriching from the wrong body
// would yield confidently wrong schemas; handlers defined in a different
// package than the one that registered the route contribute no enrichment;
// calls routed through package-level helper functions are not followed;
// response emitters behind unrecognized wrappers are missed; generic named
// types surface as their bare name (List[T] → "List"). Extraction is
// best-effort — a wrong parameter type is worse than a missing one, since
// downstream tools will happily generate the wrong schema.
type handlerSignatureExtractor struct {
	pkg      *packages.Package
	handlers map[string]*ast.FuncDecl
	// literals maps an endpoint's registration-site position to an inline
	// handler closure, covering the dominant `r.GET("/x", func(c
	// *gin.Context) {...})` idiom that never resolves to a named function.
	literals map[string]*ast.FuncLit
}

func newHandlerSignatureExtractor(pkg *packages.Package, literals map[string]*ast.FuncLit) *handlerSignatureExtractor {
	e := &handlerSignatureExtractor{pkg: pkg, handlers: map[string]*ast.FuncDecl{}, literals: literals}
	if pkg == nil {
		return e
	}
	// Index handler-shaped function declarations by their short name so we
	// can resolve endpoint.handler back to a *ast.FuncDecl without
	// re-walking the AST per endpoint. Endpoint handlers only carry the
	// short name (method expressions surface as "svc.Ping"), so the
	// short-name key is the join column that matches.
	//
	// A short name declared more than once in the package — methods on
	// different receiver types, or a method and a free function sharing a
	// name — is deliberately left unindexed: the handler string does not
	// carry the receiver, so resolving it would be a guess, and enriching
	// from the wrong body yields confidently wrong schemas.
	counts := map[string]int{}
	for _, file := range pkg.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			counts[fn.Name.Name]++
		}
	}
	for _, file := range pkg.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			if counts[fn.Name.Name] > 1 {
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
// ResponseType by walking the handler's body. The body comes from either
// the inline func literal at the registration site or, for named and
// method-expression handlers, the package-wide short-name index. Called
// once per endpoint after endpointForCall has done the framework/method/
// path work.
func (e *handlerSignatureExtractor) enrich(endpoint *model.APIEndpoint) {
	if endpoint == nil || endpoint.Kind != "http-route" || e.pkg == nil || e.pkg.TypesInfo == nil {
		return
	}
	// Resolve the handler body: an inline func literal at the registration
	// site wins; otherwise fall back to the short-name index for named and
	// method-expression handlers.
	var (
		body   ast.Node
		params *ast.FieldList
	)
	if lit, ok := e.literals[endpointPositionKey(endpoint.Range)]; ok && lit != nil {
		body, params = lit.Body, lit.Type.Params
	} else if endpoint.Handler != "" {
		if fn := e.handlers[handlerShortName(endpoint.Handler)]; fn != nil && fn.Body != nil {
			body, params = fn.Body, fn.Type.Params
		}
	}
	if body == nil {
		return
	}
	roles := e.rolesForParams(params, endpoint.Framework)
	if roles.empty() {
		return
	}
	sig := &endpointSignature{seenPath: map[string]bool{}, seenQuery: map[string]bool{}}
	ast.Inspect(body, func(n ast.Node) bool {
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

// endpointPositionKey identifies a registration call site by source
// position, joining endpoints collected during route detection to the
// inline handler literal written at that site.
func endpointPositionKey(r model.Range) string {
	return r.Start.Filename + ":" + strconv.Itoa(r.Start.Line) + ":" + strconv.Itoa(r.Start.Column)
}

// rolesForParams classifies a handler's parameter list by resolved type:
// the framework context objects for gin/echo, and *http.Request /
// http.ResponseWriter for chi and net/http handlers. Falls back to source
// text when the type checker has no entry for the parameter.
func (e *handlerSignatureExtractor) rolesForParams(params *ast.FieldList, framework string) handlerRoles {
	roles := handlerRoles{ctx: map[string]bool{}, request: map[string]bool{}, response: map[string]bool{}}
	if params == nil {
		return roles
	}
	for _, field := range params.List {
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
	path := normalizeModulePath(named.Obj().Pkg().Path())
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
func (e *handlerSignatureExtractor) paramNameAt(call *ast.CallExpr, allowed map[string]bool, receiverArg, nameArg int) (string, bool) {
	if nameArg >= len(call.Args) || receiverArg >= len(call.Args) {
		return "", false
	}
	ident, ok := call.Args[receiverArg].(*ast.Ident)
	if !ok || !allowed[ident.Name] {
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
// the imported package's path, so `chi.URLParam` and `c "github.com/go-chi/chi/v5"`
// aliased references both resolve to the framework's canonical path.
func (e *handlerSignatureExtractor) packageSelector(sel *ast.SelectorExpr) (string, string) {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", ""
	}
	if obj, ok := e.pkg.TypesInfo.Uses[ident].(*types.PkgName); ok && obj.Imported() != nil {
		return normalizeModulePath(obj.Imported().Path()), sel.Sel.Name
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
// package path and type name, with paths in normalized (major-version-
// stripped) spelling. They carry no schema beyond "object" — they are
// map[string]any under a friendlier name — and matching on the package
// path (not the identifier spelled at the callsite) keeps a user's own
// type named H or Map from collapsing.
var freeFormObjectTypePaths = map[string]bool{
	"github.com/gin-gonic/gin.H":   true,
	"github.com/labstack/echo.Map": true,
	"github.com/gofiber/fiber.Map": true,
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
		if obj.Pkg() != nil && freeFormObjectTypePaths[normalizeModulePath(obj.Pkg().Path())+"."+obj.Name()] {
			return "object"
		}
		// Generic instantiations (List[T]) surface as their bare name; the
		// type arguments' shapes are not inspected.
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
// a 4xx or 5xx code: integer literals, or any integer constant the type
// checker resolved — which covers every named net/http status constant and
// framework status wrappers. Anything else (a computed variable, an unknown
// name) is treated as a successful response, the safe default.
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
