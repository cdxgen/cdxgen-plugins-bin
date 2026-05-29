package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

var literalURLPattern = regexp.MustCompile(`(?i)\b(?:https?|grpc|grpcs|ws|wss)://[^\s"'<>` + "`" + `]+`)

var httpMethodNames = map[string]string{
	"GET": "GET", "POST": "POST", "PUT": "PUT", "PATCH": "PATCH", "DELETE": "DELETE", "HEAD": "HEAD", "OPTIONS": "OPTIONS",
	"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Head": "HEAD", "Options": "OPTIONS",
	"Handle": "", "HandleFunc": "", "Any": "ANY", "All": "ANY", "Use": "MIDDLEWARE",
}

type endpointFacts struct {
	endpoints []model.APIEndpoint
	urls      []model.ExternalURL
}

func (a *Analyzer) endpointFactsForPackage(pkg *packages.Package) endpointFacts {
	var facts endpointFacts
	for _, file := range pkg.Syntax {
		if file == nil {
			continue
		}
		fileFacts := a.endpointFactsForFile(pkg, file)
		facts.endpoints = append(facts.endpoints, fileFacts.endpoints...)
		facts.urls = append(facts.urls, fileFacts.urls...)
	}
	facts.endpoints = dedupeEndpoints(facts.endpoints)
	facts.urls = dedupeExternalURLs(facts.urls)
	return facts
}

func (a *Analyzer) endpointFactsForFile(pkg *packages.Package, file *ast.File) endpointFacts {
	facts := endpointFacts{}
	prefixByIdent := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			a.recordRouteGroups(x, prefixByIdent)
		case *ast.ValueSpec:
			a.recordRouteGroupValues(x, prefixByIdent)
		case *ast.CallExpr:
			if ep, ok := a.endpointForCall(pkg, x, prefixByIdent); ok {
				facts.endpoints = append(facts.endpoints, ep)
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				facts.urls = append(facts.urls, a.urlsForLiteral(pkg, x)...)
			}
		}
		return true
	})
	return facts
}

func (a *Analyzer) recordRouteGroups(stmt *ast.AssignStmt, groups map[string]string) {
	for i, rhs := range stmt.Rhs {
		call, ok := rhs.(*ast.CallExpr)
		if !ok || i >= len(stmt.Lhs) {
			continue
		}
		ident, ok := stmt.Lhs[i].(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		if prefix, ok := a.groupPrefixForCall(call, groups); ok {
			groups[ident.Name] = prefix
		}
	}
}

func (a *Analyzer) recordRouteGroupValues(spec *ast.ValueSpec, groups map[string]string) {
	for i, rhs := range spec.Values {
		call, ok := rhs.(*ast.CallExpr)
		if !ok || i >= len(spec.Names) || spec.Names[i] == nil {
			continue
		}
		if prefix, ok := a.groupPrefixForCall(call, groups); ok {
			groups[spec.Names[i].Name] = prefix
		}
	}
}

func (a *Analyzer) groupPrefixForCall(call *ast.CallExpr, groups map[string]string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Group" || len(call.Args) == 0 {
		return "", false
	}
	prefix, ok := stringLiteral(call.Args[0])
	if !ok {
		return "", false
	}
	base := ""
	if ident, ok := sel.X.(*ast.Ident); ok {
		base = groups[ident.Name]
	}
	return joinRoutePath(base, prefix), true
}

func (a *Analyzer) endpointForCall(pkg *packages.Package, call *ast.CallExpr, groups map[string]string) (model.APIEndpoint, bool) {
	name, receiver := callSelectorName(call)
	if name == "" {
		return model.APIEndpoint{}, false
	}
	symbol := a.endpointCallSymbol(pkg, call)
	framework := endpointFramework(symbol, name)
	method := ""
	pathArg := 0
	handlerArg := 1
	kind := "http-route"
	path := ""
	props := map[string]string{}

	switch {
	case strings.Contains(symbol, "net/http.HandleFunc") || strings.Contains(symbol, "net/http.Handle") || name == "HandleFunc" || name == "Handle":
		method = ""
		pathArg = 0
		handlerArg = 1
		framework = firstNonEmpty(framework, "net/http")
	case strings.Contains(symbol, "ListenAndServe") || name == "ListenAndServe" || name == "ListenAndServeTLS":
		kind = "http-listener"
		framework = firstNonEmpty(framework, "net/http")
		if len(call.Args) > 0 {
			path, _ = stringLiteral(call.Args[0])
		}
		method = ""
		handlerArg = 1
		props["listener"] = "true"
		if name == "ListenAndServeTLS" {
			props["tls"] = "true"
		}
	case strings.Contains(symbol, "Register") && strings.Contains(symbol, "Server"):
		kind = "rpc-service"
		framework = firstNonEmpty(framework, "grpc")
		path = name
		method = "RPC"
		pathArg = -1
		handlerArg = 1
	case strings.Contains(symbol, "grpc-gateway") && strings.Contains(name, "Register"):
		kind = "http-route"
		framework = firstNonEmpty(framework, "grpc-gateway")
		method = "ANY"
		path = name
		pathArg = -1
		handlerArg = 0
		if len(call.Args) > 0 {
			handlerArg = len(call.Args) - 1
		}
	case framework == "connectrpc" && strings.Contains(strings.ToLower(name), "handler"):
		kind = "rpc-service"
		framework = "connectrpc"
		path = name
		method = "RPC"
		pathArg = -1
		handlerArg = 0
		if len(call.Args) > 0 {
			handlerArg = len(call.Args) - 1
		}
	case framework == "fasthttp" && (strings.Contains(symbol, "ListenAndServe") || name == "ListenAndServeTLS"):
		kind = "http-listener"
		framework = "fasthttp"
		if len(call.Args) > 0 {
			path, _ = stringLiteral(call.Args[0])
		}
		method = ""
		handlerArg = 1
		props["listener"] = "true"
	case isFrameworkRouteName(name):
		if (framework == "" || framework == "net/http") && isTitleCaseHTTPMethod(name) {
			return model.APIEndpoint{}, false
		}
		method = httpMethodNames[name]
		if method == "" {
			method = strings.ToUpper(name)
		}
		pathArg = 0
		handlerArg = 1
	default:
		return model.APIEndpoint{}, false
	}

	if path == "" && pathArg >= 0 && len(call.Args) > pathArg {
		path, _ = stringLiteral(call.Args[pathArg])
	}
	if path == "" && kind != "http-listener" && kind != "rpc-service" {
		return model.APIEndpoint{}, false
	}
	if receiver != "" {
		path = joinRoutePath(groups[receiver], path)
	}
	handler := ""
	if len(call.Args) > handlerArg {
		handler = exprEndpointName(call.Args[handlerArg])
	}
	r := a.nodeRange(call)
	scheme, host, cleanPath, cleanURL := endpointAddressParts(kind, path)
	if cleanPath != "" {
		path = cleanPath
	}
	return model.APIEndpoint{ID: stableID(pkg.ID, "endpoint", kind, method, path, handler, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column)), Kind: kind, Framework: framework, Method: method, Path: path, Host: host, Scheme: scheme, URL: cleanURL, Handler: handler, PackagePath: pkg.PkgPath, UsageScope: fileRole(r.Start.Filename), Range: r, Properties: cleanProperties(props)}, true
}

func isTitleCaseHTTPMethod(name string) bool {
	switch name {
	case "Get", "Post", "Put", "Patch", "Delete", "Head", "Options":
		return true
	default:
		return false
	}
}

func callSelectorName(call *ast.CallExpr) (string, string) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		receiver := ""
		if ident, ok := fun.X.(*ast.Ident); ok {
			receiver = ident.Name
		}
		return fun.Sel.Name, receiver
	case *ast.Ident:
		return fun.Name, ""
	default:
		return "", ""
	}
}

func (a *Analyzer) endpointCallSymbol(pkg *packages.Package, call *ast.CallExpr) string {
	if pkg == nil || pkg.TypesInfo == nil || call == nil {
		return ""
	}
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if obj := pkg.TypesInfo.Uses[fun.Sel]; obj != nil {
			return objectSymbolName(obj)
		}
	case *ast.Ident:
		if obj := pkg.TypesInfo.Uses[fun]; obj != nil {
			return objectSymbolName(obj)
		}
	}
	return ""
}

func objectSymbolName(obj types.Object) string {
	if obj == nil {
		return ""
	}
	if obj.Pkg() != nil {
		return obj.Pkg().Path() + "." + obj.Name()
	}
	return obj.Name()
}

func endpointFramework(symbol string, name string) string {
	lower := strings.ToLower(symbol + " " + name)
	switch {
	case strings.Contains(lower, "github.com/gin-gonic/gin"):
		return "gin"
	case strings.Contains(lower, "github.com/go-chi/chi"):
		return "chi"
	case strings.Contains(lower, "github.com/gorilla/mux"):
		return "gorilla/mux"
	case strings.Contains(lower, "github.com/labstack/echo"):
		return "echo"
	case strings.Contains(lower, "github.com/gofiber/fiber"):
		return "fiber"
	case strings.Contains(lower, "github.com/grpc-ecosystem/grpc-gateway"):
		return "grpc-gateway"
	case strings.Contains(lower, "connectrpc.com/connect"):
		return "connectrpc"
	case strings.Contains(lower, "github.com/valyala/fasthttp"):
		return "fasthttp"
	case strings.Contains(lower, "github.com/kataras/iris"):
		return "iris"
	case strings.Contains(lower, "github.com/beego/beego"):
		return "beego"
	case strings.Contains(lower, "github.com/gobuffalo/buffalo"):
		return "buffalo"
	case strings.Contains(lower, "github.com/99designs/gqlgen") || strings.Contains(lower, "graphql"):
		return "graphql"
	case strings.Contains(lower, "google.golang.org/grpc") || strings.Contains(name, "Register"):
		return "grpc"
	case strings.Contains(lower, "net/http"):
		return "net/http"
	default:
		return ""
	}
}

func isFrameworkRouteName(name string) bool {
	if _, ok := httpMethodNames[name]; ok {
		return true
	}
	upper := strings.ToUpper(name)
	_, ok := httpMethodNames[upper]
	return ok || name == "HandleFunc" || name == "Handle" || name == "Methods" || name == "Path" || name == "PathPrefix" || name == "Router" || name == "Party"
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconvUnquote(lit.Value)
	return v, err == nil
}

func strconvUnquote(s string) (string, error) {
	if unquoted, err := strconv.Unquote(s); err == nil {
		return unquoted, nil
	}
	return strings.Trim(s, "\"`"), nil
}

func exprEndpointName(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprString(x)
	case *ast.FuncLit:
		return "func literal"
	case *ast.CallExpr:
		for i := len(x.Args) - 1; i >= 0; i-- {
			argName := exprEndpointName(x.Args[i])
			if argName != "" && argName != "func literal" {
				return argName
			}
		}
		name, _ := callSelectorName(x)
		return name
	default:
		return exprString(expr)
	}
}

func joinRoutePath(base string, part string) string {
	if base == "" {
		if part == "" {
			return ""
		}
		if strings.HasPrefix(part, "/") || strings.Contains(part, "://") || strings.HasPrefix(part, ":") {
			return part
		}
		return "/" + part
	}
	if part == "" || part == "/" {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(part, "/")
}

func endpointAddressParts(kind string, raw string) (scheme string, host string, path string, cleanURL string) {
	if raw == "" {
		return "", "", "", ""
	}
	if strings.Contains(raw, "://") {
		u, ok := sanitizeURL(raw)
		if !ok {
			return "", "", raw, ""
		}
		parsed, _ := url.Parse(u)
		return parsed.Scheme, parsed.Host, parsed.Path, u
	}
	if kind == "http-listener" {
		return "http", strings.TrimSpace(raw), "", ""
	}
	return "", "", raw, ""
}

func (a *Analyzer) urlsForLiteral(pkg *packages.Package, lit *ast.BasicLit) []model.ExternalURL {
	value, ok := stringLiteral(lit)
	if !ok || value == "" {
		return nil
	}
	var out []model.ExternalURL
	for _, match := range literalURLPattern.FindAllString(value, -1) {
		clean, ok := sanitizeURL(match)
		if !ok {
			continue
		}
		parsed, err := url.Parse(clean)
		if err != nil || parsed.Host == "" {
			continue
		}
		r := a.nodeRange(lit)
		out = append(out, model.ExternalURL{ID: stableID(pkg.ID, "external-url", clean, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column)), URL: clean, Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path, PackagePath: pkg.PkgPath, UsageScope: fileRole(r.Start.Filename), Range: r})
	}
	return out
}

func sanitizeURL(raw string) (string, bool) {
	raw = strings.TrimRight(strings.TrimSpace(raw), `.,);]}`)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), true
}

func cleanProperties(props map[string]string) map[string]string {
	if len(props) == 0 {
		return nil
	}
	return props
}

func servicesFromEndpointFacts(endpoints []model.APIEndpoint, urls []model.ExternalURL) []model.ServiceEvidence {
	byKey := map[string]*model.ServiceEvidence{}
	for _, ep := range endpoints {
		name := firstNonEmpty(ep.Host, ep.Framework, "http-service")
		kind := "server"
		key := kind + "|" + ep.PackagePath + "|" + name
		service := byKey[key]
		if service == nil {
			service = &model.ServiceEvidence{ID: stableID("service", key), Name: name, Kind: kind, Host: ep.Host, Scheme: ep.Scheme, PackagePath: ep.PackagePath, Properties: map[string]string{"evidence": "api-endpoint"}}
			byKey[key] = service
		}
		service.Endpoints = append(service.Endpoints, model.ServiceEndpoint{EndpointID: ep.ID, Method: ep.Method, Path: ep.Path, URL: ep.URL, Properties: map[string]string{"framework": ep.Framework, "handler": ep.Handler}})
	}
	for _, external := range urls {
		name := external.Host
		kind := "external"
		key := kind + "|" + external.Scheme + "|" + name
		service := byKey[key]
		if service == nil {
			service = &model.ServiceEvidence{ID: stableID("service", key), Name: name, Kind: kind, Host: external.Host, Scheme: external.Scheme, PackagePath: external.PackagePath, Properties: map[string]string{"evidence": "external-url"}}
			byKey[key] = service
		}
		service.Endpoints = append(service.Endpoints, model.ServiceEndpoint{URL: external.URL, Path: external.Path})
	}
	services := make([]model.ServiceEvidence, 0, len(byKey))
	for _, service := range byKey {
		sort.Slice(service.Endpoints, func(i, j int) bool {
			return service.Endpoints[i].Method+service.Endpoints[i].Path+service.Endpoints[i].URL < service.Endpoints[j].Method+service.Endpoints[j].Path+service.Endpoints[j].URL
		})
		services = append(services, *service)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	return services
}

func dedupeEndpoints(in []model.APIEndpoint) []model.APIEndpoint {
	seen := map[string]bool{}
	out := make([]model.APIEndpoint, 0, len(in))
	for _, ep := range in {
		key := ep.Kind + "\x00" + ep.Framework + "\x00" + ep.Method + "\x00" + ep.Path + "\x00" + ep.Handler + "\x00" + ep.Range.Start.Filename + "\x00" + fmt.Sprint(ep.Range.Start.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ep)
	}
	return out
}

func dedupeExternalURLs(in []model.ExternalURL) []model.ExternalURL {
	seen := map[string]bool{}
	out := make([]model.ExternalURL, 0, len(in))
	for _, u := range in {
		key := u.URL + "\x00" + u.Range.Start.Filename + "\x00" + fmt.Sprint(u.Range.Start.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	return out
}
