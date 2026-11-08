package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

var nativeExtensions = map[string]string{
	".c":    "c-source",
	".cc":   "cxx-source",
	".cpp":  "cxx-source",
	".cxx":  "cxx-source",
	".h":    "c-header",
	".hpp":  "cxx-header",
	".hh":   "cxx-header",
	".m":    "objc-source",
	".mm":   "objcxx-source",
	".s":    "assembly",
	".S":    "assembly",
	".sx":   "assembly",
	".syso": "native-object",
}

var securityCatalog = map[string]struct {
	category       string
	severity       string
	description    string
	recommendation string
}{
	"unsafe.*":                   {"unsafe", "high", "Uses Go unsafe APIs that bypass type and memory safety.", "Review memory safety, pointer arithmetic, and data lifetime assumptions."},
	"reflect.*":                  {"reflection", "medium", "Uses reflection, which can obscure data flow and type guarantees.", "Review reflected calls and user-controlled values."},
	"syscall.*":                  {"syscall", "high", "Uses low-level syscall APIs.", "Prefer higher-level standard library APIs and review platform-specific behavior."},
	"plugin.*":                   {"dynamic-loading", "high", "Uses Go plugin dynamic loading.", "Review plugin provenance and loading paths."},
	"os/exec.*":                  {"process-execution", "high", "Uses process execution APIs.", "Avoid shell invocation and validate executable paths and arguments."},
	"os.Getenv":                  {"environment", "medium", "Reads process environment variables.", "Avoid copying raw environment values into logs or artifacts."},
	"os.LookupEnv":               {"environment", "medium", "Reads process environment variables.", "Avoid copying raw environment values into logs or artifacts."},
	"os.Setenv":                  {"environment", "medium", "Modifies process environment variables.", "Review environment mutation side effects."},
	"net/http.ListenAndServe":    {"http-server", "medium", "Starts an HTTP server without TLS at this call site.", "Use TLS or document trusted network boundaries."},
	"net/http.ListenAndServeTLS": {"http-server", "info", "Starts an HTTPS server.", "Review TLS certificate/key handling."},
	"net/http.Get":               {"http-client", "medium", "Uses package-level HTTP client defaults.", "Prefer configured clients with timeouts and transport policy."},
	"net/http.Post":              {"http-client", "medium", "Uses package-level HTTP client defaults.", "Prefer configured clients with timeouts and transport policy."},
	"net/http.DefaultClient":     {"http-client", "medium", "References the default HTTP client.", "Prefer configured clients with explicit timeouts."},
	"crypto/md5.*":               {"weak-crypto", "high", "Uses MD5 cryptographic primitives.", "Use SHA-256 or stronger algorithms unless this is non-security checksum logic."},
	"crypto/sha1.*":              {"weak-crypto", "high", "Uses SHA-1 cryptographic primitives.", "Use SHA-256 or stronger algorithms unless required for compatibility."},
	"math/rand.*":                {"weak-randomness", "high", "Uses math/rand pseudo-randomness.", "Use crypto/rand for security-sensitive randomness."},
	"crypto/tls.*":               {"tls", "medium", "Uses TLS configuration or APIs.", "Review TLS versions, certificate validation, and cipher policy."},
	"encoding/gob.*":             {"deserialization", "medium", "Uses gob serialization/deserialization APIs.", "Do not decode untrusted data without protocol controls."},
	"encoding/json.Unmarshal":    {"deserialization", "info", "Unmarshals JSON data.", "Validate schemas and limits for untrusted inputs."},
	"archive/zip.*":              {"archive", "medium", "Uses ZIP archive APIs.", "Review zip-slip/path traversal protections during extraction."},
	"archive/tar.*":              {"archive", "medium", "Uses TAR archive APIs.", "Review path traversal protections during extraction."},
	"database/sql.Open":          {"database", "medium", "Opens a database connection.", "Review DSN construction and credential handling."},
	"html/template.*":            {"template", "info", "Uses HTML templating APIs.", "Prefer html/template over text/template for HTML output."},
	"text/template.*":            {"template", "medium", "Uses text templating APIs.", "Avoid rendering untrusted templates or unsafe output contexts."},
	"path/filepath.Join":         {"filesystem", "info", "Joins filesystem paths.", "Review user-controlled path segments and traversal protections."},
	"os.OpenFile":                {"filesystem", "medium", "Opens files with explicit flags/permissions.", "Review permissions and path control."},
	"os.WriteFile":               {"filesystem", "medium", "Writes files.", "Review permissions and path control."},
}

func (a *Analyzer) buildDirectivesForFile(file *ast.File) []model.BuildDirective {
	var directives []model.BuildDirective
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for _, text := range normalizedCommentLines(comment.Text) {
				if strings.HasPrefix(text, "go:build") {
					directives = append(directives, model.BuildDirective{Kind: "go-build", Text: strings.TrimSpace(strings.TrimPrefix(text, "go:build")), Range: a.commentRange(comment)})
				} else if strings.HasPrefix(text, "+build") {
					directives = append(directives, model.BuildDirective{Kind: "legacy-build", Text: strings.TrimSpace(strings.TrimPrefix(text, "+build")), Range: a.commentRange(comment)})
				} else if strings.HasPrefix(text, "go:generate") {
					rest := strings.TrimSpace(strings.TrimPrefix(text, "go:generate"))
					parts := strings.Fields(rest)
					d := model.BuildDirective{Kind: "go-generate", Text: rest, Range: a.commentRange(comment)}
					if len(parts) > 0 {
						d.Command = filepath.Base(parts[0])
						d.Arguments = classifyArgs(parts[1:])
					}
					directives = append(directives, d)
				} else if strings.HasPrefix(text, "go:embed") {
					patterns := strings.Fields(strings.TrimSpace(strings.TrimPrefix(text, "go:embed")))
					directives = append(directives, model.BuildDirective{Kind: "go-embed", Text: strings.Join(patterns, " "), Patterns: patterns, Target: embedTarget(file, comment.Pos()), Range: a.commentRange(comment), Properties: embedProperties(patterns)})
				} else if strings.HasPrefix(text, "go:linkname") {
					directives = append(directives, model.BuildDirective{Kind: "go-linkname", Text: strings.TrimSpace(strings.TrimPrefix(text, "go:linkname")), Range: a.commentRange(comment), Properties: map[string]string{"risk": "links to unexported or external symbol"}})
				} else if strings.HasPrefix(text, "go:nosplit") {
					directives = append(directives, model.BuildDirective{Kind: "go-nosplit", Range: a.commentRange(comment), Properties: map[string]string{"risk": "stack growth checks disabled for function"}})
				} else if strings.HasPrefix(text, "#cgo") {
					directives = append(directives, cgoDirective(text, a.commentRange(comment)))
				}
			}
		}
	}
	return directives
}

func normalizedCommentLines(raw string) []string {
	if strings.HasPrefix(raw, "//") {
		return []string{strings.TrimSpace(strings.TrimPrefix(raw, "//"))}
	}
	raw = strings.TrimPrefix(raw, "/*")
	raw = strings.TrimSuffix(raw, "*/")
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*"))
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func (a *Analyzer) securitySignalsForFile(pkg *packages.Package, file *ast.File) []model.SecuritySignal {
	var signals []model.SecuritySignal
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, "\"")
		if path == "C" {
			signals = append(signals, a.signal(pkg, "native-interop", "high", "C", "Uses cgo import C.", "Review native build flags, linked libraries, and C memory safety.", spec, nil))
		} else if path == "unsafe" || path == "plugin" || path == "syscall" {
			signals = append(signals, a.signal(pkg, securityCatalog[path+".*"].category, securityCatalog[path+".*"].severity, path, securityCatalog[path+".*"].description, securityCatalog[path+".*"].recommendation, spec, nil))
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if sig, ok := a.signalForSelector(pkg, x); ok {
				signals = append(signals, sig)
			}
			if ident, ok := x.X.(*ast.Ident); ok && ident.Name == "C" {
				signals = append(signals, a.signal(pkg, "native-symbol", "high", "C."+x.Sel.Name, "References a C symbol through cgo.", "Review C symbol provenance and memory-safety boundaries.", x, nil))
			}
		case *ast.KeyValueExpr:
			if ident, ok := x.Key.(*ast.Ident); ok && ident.Name == "InsecureSkipVerify" {
				if lit, ok := x.Value.(*ast.Ident); ok && lit.Name == "true" {
					signals = append(signals, a.signal(pkg, "tls-insecure", "critical", "tls.Config.InsecureSkipVerify", "Disables TLS certificate verification.", "Do not set InsecureSkipVerify except in tightly controlled test code.", x, map[string]string{"value": "true"}))
				}
			}
		}
		return true
	})
	signals = append(signals, a.trustedProxySignalsForFile(pkg, file)...)
	return dedupeSignals(signals)
}

func (a *Analyzer) signalForSelector(pkg *packages.Package, sel *ast.SelectorExpr) (model.SecuritySignal, bool) {
	obj := pkg.TypesInfo.Uses[sel.Sel]
	if obj == nil || obj.Pkg() == nil {
		return model.SecuritySignal{}, false
	}
	symbol := obj.Pkg().Path() + "." + obj.Name()
	for pattern, meta := range securityCatalog {
		if matchSecurityPattern(pattern, symbol) {
			return a.signal(pkg, meta.category, meta.severity, symbol, meta.description, meta.recommendation, sel, nil), true
		}
	}
	return model.SecuritySignal{}, false
}

func (a *Analyzer) signal(pkg *packages.Package, category string, severity string, symbol string, description string, recommendation string, node ast.Node, props map[string]string) model.SecuritySignal {
	r := a.nodeRange(node)
	return model.SecuritySignal{ID: stableID(pkg.ID, category, symbol, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column)), Category: category, Severity: severity, Confidence: "type-resolved", UsageScope: fileRole(r.Start.Filename), PackagePath: pkg.PkgPath, Symbol: symbol, Description: description, Recommendation: recommendation, Range: r, Properties: props}
}

// trustedProxySelectors maps the framework's own symbols that turn on
// forwarded-header handling to the signal's framework and headers properties.
// Every key is a fully resolved package path plus symbol name, so the same
// name on an unrelated receiver or in the analysed module's own code cannot
// match: the lookup goes through pkg.TypesInfo, which knows where the symbol
// was declared.
var trustedProxySelectors = map[string]struct {
	framework string
	headers   string // forwarded, x-forwarded or all; empty when no literal names it
}{
	// middleware/realip.go rewrites RemoteAddr from X-Forwarded-For, X-Real-IP
	// and True-Client-IP.
	"github.com/go-chi/chi/v5/middleware.RealIP": {"chi", "x-forwarded"},
	// proxy_headers.go rewrites RemoteAddr, URL.Scheme and Host from
	// X-Forwarded-*, X-Real-IP and the RFC 7239 Forwarded header.
	"github.com/gorilla/handlers.ProxyHeaders": {"gorilla", "all"},
	// SetTrustedProxies gates which proxies gin believes; the header list
	// lives in Engine.RemoteIPHeaders, so no family is named here.
	"github.com/gin-gonic/gin.SetTrustedProxies": {"gin", ""},
	// The two IPExtractors echo's IPExtractor field takes; X-Real-IP is the
	// single-value spelling of the de-facto X-Forwarded family.
	"github.com/labstack/echo/v4.ExtractIPFromXFFHeader":    {"echo", "x-forwarded"},
	"github.com/labstack/echo/v4.ExtractIPFromRealIPHeader": {"echo", "x-forwarded"},
}

// trustedProxyFields maps a struct field of a framework's own config type to
// how its value turns forwarded-header handling on. The key is the field's
// declaring package path plus the field name, resolved through TypesInfo, so a
// same-named field on an application struct never matches.
// trustedProxyFields maps a struct field of a framework's own config type to
// how its value turns forwarded-header handling on. The key is the field's
// declaring package path plus the field name, resolved through TypesInfo, so a
// same-named field on an application struct never matches. A field counts
// whether it is set in a composite literal (fiber.Config{ProxyHeader: ...}) or
// assigned (r.ForwardedByClientIP = true), which is how gin's Engine fields
// are set in practice.
//
// fiber's EnableTrustedProxyCheck is left out on purpose: with it off (the
// default) fiber trusts every peer's X-Forwarded-Host and X-Forwarded-Proto,
// and turning it on narrows that trust to Config.TrustedProxies
// (ctx.go IsProxyTrusted), so it never turns forwarded-header handling on.
var trustedProxyFields = map[string]trustedProxyFieldRule{
	"github.com/gin-gonic/gin.ForwardedByClientIP": {framework: "gin", kind: ruleBoolOn},
	"github.com/gin-gonic/gin.RemoteIPHeaders":     {framework: "gin", kind: ruleHeaderList},
	"github.com/gofiber/fiber/v2.ProxyHeader":      {framework: "fiber", kind: ruleHeaderLiteral},
}

type trustedProxyRuleKind int

const (
	ruleBoolOn        trustedProxyRuleKind = iota // fires unless the value is a literal false
	ruleHeaderList                                // []string literal of header names
	ruleHeaderLiteral                             // single string literal naming the header
)

type trustedProxyFieldRule struct {
	framework string
	kind      trustedProxyRuleKind
}

const ginSetTrustedProxies = "github.com/gin-gonic/gin.SetTrustedProxies"

// trustedProxySignalsForFile reports where the code turns on forwarded-header
// handling. What static analysis can see is the switch, not the proxy: the
// signal records that the application resolves the client IP, host or scheme
// from headers a client could have sent, and whether a deployment is actually
// exposed depends on the proxy in front, which no source scan can see.
func (a *Analyzer) trustedProxySignalsForFile(pkg *packages.Package, file *ast.File) []model.SecuritySignal {
	var signals []model.SecuritySignal
	emit := func(node ast.Node, symbol string, framework, headers string) {
		props := map[string]string{"framework": framework}
		if headers != "" {
			props["headers"] = headers
		}
		signals = append(signals, a.signal(pkg, "trusted-proxy-config", "info", symbol,
			"Turns on forwarded-header handling for "+framework+", so the client IP, host or scheme the application sees can be chosen by the client.",
			"Ensure the proxy in front strips or overwrites Forwarded and X-Forwarded-* headers the client sends.",
			node, props))
	}
	resolve := func(id *ast.Ident) string {
		obj := pkg.TypesInfo.Uses[id]
		if obj == nil || obj.Pkg() == nil {
			return ""
		}
		return obj.Pkg().Path() + "." + obj.Name()
	}
	field := func(node ast.Node, key *ast.Ident, value ast.Expr) {
		symbol := resolve(key)
		rule, ok := trustedProxyFields[symbol]
		if !ok {
			return
		}
		switch rule.kind {
		case ruleBoolOn:
			// A literal false turns the behaviour off; anything else may
			// turn it on, and a variable is reported rather than guessed at.
			if lit, ok := value.(*ast.Ident); ok && lit.Name == "false" {
				return
			}
			emit(node, symbol, rule.framework, "")
		case ruleHeaderLiteral:
			lit, ok := value.(*ast.BasicLit)
			if !ok {
				return
			}
			if name, _ := strconv.Unquote(lit.Value); name != "" {
				emit(node, symbol, rule.framework, forwardedHeaderFamily(name))
			}
		case ruleHeaderList:
			emit(node, symbol, rule.framework, headerFamilyUnion(value))
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			// SetTrustedProxies(nil) or an empty list turns trust off, so
			// the call is judged with its argument rather than as a bare
			// selector. A non-literal argument may be anything, and the
			// signal errs on reporting it.
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || resolve(sel.Sel) != ginSetTrustedProxies {
				return true
			}
			if !ginTrustsNothing(x) {
				emit(sel, ginSetTrustedProxies, "gin", "")
			}
			return true
		case *ast.SelectorExpr:
			symbol := resolve(x.Sel)
			if symbol == ginSetTrustedProxies {
				return true
			}
			if meta, ok := trustedProxySelectors[symbol]; ok {
				emit(x, symbol, meta.framework, meta.headers)
			}
		case *ast.KeyValueExpr:
			if key, ok := x.Key.(*ast.Ident); ok {
				field(x, key, x.Value)
			}
		case *ast.AssignStmt:
			if len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					field(x, sel.Sel, x.Rhs[i])
				}
			}
		}
		return true
	})
	return signals
}

// ginTrustsNothing reports whether a SetTrustedProxies call is passed an
// explicitly empty trusted list: nil or an empty composite literal. Such a
// call disables forwarded-header trust rather than enabling it.
func ginTrustsNothing(call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	switch arg := call.Args[0].(type) {
	case *ast.Ident:
		return arg.Name == "nil"
	case *ast.CompositeLit:
		return len(arg.Elts) == 0
	}
	return false
}

// forwardedHeaderFamily maps one header name to the family the signal's
// headers property uses: forwarded for the RFC 7239 header, x-forwarded for
// the de-facto family including its single-value spellings.
func forwardedHeaderFamily(name string) string {
	switch strings.ToLower(name) {
	case "forwarded":
		return "forwarded"
	case "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-real-ip", "client-ip":
		return "x-forwarded"
	}
	return ""
}

// headerFamilyUnion resolves a []string literal of header names to one family
// value: forwarded when only the RFC 7239 header appears, x-forwarded for the
// de-facto family, all when both do. A non-literal list names no header, and
// the signal then carries no headers property rather than a guess.
func headerFamilyUnion(expr ast.Expr) string {
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	forwarded, xForwarded := false, false
	for _, elt := range lit.Elts {
		basic, ok := elt.(*ast.BasicLit)
		if !ok {
			continue
		}
		name, _ := strconv.Unquote(basic.Value)
		switch forwardedHeaderFamily(name) {
		case "forwarded":
			forwarded = true
		case "x-forwarded":
			xForwarded = true
		}
	}
	if forwarded && xForwarded {
		return "all"
	}
	if forwarded {
		return "forwarded"
	}
	if xForwarded {
		return "x-forwarded"
	}
	return ""
}

func nativeArtifactsForPackage(pkg *packages.Package) []model.NativeArtifact {
	dirs := map[string]bool{}
	for _, file := range append(append([]string{}, pkg.GoFiles...), pkg.CompiledGoFiles...) {
		if file != "" {
			dirs[filepath.Dir(file)] = true
		}
	}
	var artifacts []model.NativeArtifact
	seen := map[string]bool{}
	for dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			ext := filepath.Ext(entry.Name())
			kind, ok := nativeExtensions[ext]
			if !ok || seen[path] {
				continue
			}
			seen[path] = true
			artifacts = append(artifacts, model.NativeArtifact{Path: path, Kind: kind, Extension: ext, PackageID: pkg.ID})
		}
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return artifacts
}

func (a *Analyzer) commentRange(comment *ast.Comment) model.Range {
	start := a.position(comment.Pos())
	end := a.position(comment.End())
	return model.Range{Start: start, End: end}
}

func cgoDirective(text string, r model.Range) model.BuildDirective {
	fields := strings.Fields(text)
	d := model.BuildDirective{Kind: "cgo", Text: text, Range: r, Properties: map[string]string{}}
	for _, field := range fields[1:] {
		if strings.Contains(field, ":") {
			parts := strings.SplitN(field, ":", 2)
			d.Properties[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return d
}

func embedTarget(file *ast.File, pos token.Pos) string {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Pos() < pos {
			continue
		}
		for _, spec := range gen.Specs {
			if value, ok := spec.(*ast.ValueSpec); ok && len(value.Names) > 0 {
				return value.Names[0].Name
			}
		}
	}
	return ""
}

func embedProperties(patterns []string) map[string]string {
	props := map[string]string{}
	for _, pattern := range patterns {
		lower := strings.ToLower(pattern)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "credential") || strings.Contains(lower, "password") {
			props["credentialIndicator"] = "true"
		}
		if strings.Contains(lower, ".pem") || strings.Contains(lower, ".key") || strings.Contains(lower, ".crt") || strings.Contains(lower, ".p12") {
			props["cryptoMaterialIndicator"] = "true"
		}
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

func classifyArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.Contains(arg, "=") || strings.HasPrefix(arg, "-") {
			out = append(out, "option")
		} else {
			out = append(out, filepath.Base(arg))
		}
	}
	return out
}

func matchSecurityPattern(pattern string, symbol string) bool {
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(symbol, strings.TrimSuffix(pattern, "*"))
	}
	return symbol == pattern
}

func dedupeSignals(signals []model.SecuritySignal) []model.SecuritySignal {
	seen := map[string]bool{}
	out := make([]model.SecuritySignal, 0, len(signals))
	for _, sig := range signals {
		if seen[sig.ID] {
			continue
		}
		seen[sig.ID] = true
		out = append(out, sig)
	}
	return out
}
