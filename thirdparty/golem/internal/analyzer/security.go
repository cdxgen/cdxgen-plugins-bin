package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
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
