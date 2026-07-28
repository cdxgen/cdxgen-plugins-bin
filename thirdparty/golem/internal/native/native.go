// Package native identifies the boundary between Go and code the Go toolchain
// does not compile: C reached through cgo, symbols aliased with //go:linkname,
// and files a build configuration silently excluded.
//
// Everything here is derived from source and from what the loader reports. No
// C compiler is invoked and no analysed code is executed.
package native

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/build/constraint"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// Directions a boundary crossing can take.
const (
	DirectionGoToC = "go->c"
	DirectionCToGo = "c->go"
)

// cgoHelper describes one of the conversion functions cgo synthesises. These
// are not C functions the project links against — reporting `C.GoString` as an
// external C symbol named "GoString" would be wrong — so they are classified
// separately, and their direction is the direction data moves through them.
type cgoHelper struct {
	direction string
	role      string
}

var cgoHelpers = map[string]cgoHelper{
	"CString":   {DirectionGoToC, "go-string-to-c"},
	"CBytes":    {DirectionGoToC, "go-bytes-to-c"},
	"GoString":  {DirectionCToGo, "c-string-to-go"},
	"GoStringN": {DirectionCToGo, "c-string-to-go"},
	"GoBytes":   {DirectionCToGo, "c-bytes-to-go"},
	"malloc":    {DirectionGoToC, "c-allocate"},
	"calloc":    {DirectionGoToC, "c-allocate"},
	"free":      {DirectionGoToC, "c-free"},
}

// Analyzer extracts native boundary records from loaded packages and SSA.
type Analyzer struct {
	Fset          *token.FileSet
	Packages      []*packages.Package
	Program       *ssa.Program
	PackageByPath map[string]*packages.Package

	evidence map[string]*cgoPreamble
}

// NewAnalyzer creates a native-boundary analyzer.
func NewAnalyzer(fset *token.FileSet, pkgs []*packages.Package, prog *ssa.Program, packageByPath map[string]*packages.Package) *Analyzer {
	return &Analyzer{
		Fset:          fset,
		Packages:      pkgs,
		Program:       prog,
		PackageByPath: packageByPath,
		evidence:      map[string]*cgoPreamble{},
	}
}

// RecognizeBoundary returns one record per cgo crossing, in both directions.
func (a *Analyzer) RecognizeBoundary() []model.NativeCall {
	var calls []model.NativeCall
	seen := map[string]bool{}
	if a.Program != nil {
		for _, pkg := range a.Program.AllPackages() {
			if pkg == nil || pkg.Pkg == nil {
				continue
			}
			for _, member := range pkg.Members {
				fn, ok := member.(*ssa.Function)
				if !ok {
					continue
				}
				call := a.recognizeCgoWrapper(fn)
				if call == nil || seen[call.ID] {
					continue
				}
				seen[call.ID] = true
				calls = append(calls, *call)
			}
		}
	}
	for _, call := range a.recognizeExports() {
		if seen[call.ID] {
			continue
		}
		seen[call.ID] = true
		calls = append(calls, call)
	}
	sort.Slice(calls, func(i, j int) bool {
		if calls[i].GoSymbol != calls[j].GoSymbol {
			return calls[i].GoSymbol < calls[j].GoSymbol
		}
		return calls[i].ID < calls[j].ID
	})
	return calls
}

// recognizeCgoWrapper turns a cgo-generated wrapper into a boundary record.
func (a *Analyzer) recognizeCgoWrapper(fn *ssa.Function) *model.NativeCall {
	name := fn.Name()
	symbol, ok := trimCgoPrefix(name)
	if !ok || symbol == "" {
		return nil
	}
	pkgPath := ""
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkgPath = fn.Pkg.Pkg.Path()
	}
	preamble := a.preambleFor(pkgPath)

	call := model.NativeCall{
		ID:             stableID("native-call", fn.String()),
		GoSymbol:       name,
		Direction:      DirectionGoToC,
		Libraries:      preamble.libraries,
		Confidence:     "high",
		Evidence:       preamble.directives,
		PackagePath:    pkgPath,
		GoFunctionID:   fn.String(),
		GoFunctionName: fn.RelString(nil),
		ArgumentRoles:  argumentRoles(fn.Signature),
	}
	if helper, isHelper := cgoHelpers[symbol]; isHelper {
		// A conversion cgo generates for itself, not a symbol from the linked
		// library: it has no C declaration to point at.
		call.Direction = helper.direction
		call.Properties = map[string]string{"cgoHelper": symbol, "role": helper.role}
	} else {
		call.CSymbol = symbol
		call.HeaderFile = preamble.headerFor(symbol)
	}
	if pos := fn.Pos(); pos.IsValid() && a.Fset != nil {
		p := a.Fset.Position(pos)
		call.Position = model.Position{Filename: p.Filename, Offset: p.Offset, Line: p.Line, Column: p.Column}
	}
	return &call
}

// trimCgoPrefix recovers the C symbol from a cgo wrapper name, reporting
// whether the name was a wrapper at all.
func trimCgoPrefix(name string) (string, bool) {
	for _, prefix := range []string{"_cgo_Cfunc_", "_Cfunc_"} {
		if strings.HasPrefix(name, prefix) {
			return strings.TrimPrefix(name, prefix), true
		}
	}
	return "", false
}

// argumentRoles describes each parameter of a wrapper, so a consumer can see
// which argument carries data across rather than only how many there are.
func argumentRoles(sig *types.Signature) []model.NativeArgumentRole {
	if sig == nil {
		return nil
	}
	params := sig.Params()
	roles := make([]model.NativeArgumentRole, 0, params.Len())
	for i := 0; i < params.Len(); i++ {
		param := params.At(i)
		roles = append(roles, model.NativeArgumentRole{
			Index:    i,
			Role:     argumentRole(param.Type()),
			Type:     types.TypeString(param.Type(), nil),
			Variadic: sig.Variadic() && i == params.Len()-1,
		})
	}
	return roles
}

// argumentRole classifies a parameter type structurally. Matching on the
// rendered type string would confuse uint32 with int32 and *C.char with
// **C.char, and the roles exist precisely to tell pointers apart.
func argumentRole(t types.Type) string {
	switch typ := types.Unalias(t).Underlying().(type) {
	case *types.Basic:
		switch {
		case typ.Kind() == types.UnsafePointer:
			return "pointer"
		case typ.Info()&types.IsInteger != 0:
			return "integer"
		case typ.Info()&types.IsFloat != 0:
			return "float"
		case typ.Info()&types.IsString != 0:
			return "string"
		}
		return "value"
	case *types.Pointer:
		if elem, ok := types.Unalias(typ.Elem()).Underlying().(*types.Basic); ok && elem.Kind() == types.Int8 {
			return "c-string"
		}
		return "c-pointer"
	case *types.Slice:
		return "slice"
	case *types.Struct:
		return "struct"
	}
	return "value"
}

// recognizeExports finds Go functions callable from C.
//
// The directive must be in the declaration's own doc comment, which is what
// cgo itself requires; scanning a file for the last //export line and pairing
// it with whichever function shares the name would miss every file that
// exports more than one function.
func (a *Analyzer) recognizeExports() []model.NativeCall {
	var calls []model.NativeCall
	for _, pkg := range a.Packages {
		if pkg == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fnDecl, ok := decl.(*ast.FuncDecl)
				if !ok || fnDecl.Doc == nil {
					continue
				}
				name := exportedName(fnDecl.Doc)
				if name == "" {
					continue
				}
				call := model.NativeCall{
					ID:             stableID("native-export", pkg.PkgPath, name),
					GoSymbol:       fnDecl.Name.Name,
					CSymbol:        name,
					Direction:      DirectionCToGo,
					Confidence:     "high",
					Evidence:       []string{"//export " + name},
					PackagePath:    pkg.PkgPath,
					GoFunctionName: pkg.PkgPath + "." + fnDecl.Name.Name,
				}
				if a.Fset != nil {
					p := a.Fset.Position(fnDecl.Pos())
					call.Position = model.Position{Filename: p.Filename, Offset: p.Offset, Line: p.Line, Column: p.Column}
				}
				if sig, ok := signatureOf(pkg, fnDecl); ok {
					call.ArgumentRoles = argumentRoles(sig)
				}
				calls = append(calls, call)
			}
		}
	}
	return calls
}

func exportedName(doc *ast.CommentGroup) string {
	for _, comment := range doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
		if rest, found := strings.CutPrefix(text, "export "); found {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func signatureOf(pkg *packages.Package, decl *ast.FuncDecl) (*types.Signature, bool) {
	if pkg.TypesInfo == nil || decl.Name == nil {
		return nil, false
	}
	obj, ok := pkg.TypesInfo.Defs[decl.Name].(*types.Func)
	if !ok || obj == nil {
		return nil, false
	}
	sig, ok := obj.Type().(*types.Signature)
	return sig, ok
}

// cgoPreamble is the `#cgo` and `#include` evidence of one package, parsed once.
type cgoPreamble struct {
	directives []string
	libraries  []string
	headers    []string
}

// headerFor picks the header a C symbol most plausibly came from. With one
// include there is no ambiguity; with several there is, so say nothing rather
// than guess, since a wrong attribution is worse than a missing one.
func (p *cgoPreamble) headerFor(string) string {
	if len(p.headers) == 1 {
		return p.headers[0]
	}
	return ""
}

func (a *Analyzer) preambleFor(pkgPath string) *cgoPreamble {
	if cached, ok := a.evidence[pkgPath]; ok {
		return cached
	}
	parsed := &cgoPreamble{}
	if pkg := a.PackageByPath[pkgPath]; pkg != nil {
		for _, file := range pkg.Syntax {
			for _, group := range file.Comments {
				for _, comment := range group.List {
					parsed.absorb(commentText(comment.Text))
				}
			}
		}
		sort.Strings(parsed.libraries)
		parsed.libraries = dedupe(parsed.libraries)
		parsed.headers = dedupe(parsed.headers)
	}
	a.evidence[pkgPath] = parsed
	return parsed
}

// absorb reads one comment line of a cgo preamble.
func (p *cgoPreamble) absorb(text string) {
	switch {
	case strings.HasPrefix(text, "#cgo"):
		p.directives = append(p.directives, text)
		// The form is `#cgo [constraints] VAR: values...`, so the variable is
		// the field ending in a colon and everything after it is its value.
		fields := strings.Fields(strings.TrimPrefix(text, "#cgo"))
		for i, field := range fields {
			if field == "LDFLAGS:" {
				p.libraries = append(p.libraries, fields[i+1:]...)
				break
			}
		}
	case strings.HasPrefix(text, "#include"):
		include := strings.TrimSpace(strings.TrimPrefix(text, "#include"))
		include = strings.Trim(include, `"<>`)
		if include != "" {
			p.headers = append(p.headers, include)
		}
	}
}

// commentText strips the comment markers from a line of either comment form.
func commentText(raw string) string {
	text := strings.TrimPrefix(raw, "//")
	text = strings.TrimPrefix(text, "/*")
	text = strings.TrimSuffix(text, "*/")
	return strings.TrimSpace(text)
}

// Linkname is a resolved //go:linkname directive.
type Linkname struct {
	Local       string // symbol in this package
	LocalFunc   string // fully qualified local function, when it has a body
	Target      string // importpath.name the directive points at
	Pull        bool   // the local declaration has no body: calls land on Target
	PackagePath string
	Position    model.Position
}

// Linknames returns every //go:linkname directive in the loaded packages.
//
// The directive is invisible to the type checker and to SSA: a pull linkname
// gives a body-less declaration an implementation from another package, so
// without reading the pragma the call graph simply ends there.
func (a *Analyzer) Linknames() []Linkname {
	var out []Linkname
	for _, pkg := range a.Packages {
		if pkg == nil {
			continue
		}
		bodies := map[string]bool{}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil {
					bodies[fn.Name.Name] = fn.Body != nil
				}
			}
		}
		for _, file := range pkg.Syntax {
			for _, group := range file.Comments {
				for _, comment := range group.List {
					local, target, ok := parseLinkname(commentText(comment.Text))
					if !ok {
						continue
					}
					entry := Linkname{
						Local:       local,
						Target:      target,
						Pull:        !bodies[local],
						PackagePath: pkg.PkgPath,
					}
					if hasBody := bodies[local]; hasBody {
						entry.LocalFunc = pkg.PkgPath + "." + local
					}
					if a.Fset != nil {
						p := a.Fset.Position(comment.Pos())
						entry.Position = model.Position{Filename: p.Filename, Offset: p.Offset, Line: p.Line, Column: p.Column}
					}
					out = append(out, entry)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PackagePath != out[j].PackagePath {
			return out[i].PackagePath < out[j].PackagePath
		}
		if out[i].Local != out[j].Local {
			return out[i].Local < out[j].Local
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// parseLinkname reads `go:linkname local [importpath.name]`. The one-argument
// form only makes a symbol visible and names no target, so it is skipped.
func parseLinkname(text string) (local, target string, ok bool) {
	rest, found := strings.CutPrefix(text, "go:linkname")
	if !found {
		return "", "", false
	}
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return "", "", false
	}
	return fields[0], fields[1], true
}

// ResolveTarget finds the SSA function a linkname points at, if the program
// contains it. A directive into runtime internals usually will not resolve,
// which is itself worth reporting and is why the caller is told.
func (a *Analyzer) ResolveTarget(target string) *ssa.Function {
	if a.Program == nil {
		return nil
	}
	pkgPath, name, ok := splitQualified(target)
	if !ok {
		return nil
	}
	for _, pkg := range a.Program.AllPackages() {
		if pkg == nil || pkg.Pkg == nil || pkg.Pkg.Path() != pkgPath {
			continue
		}
		if fn, ok := pkg.Members[name].(*ssa.Function); ok {
			return fn
		}
	}
	return nil
}

func splitQualified(qualified string) (pkgPath, name string, ok bool) {
	index := strings.LastIndex(qualified, ".")
	if index <= 0 || index == len(qualified)-1 {
		return "", "", false
	}
	return qualified[:index], qualified[index+1:], true
}

// BuildShapeCheck reports Go files that exist in the tree but took no part in
// the analysis.
//
// A single packages.Load silently picks one build configuration. On a hybrid
// repository that means whole files — the CGO_ENABLED=0 fallbacks, the other
// platform's syscalls — are invisible, and nothing in the report says so.
func BuildShapeCheck(rootDir string, pkgs []*packages.Package) []model.BuildShapeDelta {
	known := map[string]bool{}
	var deltas []model.BuildShapeDelta
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		// GoFiles is the package's own source. CompiledGoFiles is what the
		// compiler saw, which for a cgo package is generated code in the build
		// cache — so a check against CompiledGoFiles alone reports every cgo
		// source file in the project as excluded.
		for _, group := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.OtherFiles} {
			for _, file := range group {
				known[file] = true
			}
		}
		for _, file := range pkg.IgnoredFiles {
			if known[file] {
				continue
			}
			known[file] = true
			if !strings.HasSuffix(file, ".go") {
				continue
			}
			deltas = append(deltas, shapeDelta(file))
		}
	}

	// Files the loader never mentioned at all: a directory outside the pattern,
	// or a package that failed to load.
	_ = filepath.WalkDir(rootDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if skipDir(filepath.Base(path)) && path != rootDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || known[path] {
			return nil
		}
		if buildConstraintOf(path) != "" {
			deltas = append(deltas, shapeDelta(path))
			return nil
		}
		deltas = append(deltas, model.BuildShapeDelta{Path: path, Reason: "not-in-any-loaded-package"})
		return nil
	})

	sort.Slice(deltas, func(i, j int) bool { return deltas[i].Path < deltas[j].Path })
	return deltas
}

// shapeDelta classifies one excluded file. A test file is excluded because the
// run did not ask for tests, which is a different thing from a platform or tag
// constraint and should not be reported as one.
func shapeDelta(path string) model.BuildShapeDelta {
	constraintText := buildConstraintOf(path)
	if constraintText == "test-only" {
		return model.BuildShapeDelta{Path: path, Reason: "test-only", Constraint: ""}
	}
	return model.BuildShapeDelta{Path: path, Reason: "excluded-by-build-constraint", Constraint: constraintText}
}

func skipDir(base string) bool {
	return base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_")
}

// buildConstraintOf returns the file's //go:build expression, or the implicit
// constraint its name carries. Reading the real expression matters: guessing
// from the filename cannot see `//go:build !cgo`, which is the single most
// interesting exclusion in a hybrid project.
func buildConstraintOf(path string) string {
	if expr := goBuildLine(path); expr != "" {
		return expr
	}
	base := strings.TrimSuffix(filepath.Base(path), ".go")
	if strings.HasSuffix(base, "_test") {
		return "test-only"
	}
	parts := strings.Split(base, "_")
	for _, part := range parts[1:] {
		if knownGOOS[part] {
			return "GOOS=" + part
		}
		if knownGOARCH[part] {
			return "GOARCH=" + part
		}
	}
	return ""
}

func goBuildLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if constraint.IsGoBuild(line) || constraint.IsPlusBuild(line) {
			if expr, err := constraint.Parse(line); err == nil {
				return expr.String()
			}
			return line
		}
		if strings.HasPrefix(line, "package ") {
			return ""
		}
	}
	return ""
}

var knownGOOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true, "freebsd": true,
	"hurd": true, "illumos": true, "ios": true, "js": true, "linux": true, "nacl": true,
	"netbsd": true, "openbsd": true, "plan9": true, "solaris": true, "wasip1": true, "windows": true,
}

var knownGOARCH = map[string]bool{
	"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true, "mips": true,
	"mips64": true, "mips64le": true, "mipsle": true, "ppc64": true, "ppc64le": true,
	"riscv64": true, "s390x": true, "wasm": true,
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, value := range in {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// stableID matches the identifier convention used across the report: readable
// while short, hashed once it would bloat the output.
func stableID(parts ...string) string {
	joined := strings.Join(parts, "|")
	if len(joined) < 180 {
		return joined
	}
	sum := sha256.Sum256([]byte(joined))
	return parts[0] + "|sha256:" + hex.EncodeToString(sum[:])
}
