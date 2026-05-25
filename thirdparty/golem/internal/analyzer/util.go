package analyzer

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func (a *Analyzer) nodeRange(n ast.Node) model.Range {
	if n == nil {
		return model.Range{}
	}
	return model.Range{Start: a.position(n.Pos()), End: a.position(n.End())}
}

func (a *Analyzer) position(pos token.Pos) model.Position {
	if !pos.IsValid() {
		return model.Position{}
	}
	p := a.fset.Position(pos)
	return model.Position{Filename: p.Filename, Offset: p.Offset, Line: p.Line, Column: p.Column}
}

func moduleForPackage(pkg *packages.Package) *model.Module {
	if pkg == nil || pkg.Module == nil {
		return nil
	}
	return convertModule(pkg.Module)
}

func convertModule(mod *packages.Module) *model.Module {
	if mod == nil {
		return nil
	}
	out := &model.Module{Path: mod.Path, Version: mod.Version, Dir: mod.Dir, GoMod: mod.GoMod, GoVersion: mod.GoVersion, Main: mod.Main}
	out.PURL = modulePURL(out)
	if mod.Replace != nil {
		out.Replace = convertModule(mod.Replace)
	}
	return out
}

func modulePURL(mod *model.Module) string {
	if mod == nil || mod.Path == "" || strings.HasPrefix(mod.Path, ".") || strings.HasPrefix(mod.Path, "/") {
		return ""
	}
	p := "pkg:golang/" + mod.Path
	if mod.Version != "" {
		p += "@" + url.QueryEscape(mod.Version)
	}
	return p
}

func moduleKey(mod *model.Module) string {
	if mod == nil {
		return ""
	}
	return mod.Path + "@" + mod.Version + "#" + mod.Dir
}

func (a *Analyzer) moduleForPackagePath(pkgPath string) *model.Module {
	if pkgPath == "" {
		return nil
	}
	if pkg := a.packageByPath[pkgPath]; pkg != nil {
		return moduleForPackage(pkg)
	}
	var best *model.Module
	for _, mod := range a.moduleByPath {
		if mod.Path == "" {
			continue
		}
		if pkgPath == mod.Path || strings.HasPrefix(pkgPath, mod.Path+"/") {
			if best == nil || len(mod.Path) > len(best.Path) {
				best = mod
			}
		}
	}
	return best
}

func isStandardPackage(pkgPath string, mod *model.Module) bool {
	if pkgPath == "" {
		return false
	}
	if mod != nil && mod.Path != "" {
		return false
	}
	first, _, _ := strings.Cut(pkgPath, "/")
	return !strings.Contains(first, ".")
}

func isLocalModule(mod *model.Module) bool {
	return mod != nil && mod.Main
}

func qualifier(currentPkgPath string) types.Qualifier {
	return func(pkg *types.Package) string {
		if pkg == nil || pkg.Path() == currentPkgPath {
			return ""
		}
		return pkg.Path()
	}
}

func objectKind(obj types.Object) string {
	switch obj.(type) {
	case *types.Func:
		return "function"
	case *types.Var:
		return "variable"
	case *types.Const:
		return "constant"
	case *types.TypeName:
		return "type"
	case *types.PkgName:
		return "package"
	case *types.Builtin:
		return "builtin"
	case *types.Label:
		return "label"
	default:
		return fmt.Sprintf("%T", obj)
	}
}

func isBuiltinObject(obj types.Object) bool {
	_, ok := obj.(*types.Builtin)
	return ok
}

func isMethodObject(obj types.Object) bool {
	fn, ok := obj.(*types.Func)
	return ok && fn.Type() != nil && receiverFromObject(fn, "") != ""
}

func receiverFromObject(obj types.Object, currentPkgPath string) string {
	if obj == nil || obj.Type() == nil {
		return ""
	}
	if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
		return types.TypeString(sig.Recv().Type(), qualifier(currentPkgPath))
	}
	return ""
}

func packagePathFromType(t types.Type) string {
	if t == nil {
		return ""
	}
	t = types.Unalias(t)
	switch typed := t.(type) {
	case *types.Named:
		if typed.Obj() != nil && typed.Obj().Pkg() != nil {
			return typed.Obj().Pkg().Path()
		}
	case *types.Pointer:
		return packagePathFromType(typed.Elem())
	case *types.Slice:
		return packagePathFromType(typed.Elem())
	case *types.Array:
		return packagePathFromType(typed.Elem())
	case *types.Map:
		if keyPath := packagePathFromType(typed.Key()); keyPath != "" {
			return keyPath
		}
		return packagePathFromType(typed.Elem())
	case *types.Chan:
		return packagePathFromType(typed.Elem())
	case *types.Signature:
		if typed.Recv() != nil {
			return packagePathFromType(typed.Recv().Type())
		}
		if typed.Results() != nil {
			for i := 0; i < typed.Results().Len(); i++ {
				if resultPath := packagePathFromType(typed.Results().At(i).Type()); resultPath != "" {
					return resultPath
				}
			}
		}
		if typed.Params() != nil {
			for i := 0; i < typed.Params().Len(); i++ {
				if paramPath := packagePathFromType(typed.Params().At(i).Type()); paramPath != "" {
					return paramPath
				}
			}
		}
	}
	return ""
}

func receiverString(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 || recv.List[0].Type == nil {
		return ""
	}
	return exprString(recv.List[0].Type)
}

func exprString(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return "*" + exprString(x.X)
	case *ast.SelectorExpr:
		return exprString(x.X) + "." + x.Sel.Name
	case *ast.IndexExpr, *ast.IndexListExpr:
		return "generic"
	default:
		return fmt.Sprintf("%T", expr)
	}
}

func stableID(parts ...string) string {
	joined := strings.Join(parts, "|")
	if len(joined) < 180 {
		return joined
	}
	sum := sha256.Sum256([]byte(joined))
	return parts[0] + "|sha256:" + hex.EncodeToString(sum[:])
}

func stableUsageID(pkgID string, qualified string, r model.Range) string {
	return stableID(pkgID, qualified, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column), fmt.Sprint(r.End.Line), fmt.Sprint(r.End.Column))
}

func stableEdgeID(sourceID string, targetID string, pos model.Position, callType string) string {
	return stableID(sourceID, targetID, pos.Filename, fmt.Sprint(pos.Line), fmt.Sprint(pos.Column), callType)
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

func sortedModules(mods map[string]*model.Module) []model.Module {
	out := make([]model.Module, 0, len(mods))
	for _, mod := range mods {
		if mod != nil {
			out = append(out, *mod)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Version < out[j].Version
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func positionFromPackagesError(err packages.Error) model.Position {
	return model.Position{Filename: err.Pos}
}

func resolutionNote(resolved bool) string {
	if resolved {
		return ""
	}
	return "import was parsed but go/packages did not resolve package metadata"
}

func fileRole(path string) string {
	base := filepath.Base(path)
	if strings.HasSuffix(base, "_test.go") {
		return "test"
	}
	return "runtime"
}

func testKindForFunc(name string, signature string) string {
	if strings.HasPrefix(name, "Benchmark") && strings.Contains(signature, "*testing.B") {
		return "benchmark"
	}
	if strings.HasPrefix(name, "Fuzz") && strings.Contains(signature, "*testing.F") {
		return "fuzz"
	}
	if strings.HasPrefix(name, "Example") {
		return "example"
	}
	if strings.HasPrefix(name, "Test") && strings.Contains(signature, "*testing.T") {
		return "test"
	}
	return ""
}

func usageScopeForFileAndFunc(path string, functionName string, signature string) string {
	if testKind := testKindForFunc(functionName, signature); testKind != "" {
		return testKind
	}
	return fileRole(path)
}

func usageScopeForUsage(r model.Range, enclosing *model.EnclosingContext) string {
	if enclosing != nil && enclosing.UsageScope != "" {
		return enclosing.UsageScope
	}
	return fileRole(r.Start.Filename)
}

func generatedInfo(path string) (bool, string) {
	if filepath.Ext(path) != ".go" {
		return false, ""
	}
	f, err := os.Open(path)
	if err != nil {
		return false, ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	re := regexp.MustCompile(`(?i)^// Code generated by\s+([^;\.]+)`) // keep only the generator token, not raw command text.
	for i := 0; scanner.Scan() && i < 40; i++ {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, "Code generated") {
			continue
		}
		if !strings.Contains(line, "DO NOT EDIT") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			return true, sanitizeToolName(matches[1])
		}
		return true, "unknown"
	}
	return false, ""
}

func sanitizeToolName(value string) string {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return "unknown"
	}
	value = filepath.Base(fields[0])
	value = strings.Trim(value, "'\"")
	var b strings.Builder
	for _, r := range value {
		if r == '-' || r == '_' || r == '.' || r == '/' || r == '+' || r == '@' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func isGeneratedFile(path string) bool {
	generated, _ := generatedInfo(path)
	return generated
}

func constantProperties(obj types.Object) map[string]string {
	val, ok := obj.(*types.Const)
	if !ok || val.Val() == nil {
		return nil
	}
	props := map[string]string{"constantKind": val.Val().Kind().String()}
	if val.Val().Kind() == constant.Bool {
		props["constantBoolean"] = fmt.Sprint(constant.BoolVal(val.Val()))
	}
	return props
}
