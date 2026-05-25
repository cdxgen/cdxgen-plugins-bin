package analyzer

import (
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func (a *Analyzer) packageEvidence(pkg *packages.Package) model.PackageEvidence {
	mod := moduleForPackage(pkg)
	pe := model.PackageEvidence{
		ID:              pkg.ID,
		Name:            pkg.Name,
		PackagePath:     pkg.PkgPath,
		Module:          mod,
		Standard:        isStandardPackage(pkg.PkgPath, mod),
		Local:           isLocalModule(mod),
		GoFiles:         sortedStrings(pkg.GoFiles),
		CompiledGoFiles: sortedStrings(pkg.CompiledGoFiles),
		OtherFiles:      sortedStrings(pkg.OtherFiles),
	}
	for _, err := range pkg.Errors {
		pe.Diagnostics = append(pe.Diagnostics, model.Diagnostic{PackageID: pkg.ID, Position: positionFromPackagesError(err), Kind: "package", Message: err.Msg})
	}
	for _, file := range pkg.Syntax {
		if file == nil {
			continue
		}
		imports := a.importsForFile(pkg, file)
		decls := a.declarationsForFile(pkg, file)
		usages := a.usagesForFile(pkg, file, imports)
		pe.Imports = append(pe.Imports, imports...)
		pe.Declarations = append(pe.Declarations, decls...)
		pe.Usages = append(pe.Usages, usages...)
	}
	return pe
}

func (a *Analyzer) fileEvidence(pkg *packages.Package, pe model.PackageEvidence) []model.FileEvidence {
	byFile := map[string]*model.FileEvidence{}
	compiled := map[string]bool{}
	for _, f := range pkg.CompiledGoFiles {
		compiled[f] = true
		byFile[f] = &model.FileEvidence{Path: f, PackageName: pkg.Name, PackagePath: pkg.PkgPath, Compiled: true, Generated: isGeneratedFile(f)}
	}
	for _, f := range pkg.GoFiles {
		if _, ok := byFile[f]; !ok {
			byFile[f] = &model.FileEvidence{Path: f, PackageName: pkg.Name, PackagePath: pkg.PkgPath, Compiled: compiled[f], Generated: isGeneratedFile(f)}
		}
	}
	for _, imp := range pe.Imports {
		file := ensureFile(byFile, imp.Range.Start.Filename, pkg, compiled)
		file.Imports = append(file.Imports, imp)
	}
	for _, decl := range pe.Declarations {
		file := ensureFile(byFile, decl.Range.Start.Filename, pkg, compiled)
		file.Declarations = append(file.Declarations, decl)
	}
	for _, usage := range pe.Usages {
		file := ensureFile(byFile, usage.Range.Start.Filename, pkg, compiled)
		file.Usages = append(file.Usages, usage)
	}
	files := make([]model.FileEvidence, 0, len(byFile))
	for _, file := range byFile {
		files = append(files, *file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

func ensureFile(files map[string]*model.FileEvidence, path string, pkg *packages.Package, compiled map[string]bool) *model.FileEvidence {
	if files[path] == nil {
		files[path] = &model.FileEvidence{Path: path, PackageName: pkg.Name, PackagePath: pkg.PkgPath, Compiled: compiled[path], Generated: isGeneratedFile(path)}
	}
	return files[path]
}

func (a *Analyzer) importsForFile(pkg *packages.Package, file *ast.File) []model.ImportUsage {
	imports := make([]model.ImportUsage, 0, len(file.Imports))
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, "\"")
		alias := ""
		aliasKind := "default"
		if spec.Name != nil {
			alias = spec.Name.Name
			switch alias {
			case ".":
				aliasKind = "dot"
			case "_":
				aliasKind = "blank"
			default:
				aliasKind = "named"
			}
		}
		importPkg := pkg.Imports[path]
		mod := moduleForPackage(importPkg)
		resolved := importPkg != nil
		pkgID := ""
		pkgName := ""
		if importPkg != nil {
			pkgID = importPkg.ID
			pkgName = importPkg.Name
		}
		imports = append(imports, model.ImportUsage{Path: path, Name: alias, AliasKind: aliasKind, PackageID: pkgID, PackageName: pkgName, Module: mod, Standard: isStandardPackage(path, mod), Local: isLocalModule(mod), Direct: true, Range: a.nodeRange(spec), Resolved: resolved, ResolutionNote: resolutionNote(resolved)})
	}
	return imports
}

func (a *Analyzer) declarationsForFile(pkg *packages.Package, file *ast.File) []model.Declaration {
	var declarations []model.Declaration
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			declarations = append(declarations, a.funcDeclaration(pkg, d))
		case *ast.GenDecl:
			kind := strings.ToLower(d.Tok.String())
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					declarations = append(declarations, a.typeDeclaration(pkg, s))
				case *ast.ValueSpec:
					for _, name := range s.Names {
						typeText := typeOfDef(pkg, name)
						declarations = append(declarations, model.Declaration{ID: stableID(pkg.PkgPath, "", name.Name, typeText), Name: name.Name, Kind: kind, PackagePath: pkg.PkgPath, Type: typeText, Exported: ast.IsExported(name.Name), Range: a.nodeRange(name)})
					}
				}
			}
		}
	}
	return declarations
}

func (a *Analyzer) funcDeclaration(pkg *packages.Package, d *ast.FuncDecl) model.Declaration {
	name := d.Name.Name
	receiver := receiverString(d.Recv)
	kind := "function"
	if receiver != "" {
		kind = "method"
	}
	signature := typeOfDef(pkg, d.Name)
	return model.Declaration{ID: stableID(pkg.PkgPath, receiver, name, signature), Name: name, Kind: kind, PackagePath: pkg.PkgPath, Receiver: receiver, Signature: signature, Exported: ast.IsExported(name), Range: a.nodeRange(d)}
}

func typeOfDef(pkg *packages.Package, ident *ast.Ident) string {
	if ident == nil || pkg.TypesInfo == nil {
		return ""
	}
	if obj := pkg.TypesInfo.Defs[ident]; obj != nil && obj.Type() != nil {
		return types.TypeString(obj.Type(), qualifier(pkg.PkgPath))
	}
	return ""
}

func (a *Analyzer) typeDeclaration(pkg *packages.Package, s *ast.TypeSpec) model.Declaration {
	typeText := typeOfDef(pkg, s.Name)
	decl := model.Declaration{ID: stableID(pkg.PkgPath, "", s.Name.Name, typeText), Name: s.Name.Name, Kind: "type", PackagePath: pkg.PkgPath, Type: typeText, Exported: ast.IsExported(s.Name.Name), Range: a.nodeRange(s)}
	if s.Assign.IsValid() {
		decl.Alias = true
		if pkg.TypesInfo != nil {
			aliasedType := pkg.TypesInfo.TypeOf(s.Type)
			if aliasedType != nil {
				decl.AliasedType = types.TypeString(aliasedType, qualifier(pkg.PkgPath))
				decl.AliasedPackagePath = packagePathFromType(aliasedType)
				decl.AliasedModule = a.moduleForPackagePath(decl.AliasedPackagePath)
			}
		}
	}
	return decl
}

func (a *Analyzer) usagesForFile(pkg *packages.Package, file *ast.File, imports []model.ImportUsage) []model.LibraryUsage {
	importByName := map[string]model.ImportUsage{}
	for _, imp := range imports {
		name := imp.Name
		if name == "" {
			name = imp.PackageName
		}
		if name != "" && name != "." && name != "_" {
			importByName[name] = imp
		}
	}
	var usages []model.LibraryUsage
	globalAliases := usageScope{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			a.inspectGenDeclValues(pkg, d, importByName, nil, globalAliases, &usages)
		case *ast.FuncDecl:
			ctx := a.enclosingContext(pkg, d)
			aliases := globalAliases.clone()
			if d.Body != nil {
				a.inspectUsageNode(pkg, d.Body, importByName, &ctx, aliases, &usages)
			}
		}
	}
	return dedupeUsages(usages)
}

type usageScope map[string]model.LibraryUsage

func (s usageScope) clone() usageScope {
	out := usageScope{}
	for key, value := range s {
		out[key] = value
	}
	return out
}

func (a *Analyzer) inspectGenDeclValues(pkg *packages.Package, decl *ast.GenDecl, imports map[string]model.ImportUsage, enclosing *model.EnclosingContext, aliases usageScope, usages *[]model.LibraryUsage) {
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, value := range valueSpec.Values {
			if usage, ok := a.referenceUsage(pkg, value, imports, enclosing); ok && a.includeUsage(usage) {
				*usages = append(*usages, usage)
				if i < len(valueSpec.Names) {
					aliases[valueSpec.Names[i].Name] = usage
				}
			}
		}
	}
}

func (a *Analyzer) inspectUsageNode(pkg *packages.Package, root ast.Node, imports map[string]model.ImportUsage, enclosing *model.EnclosingContext, aliases usageScope, usages *[]model.LibraryUsage) {
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			a.recordAssignmentAliases(pkg, x.Lhs, x.Rhs, imports, enclosing, aliases, usages)
		case *ast.DeclStmt:
			if genDecl, ok := x.Decl.(*ast.GenDecl); ok {
				a.inspectGenDeclValues(pkg, genDecl, imports, enclosing, aliases, usages)
			}
		case *ast.CallExpr:
			if usage, ok := a.callUsage(pkg, x, imports, aliases, enclosing); ok && a.includeUsage(usage) {
				*usages = append(*usages, usage)
			}
		case *ast.SelectorExpr:
			if usage, ok := a.selectorUsage(pkg, x, imports, enclosing, false, 0); ok && a.includeUsage(usage) {
				*usages = append(*usages, usage)
			}
		}
		return true
	})
}

func (a *Analyzer) recordAssignmentAliases(pkg *packages.Package, lhs []ast.Expr, rhs []ast.Expr, imports map[string]model.ImportUsage, enclosing *model.EnclosingContext, aliases usageScope, usages *[]model.LibraryUsage) {
	for i, right := range rhs {
		if i >= len(lhs) {
			break
		}
		leftIdent, ok := lhs[i].(*ast.Ident)
		if !ok || leftIdent.Name == "_" {
			continue
		}
		if usage, ok := a.referenceUsage(pkg, right, imports, enclosing); ok && a.includeUsage(usage) {
			aliases[leftIdent.Name] = usage
			*usages = append(*usages, usage)
		}
	}
}

func (a *Analyzer) referenceUsage(pkg *packages.Package, expr ast.Expr, imports map[string]model.ImportUsage, enclosing *model.EnclosingContext) (model.LibraryUsage, bool) {
	switch x := expr.(type) {
	case *ast.SelectorExpr:
		return a.selectorUsage(pkg, x, imports, enclosing, false, 0)
	case *ast.Ident:
		obj := pkg.TypesInfo.Uses[x]
		if obj == nil {
			return model.LibraryUsage{}, false
		}
		usage := a.objectUsage(pkg, obj, x, enclosing)
		usage.Kind = "reference"
		return usage, usage.Name != ""
	default:
		return model.LibraryUsage{}, false
	}
}

func (a *Analyzer) enclosingContext(pkg *packages.Package, fn *ast.FuncDecl) model.EnclosingContext {
	ctx := model.EnclosingContext{Name: fn.Name.Name, Kind: "function", Receiver: receiverString(fn.Recv), Signature: typeOfDef(pkg, fn.Name)}
	if ctx.Receiver != "" {
		ctx.Kind = "method"
	}
	ctx.ID = stableID(pkg.PkgPath, ctx.Receiver, ctx.Name, ctx.Signature)
	return ctx
}

func (a *Analyzer) selectorUsage(pkg *packages.Package, sel *ast.SelectorExpr, imports map[string]model.ImportUsage, enclosing *model.EnclosingContext, call bool, argCount int) (model.LibraryUsage, bool) {
	obj := pkg.TypesInfo.Uses[sel.Sel]
	if obj == nil {
		return model.LibraryUsage{}, false
	}
	usage := a.objectUsage(pkg, obj, sel, enclosing)
	usage.Kind = "selector"
	usage.Call = call
	usage.ArgumentCount = argCount
	usage.Method = isMethodObject(obj)
	if sig, ok := obj.Type().(*types.Signature); ok {
		usage.Variadic = sig.Variadic()
	}
	if ident, ok := sel.X.(*ast.Ident); ok {
		if imp, found := imports[ident.Name]; found {
			usage.ImportPath = imp.Path
			usage.ImportAlias = imp.Name
			usage.ImportAliasKind = imp.AliasKind
		}
	}
	return usage, usage.Name != ""
}

func (a *Analyzer) callUsage(pkg *packages.Package, call *ast.CallExpr, imports map[string]model.ImportUsage, aliases usageScope, enclosing *model.EnclosingContext) (model.LibraryUsage, bool) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return a.selectorUsage(pkg, fun, imports, enclosing, true, len(call.Args))
	case *ast.Ident:
		if aliased, found := aliases[fun.Name]; found {
			usage := aliased
			usage.ID = stableUsageID(pkg.ID, usage.QualifiedName+".alias."+fun.Name, a.nodeRange(fun))
			usage.Kind = "functionValueCall"
			if usage.Method {
				usage.Kind = "methodValueCall"
			}
			usage.Call = true
			usage.ArgumentCount = len(call.Args)
			usage.Range = a.nodeRange(fun)
			usage.Enclosing = enclosing
			if usage.Properties == nil {
				usage.Properties = map[string]string{}
			}
			usage.Properties["calledThrough"] = fun.Name
			usage.Properties["aliasKind"] = "function-value"
			return usage, usage.Name != ""
		}
		obj := pkg.TypesInfo.Uses[fun]
		if obj == nil {
			return model.LibraryUsage{}, false
		}
		usage := a.objectUsage(pkg, obj, fun, enclosing)
		usage.Kind = "call"
		usage.Call = true
		usage.ArgumentCount = len(call.Args)
		if sig, ok := obj.Type().(*types.Signature); ok {
			usage.Variadic = sig.Variadic()
		}
		return usage, usage.Name != ""
	default:
		return model.LibraryUsage{}, false
	}
}

func (a *Analyzer) objectUsage(pkg *packages.Package, obj types.Object, n ast.Node, enclosing *model.EnclosingContext) model.LibraryUsage {
	pkgPath := ""
	pkgName := ""
	if obj.Pkg() != nil {
		pkgPath = obj.Pkg().Path()
		pkgName = obj.Pkg().Name()
	}
	mod := a.moduleForPackagePath(pkgPath)
	qualified := obj.Name()
	if pkgPath != "" {
		qualified = pkgPath + "." + obj.Name()
	}
	typeText := ""
	if obj.Type() != nil {
		typeText = types.TypeString(obj.Type(), qualifier(pkg.PkgPath))
	}
	signature := ""
	if sig, ok := obj.Type().(*types.Signature); ok {
		signature = types.TypeString(sig, qualifier(pkg.PkgPath))
	}
	usage := model.LibraryUsage{ID: stableUsageID(pkg.ID, qualified, a.nodeRange(n)), Kind: "reference", Name: obj.Name(), QualifiedName: qualified, PackagePath: pkgPath, PackageName: pkgName, Module: mod, Standard: isStandardPackage(pkgPath, mod), Local: isLocalModule(mod), SymbolKind: objectKind(obj), Type: typeText, Signature: signature, Builtin: isBuiltinObject(obj), Range: a.nodeRange(n), Enclosing: enclosing, Properties: constantProperties(obj)}
	if recv := receiverFromObject(obj, pkg.PkgPath); recv != "" {
		usage.Receiver = recv
		usage.Method = true
	}
	return usage
}

func (a *Analyzer) includeUsage(usage model.LibraryUsage) bool {
	if usage.Builtin || usage.PackagePath == "" {
		return false
	}
	if usage.Standard && !a.options.IncludeStdlib {
		return false
	}
	if usage.Local && !a.options.IncludeLocal {
		return false
	}
	return true
}

func enclosing(stack []model.EnclosingContext) *model.EnclosingContext {
	if len(stack) == 0 {
		return nil
	}
	ctx := stack[len(stack)-1]
	return &ctx
}

func dedupeUsages(usages []model.LibraryUsage) []model.LibraryUsage {
	seen := map[string]bool{}
	out := make([]model.LibraryUsage, 0, len(usages))
	for _, usage := range usages {
		if seen[usage.ID] {
			continue
		}
		seen[usage.ID] = true
		out = append(out, usage)
	}
	return out
}
