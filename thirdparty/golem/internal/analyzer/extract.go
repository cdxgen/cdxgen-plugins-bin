package analyzer

import (
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
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
		Standard:        a.isStandardPackage(pkg.PkgPath, mod),
		Local:           isLocalModule(mod),
		GoFiles:         a.reportableFiles(pkg.GoFiles),
		CompiledGoFiles: a.reportableFiles(pkg.CompiledGoFiles),
		OtherFiles:      a.reportableFiles(pkg.OtherFiles),
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
		directives := a.buildDirectivesForFile(file)
		signals := a.securitySignalsForFile(pkg, file)
		crypto := a.cryptoEvidenceForFile(pkg, file)
		pe.Imports = append(pe.Imports, imports...)
		pe.Declarations = append(pe.Declarations, decls...)
		pe.Usages = append(pe.Usages, usages...)
		pe.BuildDirectives = append(pe.BuildDirectives, directives...)
		pe.SecuritySignals = append(pe.SecuritySignals, signals...)
		pe.Crypto = mergeCryptoEvidence(pe.Crypto, crypto)
	}
	// Evidence the loader derived from cgo-generated cache files is dropped:
	// its positions name build output under GOCACHE rather than source, and
	// the absolute cache path would leak the analyst's home directory. What a
	// cgo package actually says lives in its own files, which the textual cgo
	// read reports.
	pe.Imports = a.reportableImports(pe.Imports)
	pe.Declarations = a.reportableDeclarations(pe.Declarations)
	pe.Usages = a.reportableUsages(pe.Usages)
	pe.BuildDirectives = a.reportableDirectives(pe.BuildDirectives)
	pe.SecuritySignals = a.reportableSignals(pe.SecuritySignals)
	pe.NativeArtifacts = a.nativeArtifactsForPackage(pkg)
	return pe
}

// reportableFiles keeps the file lists a report may name. The loader lists a
// cgo package's compiled files under the build cache; those are output, not
// source, and the report keeps only what an analyst can open.
func (a *Analyzer) reportableFiles(files []string) []string {
	out := make([]string, 0, len(files))
	for _, file := range files {
		if a.reportableSource(file) {
			out = append(out, file)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func (a *Analyzer) reportableImports(imports []model.ImportUsage) []model.ImportUsage {
	out := imports[:0]
	for _, imp := range imports {
		if a.reportableSource(imp.Range.Start.Filename) {
			out = append(out, imp)
		}
	}
	return out
}

func (a *Analyzer) reportableDeclarations(declarations []model.Declaration) []model.Declaration {
	out := declarations[:0]
	for _, decl := range declarations {
		if a.reportableSource(decl.Range.Start.Filename) {
			out = append(out, decl)
		}
	}
	return out
}

func (a *Analyzer) reportableUsages(usages []model.LibraryUsage) []model.LibraryUsage {
	out := usages[:0]
	for _, usage := range usages {
		if a.reportableSource(usage.Range.Start.Filename) {
			out = append(out, usage)
		}
	}
	return out
}

func (a *Analyzer) reportableDirectives(directives []model.BuildDirective) []model.BuildDirective {
	out := directives[:0]
	for _, directive := range directives {
		if a.reportableSource(directive.Range.Start.Filename) {
			out = append(out, directive)
		}
	}
	return out
}

func (a *Analyzer) reportableSignals(signals []model.SecuritySignal) []model.SecuritySignal {
	out := signals[:0]
	for _, signal := range signals {
		if a.reportableSource(signal.Range.Start.Filename) {
			out = append(out, signal)
		}
	}
	return out
}

// nativeArtifactsForPackage lists the native files that sit next to a loaded
// package's source. Directories the loader derived (the build cache) are not
// scanned: their entries are cgo's temporary files, not the project's native
// sources, and a .syso there would be counted twice.
func (a *Analyzer) nativeArtifactsForPackage(pkg *packages.Package) []model.NativeArtifact {
	dirs := map[string]bool{}
	for _, file := range append(append([]string{}, pkg.GoFiles...), pkg.CompiledGoFiles...) {
		if file != "" && a.reportableSource(file) {
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
			artifact := model.NativeArtifact{Path: path, Kind: kind, Extension: ext, PackageID: pkg.ID}
			// A .syso the cgo pass classified carries its verdict.
			if classified, ok := a.cgoArtifacts[path]; ok {
				artifact.Properties = classified.Properties
			}
			artifacts = append(artifacts, artifact)
		}
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return artifacts
}

func (a *Analyzer) fileEvidence(pkg *packages.Package, pe model.PackageEvidence) []model.FileEvidence {
	byFile := map[string]*model.FileEvidence{}
	compiled := map[string]bool{}
	// CompiledGoFiles of a cgo package are cache paths; a report names only
	// files inside the module or the module cache, so the compiled flag rides
	// on the reportable entries and the cache files are skipped.
	for _, f := range pkg.CompiledGoFiles {
		compiled[f] = a.reportableSource(f)
		if a.reportableSource(f) {
			byFile[f] = newFileEvidence(f, pkg, true)
		}
	}
	for _, f := range pkg.GoFiles {
		if _, ok := byFile[f]; !ok && a.reportableSource(f) {
			byFile[f] = newFileEvidence(f, pkg, compiled[f])
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
	for _, directive := range pe.BuildDirectives {
		file := ensureFile(byFile, directive.Range.Start.Filename, pkg, compiled)
		file.BuildDirectives = append(file.BuildDirectives, directive)
	}
	for _, signal := range pe.SecuritySignals {
		file := ensureFile(byFile, signal.Range.Start.Filename, pkg, compiled)
		file.SecuritySignals = append(file.SecuritySignals, signal)
	}
	if pe.Crypto != nil {
		for _, library := range pe.Crypto.Libraries {
			file := ensureFile(byFile, library.Range.Start.Filename, pkg, compiled)
			file.Crypto = mergeCryptoEvidence(file.Crypto, &model.CryptoEvidence{Libraries: []model.CryptoLibrary{library}})
		}
		for _, asset := range pe.Crypto.Assets {
			file := ensureFile(byFile, asset.Range.Start.Filename, pkg, compiled)
			file.Crypto = mergeCryptoEvidence(file.Crypto, &model.CryptoEvidence{Assets: []model.CryptoAsset{asset}})
		}
		for _, operation := range pe.Crypto.Operations {
			file := ensureFile(byFile, operation.Range.Start.Filename, pkg, compiled)
			file.Crypto = mergeCryptoEvidence(file.Crypto, &model.CryptoEvidence{Operations: []model.CryptoOperation{operation}})
		}
		for _, material := range pe.Crypto.Materials {
			file := ensureFile(byFile, material.Range.Start.Filename, pkg, compiled)
			file.Crypto = mergeCryptoEvidence(file.Crypto, &model.CryptoEvidence{Materials: []model.CryptoMaterial{material}})
		}
		for _, protocol := range pe.Crypto.Protocols {
			file := ensureFile(byFile, protocol.Range.Start.Filename, pkg, compiled)
			file.Crypto = mergeCryptoEvidence(file.Crypto, &model.CryptoEvidence{Protocols: []model.CryptoProtocol{protocol}})
		}
		for _, finding := range pe.Crypto.Findings {
			file := ensureFile(byFile, finding.Range.Start.Filename, pkg, compiled)
			file.Crypto = mergeCryptoEvidence(file.Crypto, &model.CryptoEvidence{Findings: []model.CryptoFinding{finding}})
		}
	}
	files := make([]model.FileEvidence, 0, len(byFile))
	for _, file := range byFile {
		sortCryptoEvidence(file.Crypto)
		files = append(files, *file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

func ensureFile(files map[string]*model.FileEvidence, path string, pkg *packages.Package, compiled map[string]bool) *model.FileEvidence {
	if files[path] == nil {
		files[path] = newFileEvidence(path, pkg, compiled[path])
	}
	return files[path]
}

func newFileEvidence(path string, pkg *packages.Package, compiled bool) *model.FileEvidence {
	generated, generatedBy := generatedInfo(path)
	return &model.FileEvidence{Path: path, PackageName: pkg.Name, PackagePath: pkg.PkgPath, Role: fileRole(path), TestFile: fileRole(path) != "runtime", Compiled: compiled, Generated: generated, GeneratedBy: generatedBy}
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
		rangeInfo := a.nodeRange(spec)
		imports = append(imports, model.ImportUsage{Path: path, Name: alias, AliasKind: aliasKind, UsageScope: fileRole(rangeInfo.Start.Filename), PackageID: pkgID, PackageName: pkgName, Module: mod, Standard: a.isStandardPackage(path, mod), Local: isLocalModule(mod), Direct: true, Range: rangeInfo, Resolved: resolved, ResolutionNote: resolutionNote(resolved)})
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
						rangeInfo := a.nodeRange(name)
						declarations = append(declarations, model.Declaration{ID: stableID(pkg.PkgPath, "", name.Name, typeText), Name: name.Name, Kind: kind, UsageScope: fileRole(rangeInfo.Start.Filename), PackagePath: pkg.PkgPath, Type: typeText, Exported: ast.IsExported(name.Name), Range: rangeInfo})
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
	rangeInfo := a.nodeRange(d)
	testKind := testKindForFunc(name, signature)
	return model.Declaration{ID: stableID(pkg.PkgPath, receiver, name, signature), Name: name, Kind: kind, TestKind: testKind, UsageScope: usageScopeForFileAndFunc(rangeInfo.Start.Filename, name, signature), PackagePath: pkg.PkgPath, Receiver: receiver, Signature: signature, Exported: ast.IsExported(name), Range: rangeInfo}
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
	rangeInfo := a.nodeRange(s)
	decl := model.Declaration{ID: stableID(pkg.PkgPath, "", s.Name.Name, typeText), Name: s.Name.Name, Kind: "type", UsageScope: fileRole(rangeInfo.Start.Filename), PackagePath: pkg.PkgPath, Type: typeText, Exported: ast.IsExported(s.Name.Name), Range: rangeInfo}
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
	rangeInfo := a.nodeRange(fn)
	signature := typeOfDef(pkg, fn.Name)
	ctx := model.EnclosingContext{Name: fn.Name.Name, Kind: "function", TestKind: testKindForFunc(fn.Name.Name, signature), UsageScope: usageScopeForFileAndFunc(rangeInfo.Start.Filename, fn.Name.Name, signature), Receiver: receiverString(fn.Recv), Signature: signature}
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
			usage.UsageScope = usageScopeForUsage(usage.Range, enclosing)
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
	rangeInfo := a.nodeRange(n)
	usage := model.LibraryUsage{ID: stableUsageID(pkg.ID, qualified, rangeInfo), Kind: "reference", Name: obj.Name(), QualifiedName: qualified, PackagePath: pkgPath, PackageName: pkgName, UsageScope: usageScopeForUsage(rangeInfo, enclosing), Module: mod, Standard: a.isStandardPackage(pkgPath, mod), Local: isLocalModule(mod), SymbolKind: objectKind(obj), Type: typeText, Signature: signature, Builtin: isBuiltinObject(obj), Range: rangeInfo, Enclosing: enclosing, Properties: constantProperties(obj)}
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
