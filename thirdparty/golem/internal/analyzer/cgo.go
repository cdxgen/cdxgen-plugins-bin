package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/native"
)

// cgoEvidence is the collected cgo view of one analysis: the files read
// textually, the directives and risks found in them, and how they attach to
// packages.
type cgoEvidence struct {
	moduleRoot string
	files      map[string]*cgoFile
	packages   map[string]*model.CgoPackageSummary
	syso       map[string]bool // path -> header looks like an object or archive
}

// cgoFile is one .go file that imports "C", read with go/parser rather than
// loaded by the toolchain.
type cgoFile struct {
	path        string
	packagePath string
	modulePath  string
	loaded      bool // a package the loader returned owns this file
	directives  []model.BuildDirective
	risks       []native.CgoFlagRisk
	signals     []model.SecuritySignal
}

// cgoModeOf resolves the cgo mode the load ran with: "disabled" when golem
// pinned CGO_ENABLED=0, "enabled" when the analyst exported CGO_ENABLED=1.
// The probe's answer wins because it is the value the packages were actually
// loaded under; the forced flag and the process environment are the fallbacks
// for when the probe could not run.
func cgoModeOf(forced bool, target buildTarget) string {
	if value := strings.TrimSpace(target.CGOEnabled); value != "" {
		if value == "1" {
			return "enabled"
		}
		return "disabled"
	}
	if forced || os.Getenv("CGO_ENABLED") != "1" {
		return "disabled"
	}
	return "enabled"
}

// collectCgoEvidence reads every file that imports "C" textually and classifies
// what it finds. The loader is not asked to compile anything: with CGO_ENABLED
// pinned to 0 the loader refuses those files outright (they land in
// IgnoredFiles, and a package made only of them does not load at all), so the
// report would otherwise lose the Go/C boundary of the analysed tree exactly
// when the host is protected.
//
// The same read supplies the directives when cgo IS on: what the loader parsed
// for a cgo package is cgo-generated cache files, and the source file is the
// thing an analyst can open.
func (a *Analyzer) collectCgoEvidence(pkgs []*packages.Package, moduleRoot string) *cgoEvidence {
	collected := &cgoEvidence{
		moduleRoot: moduleRoot,
		files:      map[string]*cgoFile{},
		packages:   map[string]*model.CgoPackageSummary{},
		syso:       map[string]bool{},
	}
	known := map[string]bool{}
	seenPkg := map[string]bool{}
	loadedModuleDirs := map[string]bool{}
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if pkg == nil || seenPkg[pkg.ID] {
			return
		}
		seenPkg[pkg.ID] = true
		for _, group := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.OtherFiles, pkg.IgnoredFiles} {
			for _, file := range group {
				known[file] = true
			}
		}
		modulePath := ""
		if pkg.Module != nil {
			modulePath = pkg.Module.Path
			if pkg.Module.Dir != "" {
				loadedModuleDirs[filepath.Clean(pkg.Module.Dir)] = true
			}
		}
		// Every source file of every loaded package is offered to the textual
		// reader: a package whose cgo step failed (a patched toolchain
		// refusing a flag) has no compiled files to recognise it by, and its
		// directives matter at least as much as a healthy package's.
		// IgnoredFiles join because with cgo off that is where files that
		// import "C" end up.
		var candidates []string
		candidates = append(candidates, pkg.GoFiles...)
		for _, file := range pkg.IgnoredFiles {
			if strings.HasSuffix(file, ".go") {
				candidates = append(candidates, file)
			}
		}
		found := false
		for _, file := range candidates {
			if !a.reportableSource(file) {
				continue
			}
			if collected.readCgoFile(file, pkg.PkgPath, modulePath, true) {
				found = true
			}
		}
		if found {
			collected.notePackage(pkg.PkgPath, modulePath, true)
		}
	})
	// Files the loader never mentioned: with cgo off, a package whose files
	// all import "C" does not load at all, so nothing above saw it. Vendor is
	// walked on purpose: a vendored dependency's #cgo flags run on the host
	// like any other's. Directory symlinks are never followed, and a file
	// entry that is itself a symlink is skipped, so the walk cannot leave the
	// module root through a link planted in the tree.
	_ = filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() {
			if path != moduleRoot {
				switch name := entry.Name(); {
				case name == ".git", name == "testdata", strings.HasPrefix(name, "."), strings.HasPrefix(name, "_"):
					return filepath.SkipDir
				}
				// A nested module is outside the load's ./... unless a
				// workspace brought it in. Its own run (multi-module
				// recursion, or a scan of that directory) reports it, so
				// reading it here would count its packages twice and call
				// them unloaded.
				if !loadedModuleDirs[filepath.Clean(path)] && !underVendor(moduleRoot, path) {
					if _, err := os.Lstat(filepath.Join(path, "go.mod")); err == nil {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".syso"):
			collected.syso[path] = native.SysoObjectValid(path)
		case strings.HasSuffix(path, ".go") && !known[path]:
			if collected.readCgoFile(path, "", "", false) {
				record := collected.files[path]
				if record.packagePath == "" {
					record.packagePath, record.modulePath = collected.inferPackage(filepath.Dir(path))
				}
				collected.notePackage(record.packagePath, record.modulePath, false)
			}
		}
		return nil
	})
	for _, record := range collected.files {
		sort.Slice(record.directives, func(i, j int) bool {
			if record.directives[i].Range.Start.Line != record.directives[j].Range.Start.Line {
				return record.directives[i].Range.Start.Line < record.directives[j].Range.Start.Line
			}
			return record.directives[i].Variable < record.directives[j].Variable
		})
	}
	return collected
}

// packageCompiledWithCgo reports whether the loader returned cgo-generated
// files for pkg: cgo writes its output under the build cache, so a compiled
// file there means the package crossed into C and was translated. It feeds
// the mode the report states for a package, not the decision to read it.
func (a *Analyzer) packageCompiledWithCgo(pkg *packages.Package) bool {
	if a.gocache == "" {
		return false
	}
	for _, file := range pkg.CompiledGoFiles {
		if underPath(filepath.Clean(file), a.gocache) {
			return true
		}
	}
	return false
}

// readCgoFile parses one file with go/parser in ImportsOnly|ParseComments mode
// and records it when it imports "C". Nothing in the file is ever executed;
// the parser is the only tool that touches it.
func (c *cgoEvidence) readCgoFile(path, packagePath, modulePath string, loaded bool) bool {
	if existing, ok := c.files[path]; ok {
		// A file can be reached from two packages (a test variant, or the
		// module walk after the loader ignored it); the loader's attribution
		// is the better one.
		if loaded && !existing.loaded {
			existing.packagePath = packagePath
			existing.modulePath = modulePath
			existing.loaded = true
		}
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil || !importsC(data) {
		return false
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
	if err != nil || !fileImportsC(file) {
		return false
	}
	record := &cgoFile{path: path, packagePath: packagePath, modulePath: modulePath, loaded: loaded}
	srcDir := filepath.Dir(path)
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for _, line := range preambleLines(comment.Text) {
				c.absorbPreambleLine(record, line, fset.Position(comment.Pos()), srcDir)
			}
		}
	}
	c.absorbCompilerDirectives(record, data, path)
	{
		// The loader never reports this signal itself: the files it parsed of
		// a cgo package are cgo-generated, and the `import "C"` line is gone
		// from them. The textual read is the only place the boundary is
		// visible in every mode.
		position := fset.Position(file.Pos())
		line := position.Line
		record.signals = []model.SecuritySignal{{
			ID:             stableID("textual", packagePath, "native-interop", path, "import-C"),
			Category:       "native-interop",
			Severity:       "high",
			Confidence:     "textual",
			PackagePath:    packagePath,
			Symbol:         "C",
			Description:    "Imports cgo package C.",
			Recommendation: "Review native build flags, linked libraries, and C memory safety.",
			Range:          model.Range{Start: model.Position{Filename: path, Line: line}, End: model.Position{Filename: path, Line: line}},
		}}
	}
	c.files[path] = record
	return true
}

// absorbPreambleLine turns one `#cgo` preamble line into a directive record
// that carries names and categories, never the raw value: the value can hold
// paths and secrets that must not reach a report.
func (c *cgoEvidence) absorbPreambleLine(record *cgoFile, line string, position token.Position, srcDir string) {
	directive, ok := native.ParseCgoDirective(line)
	if !ok {
		return
	}
	risks := native.ClassifyCgoValues(directive.Variable, directive.Values, native.CgoValuesInput{
		ModuleRoot: c.moduleRoot,
		SrcDir:     srcDir,
	})
	d := model.BuildDirective{
		Kind:       "cgo",
		Variable:   directive.Variable,
		Constraint: directive.Constraint,
		Range:      model.Range{Start: model.Position{Filename: position.Filename, Line: position.Line, Column: position.Column}, End: model.Position{Filename: position.Filename, Line: position.Line, Column: position.Column}},
	}
	for _, value := range directive.Values {
		if name := cgoFlagDisplayName(value, directive.Variable); name != "" {
			d.Flags = append(d.Flags, name)
		}
	}
	for _, risk := range risks {
		d.Categories = append(d.Categories, risk.Categories...)
		record.risks = append(record.risks, risk)
	}
	d.Flags = sortedUnique(d.Flags)
	d.Categories = sortedUnique(d.Categories)
	record.directives = append(record.directives, d)
}

// absorbCompilerDirectives scans the raw text for //go:cgo_* lines, which the
// ImportsOnly parse does not reach past the import block. In hand-written
// source these directives are a signal by themselves; generated files are
// skipped because cgo writes them into its own output routinely.
func (c *cgoEvidence) absorbCompilerDirectives(record *cgoFile, data []byte, path string) {
	if generated, _ := generatedInfo(path); generated {
		return
	}
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//go:cgo_") {
			continue
		}
		name, categories, ok := native.ClassifyCompilerDirective(trimmed[len("//"):])
		if !ok {
			continue
		}
		column := strings.Index(line, "//") + 1
		directive := model.BuildDirective{
			Kind:       "go-cgo",
			Variable:   name,
			Range:      model.Range{Start: model.Position{Filename: path, Line: i + 1, Column: column}, End: model.Position{Filename: path, Line: i + 1, Column: column}},
			Categories: categories,
		}
		record.directives = append(record.directives, directive)
		record.risks = append(record.risks, native.CgoFlagRisk{Name: name, Categories: categories})
	}
}

// inferPackage derives the package and module path of a directory no loaded
// package owns: the nearest go.mod above it names the module, and the
// directory below that names the package.
func (c *cgoEvidence) inferPackage(dir string) (packagePath, modulePath string) {
	search := dir
	for {
		if data, err := os.ReadFile(filepath.Join(search, "go.mod")); err == nil {
			modulePath = goModModulePath(data)
			if modulePath != "" {
				if rel, err := filepath.Rel(search, dir); err == nil && rel != "." {
					packagePath = modulePath + "/" + filepath.ToSlash(rel)
				} else {
					packagePath = modulePath
				}
			}
			return packagePath, modulePath
		}
		if len(search) <= len(c.moduleRoot) {
			break
		}
		parent := filepath.Dir(search)
		if parent == search {
			break
		}
		search = parent
	}
	rel, err := filepath.Rel(c.moduleRoot, dir)
	if err != nil {
		return "", ""
	}
	return filepath.ToSlash(rel), ""
}

// notePackage creates or updates the summary of one package that crosses into
// C. loaded records whether the loader returned the package; a package seen
// only textually is exactly what UnloadedPackageCount counts.
func (c *cgoEvidence) notePackage(packagePath, modulePath string, loaded bool) {
	if packagePath == "" {
		return
	}
	summary, ok := c.packages[packagePath]
	if !ok {
		summary = &model.CgoPackageSummary{PackagePath: packagePath, ModulePath: modulePath, Loaded: loaded}
		c.packages[packagePath] = summary
	}
	if modulePath != "" && summary.ModulePath == "" {
		summary.ModulePath = modulePath
	}
	if loaded {
		summary.Loaded = true
	}
}

// assembleCgoReport folds the collected files, directives and .syso
// classifications into the report's cgo object. Directives and signals are
// returned for the report to attach: the per-package ones join the package
// evidence the loader produced, the rest belong to packages that never loaded.
type cgoAttachment struct {
	directivesByPackage map[string][]model.BuildDirective
	signalsByPackage    map[string][]model.SecuritySignal
	artifactsByPackage  map[string][]model.NativeArtifact
}

func (a *Analyzer) assembleCgoReport(collected *cgoEvidence, mode, toolchainVersion string, patched bool, envOverrides []string) (*model.CgoEvidence, cgoAttachment) {
	evidence := &model.CgoEvidence{
		Mode:             mode,
		ToolchainVersion: toolchainVersion,
		ToolchainPatched: patched,
		EnvOverrideNames: envOverrides,
	}
	attachment := cgoAttachment{
		directivesByPackage: map[string][]model.BuildDirective{},
		signalsByPackage:    map[string][]model.SecuritySignal{},
		artifactsByPackage:  map[string][]model.NativeArtifact{},
	}
	// Every .syso under the module is classified, whether or not a package
	// around it was seen: the linker reads the file whatever the Go code
	// looks like. Files already classified by the walk keep that verdict.
	sysoVerdict := map[string]bool{}
	for path, valid := range collected.syso {
		sysoVerdict[path] = valid
	}
	sysoDirs := map[string]bool{}
	for path := range collected.syso {
		sysoDirs[filepath.Dir(path)] = true
	}
	for _, record := range collected.files {
		sysoDirs[filepath.Dir(record.path)] = true
	}
	for dir := range sysoDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".syso") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if _, seen := sysoVerdict[path]; !seen {
				sysoVerdict[path] = native.SysoObjectValid(path)
			}
		}
	}
	// The package that owns a directory: a textual cgo file in it wins, else
	// the go.mod layout names one.
	ownerOfDir := map[string]string{}
	for _, record := range collected.files {
		if record.packagePath != "" {
			ownerOfDir[filepath.Dir(record.path)] = record.packagePath
		}
	}
	ownerOf := func(path string) string {
		dir := filepath.Dir(path)
		if owner := ownerOfDir[dir]; owner != "" {
			return owner
		}
		packagePath, _ := collected.inferPackage(dir)
		if packagePath != "" {
			collected.notePackage(packagePath, "", false)
		}
		return packagePath
	}
	riskyFlags := map[string]bool{}
	riskCategories := map[string]bool{}
	for path, valid := range sysoVerdict {
		evidence.SysoCount++
		owner := ownerOf(path)
		summary := collected.packages[owner]
		if !valid {
			evidence.SysoInvalidCount++
			riskCategories[native.CategoryInvalidObject] = true
			if summary != nil {
				summary.SysoInvalidCount++
				summary.RiskCategories = append(summary.RiskCategories, native.CategoryInvalidObject)
			}
		}
		if summary != nil {
			summary.SysoCount++
		}
		attachment.artifactsByPackage[owner] = append(attachment.artifactsByPackage[owner], model.NativeArtifact{
			Path:       path,
			Kind:       "native-object",
			Extension:  ".syso",
			Properties: map[string]string{"objectHeaderValid": boolLabel(valid)},
		})
	}
	for _, record := range collected.files {
		evidence.FileCount++
		if summary := collected.packages[record.packagePath]; summary != nil {
			summary.FileCount++
		}
		if record.packagePath != "" {
			attachment.directivesByPackage[record.packagePath] = append(attachment.directivesByPackage[record.packagePath], record.directives...)
			attachment.signalsByPackage[record.packagePath] = append(attachment.signalsByPackage[record.packagePath], record.signals...)
		}
		for _, directive := range record.directives {
			evidence.DirectiveCount++
			if directive.Variable == "pkg-config" {
				evidence.PkgConfigCount++
				if summary := collected.packages[record.packagePath]; summary != nil {
					summary.PkgConfigCount++
				}
			}
			if summary := collected.packages[record.packagePath]; summary != nil {
				summary.DirectiveCount++
				summary.RiskCategories = append(summary.RiskCategories, directive.Categories...)
			}
		}
		for _, risk := range record.risks {
			for _, category := range risk.Categories {
				riskCategories[category] = true
			}
			if !onlyInformational(risk.Categories) {
				riskyFlags[risk.Name] = true
				if summary := collected.packages[record.packagePath]; summary != nil {
					summary.RiskyFlags = append(summary.RiskyFlags, risk.Name)
				}
			}
		}
	}
	for _, summary := range collected.packages {
		summary.RiskCategories = sortedUnique(summary.RiskCategories)
		summary.RiskyFlags = sortedUnique(summary.RiskyFlags)
		if !summary.Loaded {
			evidence.UnloadedPackageCount++
		}
		evidence.Packages = append(evidence.Packages, *summary)
	}
	sort.Slice(evidence.Packages, func(i, j int) bool { return evidence.Packages[i].PackagePath < evidence.Packages[j].PackagePath })
	evidence.PackageCount = len(evidence.Packages)
	evidence.RiskyFlags = sortedKeys(riskyFlags)
	evidence.RiskCategories = sortedKeys(riskCategories)
	evidence.RiskyFlagCount = len(evidence.RiskyFlags)
	return evidence, attachment
}

func boolLabel(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// onlyInformational reports whether every category is the module-path one, the
// one category that describes an ordinary flag whose target is merely local.
func onlyInformational(categories []string) bool {
	for _, category := range categories {
		if category != native.CategoryModulePath {
			return false
		}
	}
	return len(categories) > 0
}

// underPath reports whether path names something inside root, both absolute
// and cleaned by the caller.
// underVendor reports whether path lies in a vendor directory of the module
// rooted at moduleRoot. Vendored dependencies are part of the build, so a
// go.mod copied into one does not make it a separate module.
func underVendor(moduleRoot, path string) bool {
	rel, err := filepath.Rel(moduleRoot, path)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "vendor" {
			return true
		}
	}
	return false
}

func underPath(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// cgoFlagDisplayName renders one #cgo value token as the name a report may
// carry: quotes are gone, "=" values are cut, and a token that still looks
// like a path or a command file is dropped rather than published.
func cgoFlagDisplayName(value, variable string) string {
	name := strings.Trim(value, `"'`)
	if variable == "pkg-config" {
		if strings.HasPrefix(name, "--") {
			if base, _, ok := strings.Cut(name, "="); ok {
				name = base
			}
			return name
		}
		if name == "" || strings.ContainsAny(name, `/\: `) || strings.Contains(name, "..") || strings.HasPrefix(name, "-") {
			return ""
		}
		return name
	}
	if name == "" || strings.HasPrefix(name, "@") || strings.Contains(name, `"`) {
		return ""
	}
	if base, _, ok := strings.Cut(name, "="); ok {
		name = base
	}
	if strings.ContainsAny(name, `/\ `) {
		// Joined path flags reduce to the flag; anything else that still
		// holds a separator is a path and not a name.
		if prefix, ok := joinedFlagPrefix(name); ok {
			return prefix
		}
		return ""
	}
	return name
}

// joinedFlagPrefix reduces "-I/usr/include" to "-I" for the short flags that
// glue their path argument on.
func joinedFlagPrefix(name string) (string, bool) {
	for _, prefix := range []string{"-I", "-L", "-F", "-B", "-isysroot"} {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			return prefix, true
		}
	}
	return "", false
}

// importsC is the cheap pre-filter: cgo admits exactly one spelling of the
// import, so the bytes either contain it or the parser will say no.
func importsC(data []byte) bool {
	return strings.Contains(string(data), `import "C"`)
}

// fileImportsC reports whether a parsed file imports C.
func fileImportsC(file *ast.File) bool {
	for _, spec := range file.Imports {
		if strings.Trim(spec.Path.Value, `"`) == "C" {
			return true
		}
	}
	return false
}

// preambleLines splits a raw comment into the lines its author wrote.
func preambleLines(text string) []string {
	text = strings.TrimPrefix(text, "//")
	text = strings.TrimPrefix(text, "/*")
	text = strings.TrimSuffix(text, "*/")
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*"))
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// goModModulePath reads the module path from go.mod content.
func goModModulePath(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module"); ok {
			rest = strings.TrimSpace(rest)
			if rest != "" && !strings.HasPrefix(rest, "//") {
				return strings.Trim(rest, `"`)
			}
		}
	}
	return ""
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ensureTextualFile returns the file evidence for a file only the textual cgo
// read saw, creating it on first use.
func ensureTextualFile(files map[string]*model.FileEvidence, path, packagePath string) *model.FileEvidence {
	if files[path] != nil {
		return files[path]
	}
	generated, generatedBy := generatedInfo(path)
	files[path] = &model.FileEvidence{
		Path:        path,
		PackagePath: packagePath,
		Role:        fileRole(path),
		TestFile:    fileRole(path) != "runtime",
		Generated:   generated,
		GeneratedBy: generatedBy,
	}
	return files[path]
}

// gocacheDir returns the build cache directory, falling back to the default
// location when the probe could not answer. The fallback keeps build-cache
// paths out of the report even on a probe failure.
func gocacheDir(target buildTarget) string {
	if dir := strings.TrimSpace(target.GOCACHE); dir != "" {
		return filepath.Clean(dir)
	}
	if cache, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cache, "go-build")
	}
	return ""
}

// reportableSource reports whether a file may be named in the report: source
// lives in the analysed module or the module cache, and everything else
// (cgo-generated files under the build cache, in particular) is derived
// output whose absolute path would also leak the analyst's home directory.
func (a *Analyzer) reportableSource(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	if underPath(clean, filepath.Clean(a.options.Dir)) {
		return true
	}
	if a.modcache != "" && underPath(clean, a.modcache) {
		return true
	}
	return false
}

// warnUnpatchedCgoToolchain prints the one warning an analyst who explicitly
// enabled cgo on an unpatched toolchain gets: the analysed tree can run
// commands through the C compiler that build it.
func warnUnpatchedCgoToolchain(options Options, version string) {
	writer := options.ProgressWriter
	if writer == nil {
		writer = os.Stderr
	}
	fmt.Fprintf(writer, "golem: warning: CGO_ENABLED is set and toolchain %s predates the cgo flag checks fixed in go1.26.11 and go1.27.4; #cgo directives in the analysed tree can run commands on this host\n", version)
}
