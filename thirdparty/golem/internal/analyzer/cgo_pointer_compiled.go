package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// The compiled pass. With CGO_ENABLED=1 the loader type-checks the
// cgo-generated files, and every rewritten call carries the literal
// _cgoCheckPointer calls cgo chose, inside an immediately invoked closure.
// Reading those calls is exact: whether an argument was checked at all, and
// whether the check carried type information, is what cgo itself decided.
// Positions in the generated files carry /*line*/ directives that resolve
// back to the original source, which this pass relies on and the fixture
// suite verifies.
//
// The pass confirms, refutes or adds to the textual findings: a textual
// untyped finding with a nil-typed compiled check at the same argument
// position is confirmed and escalated with type information; one without is
// the approximation over-firing and is dropped on a file whose cgo step ran;
// a compiled nil check with no textual finding is a case the approximation
// could not see (an argument of unsafe.Pointer type with no unsafe.Pointer
// conversion in sight), and the compiled record is preferred.

// cgoCompiledCheck is one _cgoCheckPointer call found in generated code,
// resolved to the original coordinates and values it guards.
type cgoCompiledCheck struct {
	file      string         // the original source file the check's position resolves to
	line      int            // the checked argument's original position; the join key
	col       int            // with the textual records, because the /*line*/
	argPos    model.Position // directives pin the generated code to it
	untyped   bool           // the second argument is nil
	arg       ast.Expr       // the defining expression of the checked value
	object    ast.Expr       // the object whose memory the runtime scan covers
	owner     string         // go, c or unknown, from the generated definitions
	pinned    bool           // the value was passed to a Pinner earlier in the function
	addressed bool           // the argument took an address, so the object type is the pointee
	sym       string         // C symbol, from the closure's _Cfunc_ call
	pkg       *packages.Package
}

// cgoPinnedBefore reports whether every identifier the expression is rooted
// in was passed to a Pinner earlier in the same function, with no Unpin of
// that pinner in between. Intraprocedural and path-insensitive, like the
// textual walk's pin record.
func cgoPinnedBefore(facts *cgoFunctionFacts, pos token.Pos, arg ast.Expr) bool {
	bases := cgoBaseIdents(arg, &cgoCallEvent{facts: facts}, 0)
	if len(bases) == 0 {
		return false
	}
	lastUnpin := token.NoPos
	for _, pin := range facts.pins {
		if pin.pos >= pos {
			break
		}
		if pin.unpin {
			lastUnpin = pin.pos
			continue
		}
		if lastUnpin != token.NoPos && pin.pos < lastUnpin {
			continue
		}
		for target := range pin.targets {
			delete(bases, target)
		}
	}
	return len(bases) == 0
}

// mergeCompiledPointerChecks walks the generated files of every loaded cgo
// package and folds the compiled verdicts into the textual records.
func (a *Analyzer) mergeCompiledPointerChecks(collected *cgoEvidence, pkgs []*packages.Package) {
	if a.gocache == "" || a.fset == nil {
		return
	}
	seenPkg := map[string]bool{}
	covered := map[string]bool{} // original files whose cgo step ran and was walked
	var checks []cgoCompiledCheck
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if pkg == nil || seenPkg[pkg.ID] {
			return
		}
		seenPkg[pkg.ID] = true
		if !a.packageCompiledWithCgo(pkg) {
			return
		}
		// pkg.Syntax parallels pkg.CompiledGoFiles entry for entry, which is
		// the only reliable way to name the generated files: the leading
		// //line directive of a cgo-generated file makes fset.Position
		// resolve its package clause to the ORIGINAL source, so positions
		// cannot identify the file they belong to.
		generated := false
		for i, file := range pkg.Syntax {
			if i >= len(pkg.CompiledGoFiles) || !underPath(filepath.Clean(pkg.CompiledGoFiles[i]), a.gocache) {
				continue
			}
			found := a.collectCompiledChecks(file, pkg, &checks)
			generated = generated || found
		}
		if generated {
			for _, original := range pkg.GoFiles {
				covered[filepath.Clean(original)] = true
			}
		}
	})
	// Group by the source file the checks resolve to, so the merge stays per
	// textual record.
	byFile := map[string][]cgoCompiledCheck{}
	for _, check := range checks {
		if _, ok := collected.files[check.file]; !ok {
			continue
		}
		byFile[check.file] = append(byFile[check.file], check)
	}
	for path, fileChecks := range byFile {
		record := collected.files[path]
		a.mergeFileCompiledChecks(record, fileChecks, true)
	}
	// Files the walk covered but no check mentions: their textual untyped
	// findings are refutations and their guessed arguments are unchecked.
	for _, record := range collected.files {
		if _, has := byFile[record.path]; has {
			continue
		}
		if covered[filepath.Clean(record.path)] {
			a.mergeFileCompiledChecks(record, nil, true)
		}
	}
}

// collectCompiledChecks walks one generated file and pulls the
// _cgoCheckPointer calls out of their closures.
func (a *Analyzer) collectCompiledChecks(file *ast.File, pkg *packages.Package, out *[]cgoCompiledCheck) bool {
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// Facts of the enclosing function: the closure's argument expression
		// names identifiers (a C.CString result, an unsafe.Pointer variable)
		// defined outside it, so owner resolution chains the closure facts
		// into the function facts.
		outer := cgoCollectFacts(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			literal, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			inner := cgoCollectFacts(literal.Body)
			inner.parent = outer
			// The pin state comes from the function facts: they collected the
			// whole body, closures included, so a Pin outside the closure is
			// visible where the closure's own facts would miss it.
			a.collectClosureChecks(literal, inner, outer, pkg, out, &found)
			return true
		})
	}
	return found
}

// collectClosureChecks pairs the _cgoCheckPointer calls of one rewritten call
// closure with the C call they guard. cgo writes the checks first and the C
// call last, so each check pairs with the first _Cfunc_ call at or after its
// position.
func (a *Analyzer) collectClosureChecks(literal *ast.FuncLit, facts, functionFacts *cgoFunctionFacts, pkg *packages.Package, out *[]cgoCompiledCheck, found *bool) {
	var cCalls []struct {
		pos token.Pos
		sym string
	}
	var checkCalls []*ast.CallExpr
	ast.Inspect(literal.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			if id.Name == "_cgoCheckPointer" && len(call.Args) >= 1 {
				checkCalls = append(checkCalls, call)
				return true
			}
			if symbol, ok := trimCgoWrapperName(id.Name); ok && symbol != "" {
				cCalls = append(cCalls, struct {
					pos token.Pos
					sym string
				}{call.Pos(), symbol})
			}
		}
		return true
	})
	for _, check := range checkCalls {
		sym := ""
		for _, c := range cCalls {
			if c.pos >= check.Pos() {
				sym = c.sym
				break
			}
		}
		// The first argument names the _cgo value the check sees; its
		// defining assignment in the closure holds the original argument
		// expression under a /*line*/ directive.
		argIdent, _ := check.Args[0].(*ast.Ident)
		if argIdent == nil || facts.setTwice[argIdent.Name] {
			continue
		}
		arg := facts.defs[argIdent.Name]
		if arg == nil {
			continue
		}
		untyped := false
		if len(check.Args) > 1 {
			if id, ok := check.Args[1].(*ast.Ident); ok && id.Name == "nil" {
				untyped = true
			}
		}
		argPos := a.fset.Position(arg.Pos())
		if !argPos.IsValid() {
			continue
		}
		event := &cgoCallEvent{facts: facts}
		object, addressed := cgoCheckedObject(arg, event)
		owner := cgoOwnerUnknown
		if cgoIsCRooted(arg, event, 0) {
			owner = cgoOwnerC
		} else if object != nil {
			owner = cgoOwnerGo
			// A Go field or variable typed as a C pointer holds a C handle:
			// the scan stops at non-Go memory even though the value never
			// passed through a C call in this function.
			if cgoIsCPointer(pkg.TypesInfo.TypeOf(object)) {
				owner = cgoOwnerC
			}
		}
		// The pin state the same function body shows: a value pinned before
		// the check cannot panic the scan, which is what the escalation
		// records.
		pinned := false
		if owner == cgoOwnerGo {
			pinned = cgoPinnedBefore(functionFacts, check.Pos(), arg)
		}
		*found = true
		*out = append(*out, cgoCompiledCheck{
			file:      argPos.Filename,
			line:      argPos.Line,
			col:       argPos.Column,
			argPos:    model.Position{Filename: argPos.Filename, Line: argPos.Line, Column: argPos.Column},
			untyped:   untyped,
			arg:       arg,
			object:    object,
			owner:     owner,
			pinned:    pinned,
			addressed: addressed,
			sym:       sym,
			pkg:       pkg,
		})
	}
}

// mergeFileCompiledChecks folds one file's compiled verdicts into its textual
// records: findings are confirmed and escalated, refuted ones are dropped,
// and the call-site arguments are corrected to what cgo actually emitted.
// checks holds the compiled checks for this file; covered states whether the
// cgo step ran for it and was walked, which decides whether a textual finding
// without a compiled check is a refutation or an open question.
func (a *Analyzer) mergeFileCompiledChecks(record *cgoFile, checks []cgoCompiledCheck, covered bool) {
	if record.pointer == nil {
		return
	}
	type key struct {
		line, col int
	}
	textual := map[key]*model.SecuritySignal{}
	for i := range record.pointer.signals {
		signal := &record.pointer.signals[i]
		if signal.Category == CgoCategoryUntypedCheck {
			textual[key{signal.Range.Start.Line, signal.Range.Start.Column}] = signal
		}
	}
	argsByPos := map[key]*model.NativeCallArgument{}
	siteByArg := map[key]*model.NativeCallSite{}
	for si := range record.pointer.callSites {
		site := &record.pointer.callSites[si]
		for ai := range site.Arguments {
			argument := &site.Arguments[ai]
			if argument.Position != nil {
				k := key{argument.Position.Line, argument.Position.Column}
				argsByPos[k] = argument
				siteByArg[k] = site
			}
		}
	}
	confirmed := map[key]bool{}
	// Additions are held apart from the record's signals until every
	// confirmation is done: appending during the loop could reallocate the
	// backing array and leave the textual map pointing at a stale copy, the
	// bug this ordering exists to avoid.
	var additions []model.SecuritySignal
	for _, check := range checks {
		k := key{check.line, check.col}
		if signal, ok := textual[k]; ok {
			// The textual finding was right; the compiled record upgrades it.
			signal.Confidence = "high"
			signal.PackagePath = check.pkg.PkgPath
			if check.sym != "" {
				signal.Symbol = "C." + check.sym
			}
			signal.Properties = map[string]string{}
			a.escalate(check, &signal.Severity, signal.Properties)
			confirmed[k] = true
		} else if check.untyped && check.owner != cgoOwnerC {
			// No textual finding here and the check is nil-typed: the
			// approximation could not see it and the compiled record wins.
			// C-owned arguments are never findings: the runtime stops at
			// non-Go memory, whatever check cgo emitted.
			argument := argsByPos[k]
			additions = append(additions, a.compiledFinding(check, argument))
			confirmed[k] = true
		} else {
			// A bounded check the textual shape already describes.
			confirmed[k] = true
		}
		if argument, ok := argsByPos[k]; ok {
			if check.untyped {
				argument.Shape = cgoShapeUntyped
			}
			if check.owner != cgoOwnerUnknown {
				argument.Owner = check.owner
			}
			if site := siteByArg[k]; site != nil {
				site.Confidence = "high"
			}
		}
	}
	if len(additions) > 0 {
		record.pointer.signals = append(record.pointer.signals, additions...)
	}
	// A textual finding whose argument no compiled check covers is the
	// approximation over-firing, final on a file whose cgo step ran.
	if covered {
		for si := range record.pointer.callSites {
			site := &record.pointer.callSites[si]
			for ai := range site.Arguments {
				argument := &site.Arguments[ai]
				if argument.Position == nil || argument.Shape != cgoShapeUntyped {
					continue
				}
				if !confirmed[key{argument.Position.Line, argument.Position.Column}] {
					argument.Shape = cgoShapeNoCheck
					argument.Owner = cgoOwnerUnknown
				}
			}
		}
		kept := record.pointer.signals[:0]
		for _, signal := range record.pointer.signals {
			if signal.Category == CgoCategoryUntypedCheck {
				if !confirmed[key{signal.Range.Start.Line, signal.Range.Start.Column}] {
					continue
				}
			}
			kept = append(kept, signal)
		}
		record.pointer.signals = kept
	}
	// Reachable but unpinned: for every argument whose memory Go owns and
	// whose value was not pinned, the pointee's type says whether C can walk
	// past what cgo's two-level check covers. This needs type information, so
	// it only runs on compiled evidence; the textual read has no types and
	// stays silent rather than guess.
	// Bounded and untyped checks alike: the two-level question is about the
	// type behind the argument, not about which shape the check used.
	for _, check := range checks {
		a.maybeUnpinnedReachableFinding(record, check)
	}
}

// compiledFinding builds the signal for a nil-typed check the textual pass
// had no finding for. The owner comes from the generated definitions, which
// is exact evidence rather than the textual approximation.
func (a *Analyzer) compiledFinding(check cgoCompiledCheck, argument *model.NativeCallArgument) model.SecuritySignal {
	severity := "medium"
	props := map[string]string{}
	a.escalate(check, &severity, props)
	return model.SecuritySignal{
		ID:             stableID("cgo-untyped-check", check.pkg.PkgPath, check.file, strconv.Itoa(check.line)+":"+strconv.Itoa(check.col), "compiled"),
		Category:       CgoCategoryUntypedCheck,
		Severity:       severity,
		Confidence:     "high",
		PackagePath:    check.pkg.PkgPath,
		Symbol:         "C." + check.sym,
		Description:    "cgo checks this argument with no type information: the runtime scans the entire heap object behind the pointer and panics when any pointer field of that object holds an unpinned Go pointer.",
		Recommendation: "Take the address inside the call, for example C.f(unsafe.Pointer(&s.field)), so cgo checks only that field, or pass memory C owns.",
		Range:          model.Range{Start: model.Position{Filename: check.file, Line: check.line, Column: check.col}, End: model.Position{Filename: check.file, Line: check.line, Column: check.col}},
		Properties:     props,
	}
}

// escalateCompiledSignal upgrades a confirmed textual finding with the type
// information the generated files carry.
func (a *Analyzer) escalateCompiledSignal(signal *model.SecuritySignal, check cgoCompiledCheck) {
	props := signal.Properties
	if props == nil {
		props = map[string]string{}
		signal.Properties = props
	}
	a.escalate(check, &signal.Severity, props)
}

// escalate sets the severity and properties of one finding from the type of
// the object behind the checked argument: an object with pointer-shaped
// slots can panic the runtime scan (severity high, panicRisk), and the slot
// count says what the scan costs. Without type information the severity
// stays medium.
func (a *Analyzer) escalate(check cgoCompiledCheck, severity *string, props map[string]string) {
	if check.owner == cgoOwnerC {
		// cgoCheckPointer returns as soon as it sees non-Go memory; there is
		// nothing to scan and nothing to panic on.
		return
	}
	if check.pkg != nil && check.pkg.TypesInfo != nil && check.object != nil {
		if cgoIsCPointer(check.pkg.TypesInfo.TypeOf(check.object)) {
			return
		}
	}
	if check.pinned {
		// A pinned object cannot panic the scan; the expensive scan still
		// runs, so the finding stays, at medium severity.
		props["pinned"] = "true"
		return
	}
	if check.pkg == nil || check.pkg.TypesInfo == nil || check.object == nil {
		return
	}
	t := check.pkg.TypesInfo.TypeOf(check.object)
	if t == nil {
		return
	}
	slots, hasPointer, bounded := cgoObjectPointerSlots(types.Unalias(t), map[types.Type]bool{}, 0)
	if hasPointer {
		*severity = "high"
		props["panicRisk"] = "true"
	}
	// A bounded object names exactly how many slots the scan covers; a slice
	// of pointers covers an unknown count, which the flag says instead.
	if bounded && slots > 0 {
		props["pointerSlots"] = strconv.Itoa(slots)
	} else if hasPointer {
		props["pointerArray"] = "true"
	}
}

// cgoCheckedObject chases the checked argument's expression to the object
// whose memory the runtime scan covers: through the closure's _cgo names and
// the conversions to an address, whose receiver or base names the object.
// &s.f scans s (an untyped check), &a[i] and a[i:j] scan the backing array of
// a, and a C-rooted chase stops, because Go never scans C memory. An
// identifier without a visible definition names itself, which is what a
// function parameter looks like to the intraprocedural read.
func cgoCheckedObject(arg ast.Expr, event *cgoCallEvent) (object ast.Expr, addressed bool) {
	expr := arg
	for depth := 0; depth < 8; depth++ {
		switch e := expr.(type) {
		case *ast.Ident:
			if event.facts != nil {
				if def, ok := event.facts.lookup(e.Name); ok {
					expr = def
					continue
				}
			}
			return e, addressed
		case *ast.CallExpr:
			// A C wrapper call result is C memory; the chase stops. Any
			// other single-argument call is a conversion to unwrap.
			if !isCgoWrapperCall(e) && !cgoIsCRooted(e, event, 0) && len(e.Args) == 1 {
				expr = e.Args[0]
				continue
			}
			return nil, addressed
		case *ast.ParenExpr:
			expr = e.X
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				expr = e.X
				addressed = true
				continue
			}
			return nil, addressed
		case *ast.SelectorExpr:
			// &s.f scans s: the object is the receiver. Without an address
			// of, though, the selector IS the value C receives (a handle
			// field such as c.db), and its own type is the pointee.
			if !addressed {
				return e, addressed
			}
			expr = e.X
		case *ast.IndexExpr:
			// &a[i] scans a's backing array.
			expr = e.X
			addressed = true
		case *ast.SliceExpr:
			expr = e.X
			addressed = true
		default:
			return nil, addressed
		}
	}
	return nil, addressed
}

// isCgoWrapperCall reports whether the call invokes one of the _Cfunc_
// wrappers cgo generates, which is how C.* calls appear in generated code.
// The rewrite wraps the callee in a ParenExpr when a /*line*/ directive
// splits it, so the parentheses come off first.
func isCgoWrapperCall(call *ast.CallExpr) bool {
	fun := call.Fun
	for depth := 0; depth < 4; depth++ {
		paren, ok := fun.(*ast.ParenExpr)
		if !ok {
			break
		}
		fun = paren.X
	}
	id, ok := fun.(*ast.Ident)
	if !ok {
		return false
	}
	_, ok = trimCgoWrapperName(id.Name)
	return ok
}

// cgoObjectPointerSlots counts the pointer-shaped slots the runtime scan of
// one object covers, and reports whether any slot can hold an unpinned Go
// pointer. A struct contributes one slot per pointer-shaped field, arrays
// contribute their bound times the element slots, and slices, maps, channels,
// interfaces, functions and strings contribute the one word the scan sees of
// them. The count is the static view a report can carry; the runtime scan
// itself walks the whole span.
func cgoObjectPointerSlots(t types.Type, seen map[types.Type]bool, depth int) (slots int, hasPointer bool, isPointerArray bool) {
	if t == nil || depth > 8 {
		return 0, false, false
	}
	if seen[t] {
		return 0, false, false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		seen[t] = true
		defer delete(seen, t)
		for i := 0; i < u.NumFields(); i++ {
			fieldSlots, fieldPointer, _ := cgoObjectPointerSlots(u.Field(i).Type(), seen, depth+1)
			slots += fieldSlots
			hasPointer = hasPointer || fieldPointer
		}
		return slots, hasPointer, true
	case *types.Array:
		seen[t] = true
		defer delete(seen, t)
		elemSlots, elemPointer, _ := cgoObjectPointerSlots(u.Elem(), seen, depth+1)
		if bound := u.Len(); bound > 0 {
			return int(bound) * elemSlots, elemPointer, elemPointer
		}
		return elemSlots, elemPointer, false
	case *types.Pointer:
		return 1, true, true
	case *types.Slice:
		// The untyped checks golem flags point into the backing array, not
		// at the header, so the scan covers the elements. The length is
		// unknown, which is why the caller distinguishes a bounded array
		// (a slot count) from an unbounded one (a flag).
		seen[t] = true
		defer delete(seen, t)
		elemSlots, elemPointer, _ := cgoObjectPointerSlots(u.Elem(), seen, depth+1)
		return elemSlots, elemPointer, false
	case *types.Signature, *types.Interface, *types.Map, *types.Chan:
		return 1, true, true
	case *types.Basic:
		if u.Info()&types.IsString != 0 {
			return 1, true, true
		}
		if u.Kind() == types.UnsafePointer {
			return 1, true, true
		}
		return 0, false, true
	}
	return 0, false, false
}

// trimCgoWrapperName recovers the C symbol from a cgo wrapper function name,
// reporting whether the name was a wrapper at all. The generated closures
// call the wrappers directly.
func trimCgoWrapperName(name string) (string, bool) {
	for _, prefix := range []string{"_cgo_Cfunc_", "_Cfunc_"} {
		if strings.HasPrefix(name, prefix) {
			return strings.TrimPrefix(name, prefix), true
		}
	}
	return "", false
}

// maybeUnpinnedReachableFinding reports a C call argument whose pointed-to
// type is recursive or whose pointer chain exceeds the two levels cgo's check
// follows, when the enclosing function did not pin the value. Severity is
// medium and the confidence says type-resolved: the types are exact, the pin
// analysis is the intraprocedural one.
func (a *Analyzer) maybeUnpinnedReachableFinding(record *cgoFile, check cgoCompiledCheck) {
	if check.owner != cgoOwnerGo || check.pinned || check.object == nil {
		return
	}
	if check.pkg == nil || check.pkg.TypesInfo == nil {
		return
	}
	t := check.pkg.TypesInfo.TypeOf(check.object)
	if t == nil {
		return
	}
	// The object type is the pointee when the argument took an address, and
	// reaching its contents is the first hop; a value passed directly starts
	// its chain at its own type.
	startHops := 0
	if check.addressed {
		startHops = 1
	}
	recursive := cgoTypeRecursive(types.Unalias(t), map[types.Type]bool{}, 0)
	depth := cgoPointerChainDepth(types.Unalias(t), map[types.Type]bool{}, startHops, 0)
	if !recursive && depth <= cgoCheckFollowsLevels {
		return
	}
	signal := model.SecuritySignal{
		ID:             stableID("cgo-unpinned-reachable", check.pkg.PkgPath, check.file, strconv.Itoa(check.line)+":"+strconv.Itoa(check.col)),
		Category:       CgoCategoryUnpinnedReachable,
		Severity:       "medium",
		Confidence:     "type-resolved",
		PackagePath:    check.pkg.PkgPath,
		Symbol:         "C." + check.sym,
		Description:    "The type behind this argument is recursive or deeper than the two pointer levels cgo's check follows: C can walk nodes whose pinning golem cannot see verified.",
		Recommendation: "Pin every node C will read with runtime.Pinner, or copy the structure into C memory.",
		Range:          model.Range{Start: model.Position{Filename: check.file, Line: check.line, Column: check.col}, End: model.Position{Filename: check.file, Line: check.line, Column: check.col}},
		Properties:     map[string]string{},
	}
	if recursive {
		signal.Properties["recursive"] = "true"
	}
	if depth > cgoCheckFollowsLevels {
		signal.Properties["pointerChainDepth"] = strconv.Itoa(depth)
	}
	record.pointer.signals = append(record.pointer.signals, signal)
}

// cgoCheckFollowsLevels is the pointer depth cgo's runtime check covers: two
// levels of pointers from the value it receives.
const cgoCheckFollowsLevels = 2

// cgoIsCType reports whether the type is one of the _Ctype_ named types cgo
// synthesises for C types.
func cgoIsCType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	return strings.HasPrefix(named.Obj().Name(), "_Ctype_")
}

// cgoIsCPointer reports whether the type is a pointer to a C type, directly
// or through a Go named type defined over one (the wrapper pattern build-tag
// files use to keep one type name across platforms). The memory behind such
// a pointer is C-side, whatever the Go name on it is.
func cgoIsCPointer(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if cgoIsCType(t) {
		return false
	}
	ptr, ok := t.Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	return cgoIsCType(types.Unalias(ptr.Elem()))
}

// cgoTypeRecursive reports whether the type contains a pointer path back to
// itself: a struct with a field pointing to its own type, directly or
// through a slice, an array or another struct.
func cgoTypeRecursive(t types.Type, path map[types.Type]bool, depth int) bool {
	if t == nil || depth > 16 {
		return false
	}
	t = types.Unalias(t)
	if path[t] {
		return true
	}
	// A C type is C memory: what lies behind it is C's own structure and
	// never a Go node to pin.
	if cgoIsCType(t) {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return cgoTypeRecursive(u.Elem(), path, depth+1)
	case *types.Slice:
		return cgoTypeRecursive(u.Elem(), path, depth+1)
	case *types.Array:
		return cgoTypeRecursive(u.Elem(), path, depth+1)
	case *types.Struct:
		path[t] = true
		defer delete(path, t)
		for i := 0; i < u.NumFields(); i++ {
			if cgoTypeRecursive(u.Field(i).Type(), path, depth+1) {
				return true
			}
		}
	}
	return false
}

// cgoPointerChainDepth returns the largest number of pointer hops needed to
// walk every pointer reachable from t, where t is the type of the value the
// check received. A linked list needs unbounded hops, which the path set
// caps; the recursion detector above reports that case separately.
func cgoPointerChainDepth(t types.Type, seen map[types.Type]bool, hops int, depth int) int {
	if t == nil || depth > 16 {
		return hops
	}
	t = types.Unalias(t)
	if seen[t] {
		return hops
	}
	if cgoIsCType(t) {
		// C memory ends the Go-side walk: there is nothing behind it for the
		// pin recommendation to cover.
		return hops
	}
	seen[t] = true
	defer delete(seen, t)
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		next := cgoPointerChainDepth(u.Elem(), seen, hops+1, depth+1)
		if next > hops+1 {
			return next
		}
		return hops + 1
	case *types.Slice:
		// A slice header holds one pointer; the elements are walked at the
		// same hop the header costs.
		return cgoPointerChainDepth(u.Elem(), seen, hops+1, depth+1)
	case *types.Array:
		return cgoPointerChainDepth(u.Elem(), seen, hops, depth+1)
	case *types.Struct:
		best := hops
		for i := 0; i < u.NumFields(); i++ {
			if d := cgoPointerChainDepth(u.Field(i).Type(), seen, hops, depth+1); d > best {
				best = d
			}
		}
		return best
	}
	return hops
}
