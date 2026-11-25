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
	pinned    bool           // every Go pointer stored in the scanned memory was pinned first
	loopPin   bool           // the function pinned values inside a loop before the call
	addressed bool           // the argument took an address
	deref     bool           // the address went through a field or element of object, so a pointer-typed object is dereferenced first
	reach     types.Type     // the type of the memory C receives, which bounds what C can walk
	sym       string         // C symbol, from the closure's _Cfunc_ call
	pkg       *packages.Package
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
		// A nested function literal is its own rewritten call (cgo nests them
		// for a deferred C call and for a C call inside a closure), and the
		// caller visits it on its own; descending here would report its
		// checks twice.
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
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
		if argIdent == nil {
			continue
		}
		arg, ok := facts.lookup(argIdent.Name, argIdent.Pos())
		if !ok {
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
		object, addressed, deref := cgoCheckedObject(arg, event)
		owner := cgoOwnerUnknown
		if cgoIsCRooted(arg, event, 0) {
			owner = cgoOwnerC
		} else if object != nil {
			owner = cgoOwnerGo
			// A Go field or variable typed as a C pointer holds a C handle:
			// the scan stops at non-Go memory even though the value never
			// passed through a C call in this function.
			objectType := pkg.TypesInfo.TypeOf(object)
			if cgoIsCPointer(objectType) {
				owner = cgoOwnerC
			} else if !addressed && objectType != nil {
				// An unsafe.Pointer value whose origin this function does not
				// show (a parameter, a struct field, a helper's result) may
				// point at C memory as easily as Go memory: go-sqlite3 keeps
				// C.malloc'd handles and buffers in exactly such fields.
				if basic, ok := types.Unalias(objectType).Underlying().(*types.Basic); ok && basic.Kind() == types.UnsafePointer {
					owner = cgoOwnerUnknown
				}
			}
		}
		// The pin state the same function body shows. A bounded check needs
		// the pointer stored at the passed address pinned; an untyped check
		// scans the whole object, so it needs every pointer field of that
		// object pinned, which only the types can enumerate.
		pinnedSet, loopPin := functionFacts.pinnedBefore(check.Pos())
		pinned := false
		if owner == cgoOwnerGo {
			if untyped {
				pinned = cgoScanPinned(pkg.TypesInfo, object, addressed, deref, pinnedSet)
			} else {
				pinned = cgoStoredPointerPinned(arg, facts, argIdent.Pos(), pinnedSet)
			}
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
			loopPin:   loopPin,
			reach:     cgoReachType(pkg.TypesInfo, arg, facts),
			addressed: addressed,
			deref:     deref,
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
	// seen marks the arguments cgo emitted any check for; finding marks the
	// ones that are findings: a nil-typed check of memory that is not C's.
	// A textual finding is kept only where the compiled check agrees, so a
	// bounded check or a C-owned argument refutes it.
	seen := map[key]bool{}
	finding := map[key]bool{}
	// Additions are held apart from the record's signals until every
	// confirmation is done: appending during the loop could reallocate the
	// backing array and leave the textual map pointing at a stale copy.
	var additions []model.SecuritySignal
	for _, check := range checks {
		k := key{check.line, check.col}
		seen[k] = true
		if check.untyped && check.owner != cgoOwnerC {
			finding[k] = true
			if signal, ok := textual[k]; ok {
				// The textual finding was right; the compiled record upgrades it.
				signal.Confidence = "high"
				signal.PackagePath = check.pkg.PkgPath
				if check.sym != "" {
					signal.Symbol = "C." + check.sym
				}
				signal.Properties = map[string]string{}
				a.escalate(check, &signal.Severity, signal.Properties)
			} else {
				// The approximation could not see this one; the compiled
				// record wins.
				additions = append(additions, a.compiledFinding(check, argsByPos[k]))
			}
		}
		if argument, ok := argsByPos[k]; ok {
			if check.untyped {
				argument.Shape = cgoShapeUntyped
			} else if argument.Shape == cgoShapeUntyped || argument.Shape == cgoShapeNoCheck {
				// cgo bounded the check where the text could not tell.
				argument.Shape, _ = cgoCheckShape(check.arg)
			}
			if check.owner != cgoOwnerUnknown {
				argument.Owner = check.owner
			}
			argument.Pinned = check.owner == cgoOwnerGo && check.pinned
			if site := siteByArg[k]; site != nil {
				site.Confidence = "high"
			}
		}
	}
	if len(additions) > 0 {
		record.pointer.signals = append(record.pointer.signals, additions...)
	}
	// On a file whose cgo step ran, the compiled checks are the whole truth:
	// an argument with no check was not checked, and a textual finding the
	// compiled pass did not keep is the approximation over-firing.
	if covered {
		for si := range record.pointer.callSites {
			site := &record.pointer.callSites[si]
			for ai := range site.Arguments {
				argument := &site.Arguments[ai]
				if argument.Position == nil || argument.Shape != cgoShapeUntyped {
					continue
				}
				if !seen[key{argument.Position.Line, argument.Position.Column}] {
					argument.Shape = cgoShapeNoCheck
					argument.Owner = cgoOwnerUnknown
				}
			}
		}
		kept := record.pointer.signals[:0]
		for _, signal := range record.pointer.signals {
			if signal.Category == CgoCategoryUntypedCheck && !finding[key{signal.Range.Start.Line, signal.Range.Start.Column}] {
				continue
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
	if check.owner == cgoOwnerUnknown {
		// cgo emits the untyped check, but whether the runtime scans anything
		// depends on memory the analysis cannot attribute; if it is C's, the
		// check returns at once. Reported, at low severity, so the reader can
		// see the call and decide.
		*severity = "low"
		props["memoryOwner"] = cgoOwnerUnknown
		return
	}
	if check.pkg != nil && check.pkg.TypesInfo != nil && check.object != nil {
		if cgoIsCPointer(check.pkg.TypesInfo.TypeOf(check.object)) {
			return
		}
	}
	if check.pinned {
		// Every pointer the scan can meet was pinned, so it cannot panic; the
		// expensive scan still runs, so the finding stays, at medium severity.
		props["pinned"] = "true"
		return
	}
	t := check.scannedType()
	if t == nil {
		return
	}
	slots, hasPointer, bounded := cgoObjectPointerSlots(t, map[types.Type]bool{}, 0)
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
func cgoCheckedObject(arg ast.Expr, event *cgoCallEvent) (object ast.Expr, addressed, deref bool) {
	expr := arg
	for depth := 0; depth < 8; depth++ {
		switch e := expr.(type) {
		case *ast.Ident:
			// Before an address is taken the identifier holds the pointer
			// (p := unsafe.Pointer(&s.f)) and its definition leads on. After
			// it, the identifier is the object whose memory is scanned, and
			// its definition (s := &T{}) is how it was made, not what it is.
			// A definition that is a function's result (buf := buffer()) says
			// nothing more than the identifier's own type does, so the chase
			// stops at the identifier there too.
			if !addressed && event.facts != nil {
				if def, ok := event.facts.lookup(e.Name, e.Pos()); ok && cgoIsPointerExpr(def) {
					expr = def
					continue
				}
			}
			return e, addressed, deref
		case *ast.CallExpr:
			// A C wrapper call result is C memory; the chase stops. Any
			// other single-argument call is a conversion to unwrap.
			if !isCgoWrapperCall(e) && !cgoIsCRooted(e, event, 0) && len(e.Args) == 1 {
				expr = e.Args[0]
				continue
			}
			return nil, addressed, deref
		case *ast.ParenExpr:
			expr = e.X
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				expr = e.X
				addressed = true
				continue
			}
			return nil, addressed, deref
		case *ast.SelectorExpr:
			// &s.f scans s: the object is the receiver, and when s is a
			// pointer the selector dereferenced it, so the scanned memory is
			// *s. Without an address of, the selector IS the value C receives
			// (a handle field such as c.db), and its own type is the pointee.
			if !addressed {
				return e, addressed, deref
			}
			expr = e.X
			deref = true
		case *ast.IndexExpr:
			// &a[i] scans a's backing array, through a pointer to an array
			// the same way a selector goes through a pointer to a struct.
			expr = e.X
			addressed = true
			deref = true
		case *ast.SliceExpr:
			expr = e.X
			addressed = true
			deref = true
		default:
			return nil, addressed, deref
		}
	}
	return nil, addressed, deref
}

// scannedType is the type of the memory the runtime check covers. An
// addressed argument scans the object it took the address in, dereferenced
// when it reached a field or element through a pointer-typed object
// (s := &T{}; &s.f scans a T, not a *T). An argument that is itself a pointer
// value scans what it points to: a *T scans a T, and an unsafe.Pointer scans
// memory whose type the analysis cannot know, so it answers nil and no
// escalation is claimed.
func (check cgoCompiledCheck) scannedType() types.Type {
	if check.pkg == nil || check.pkg.TypesInfo == nil || check.object == nil {
		return nil
	}
	return cgoScannedType(check.pkg.TypesInfo.TypeOf(check.object), check.addressed, check.deref)
}

func cgoScannedType(t types.Type, addressed, deref bool) types.Type {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if addressed && !deref {
		return t
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return types.Unalias(u.Elem())
	case *types.Basic:
		if u.Kind() == types.UnsafePointer {
			return nil
		}
	}
	return t
}

// cgoReachType is the type of the memory C receives: for &E the type of E
// (the field or variable, not the object around it, because C is handed
// that field), for a slice the element type, and for a pointer value its
// pointee. An unsafe.Pointer value whose origin the function does not show
// has no knowable pointee and answers nil.
func cgoReachType(info *types.Info, arg ast.Expr, facts *cgoFunctionFacts) types.Type {
	if info == nil {
		return nil
	}
	expr := arg
	for depth := 0; depth < 8; depth++ {
		expr = cgoUnparen(expr)
		switch e := expr.(type) {
		case *ast.CallExpr:
			if len(e.Args) == 1 && (cgoIsType(e.Fun) || cgoIsUnsafeData(e.Fun, false)) {
				expr = e.Args[0]
				continue
			}
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				if t := info.TypeOf(e.X); t != nil {
					return types.Unalias(t)
				}
				return nil
			}
		case *ast.Ident:
			if facts != nil {
				if def, ok := facts.lookup(e.Name, e.Pos()); ok {
					expr = def
					continue
				}
			}
		}
		t := info.TypeOf(expr)
		if t == nil {
			return nil
		}
		switch u := types.Unalias(t).Underlying().(type) {
		case *types.Pointer:
			return types.Unalias(u.Elem())
		case *types.Slice:
			return types.Unalias(u.Elem())
		}
		return nil
	}
	return nil
}

// cgoScanPinned reports whether an untyped check of object cannot meet an
// unpinned Go pointer: the scanned type is a struct whose every pointer-shaped
// field is a plain pointer the function pinned as Pin(object.field) before
// the call. A field of any other pointer-shaped kind (a slice, a string, a
// map, an interface, a nested struct holding pointers) cannot be verified
// from one function body, so it answers false; a type with no pointer at all
// answers false too, because there is nothing to pin and escalate already
// keeps it at medium.
func cgoScanPinned(info *types.Info, object ast.Expr, addressed, deref bool, pinned map[string]bool) bool {
	if info == nil || object == nil || len(pinned) == 0 {
		return false
	}
	t := cgoScannedType(info.TypeOf(object), addressed, deref)
	if t == nil {
		return false
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	base := types.ExprString(cgoUnparen(object))
	fields := 0
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		_, hasPointer, _ := cgoObjectPointerSlots(field.Type(), map[types.Type]bool{}, 0)
		if !hasPointer {
			continue
		}
		if _, isPtr := types.Unalias(field.Type()).Underlying().(*types.Pointer); !isPtr {
			return false
		}
		if !pinned[base+"."+field.Name()] {
			return false
		}
		fields++
	}
	return fields > 0
}

// cgoIsPointerExpr reports whether a definition derives a pointer from
// another value the chase can follow: an address, a conversion, a field, an
// element, a slice, another name, or a C call (whose result ends the chase
// as C memory).
func cgoIsPointerExpr(expr ast.Expr) bool {
	switch e := cgoUnparen(expr).(type) {
	case *ast.UnaryExpr:
		return e.Op == token.AND
	case *ast.CallExpr:
		if isCgoWrapperCall(e) {
			return true
		}
		if _, ok := cgoCallOf(e); ok {
			return true
		}
		return len(e.Args) == 1 && (cgoIsType(e.Fun) || cgoIsUnsafeData(e.Fun, false))
	case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.SliceExpr:
		return true
	}
	return false
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
	if check.owner != cgoOwnerGo || check.reach == nil {
		return
	}
	t := check.reach
	// The pointers stored in the memory C receives are the first level the
	// check follows; their targets' pointers are the second.
	recursive := cgoTypeRecursive(t, map[types.Type]bool{}, 0)
	depth := cgoPointerChainDepth(t, map[types.Type]bool{}, 0, 0)
	if !recursive && depth <= cgoCheckFollowsLevels {
		return
	}
	// Pinning the first node does not cover the rest of a recursive
	// structure; pinning inside a loop is how code walks a list to pin every
	// node, so that, and only that, silences a recursive type. A finite chain
	// deeper than the check needs its third level pinned, which one function
	// body cannot be shown to do from the pins the check itself requires, so
	// it is always reported.
	if recursive && check.loopPin {
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
	if strings.HasPrefix(named.Obj().Name(), "_Ctype_") {
		return true
	}
	// `type SQLiteContext C.sqlite3_context` gives a Go name to a C struct:
	// go/types shares the underlying struct between the two names, so the
	// identity of that struct is what still marks the memory as C's. Only
	// structs are matched; a basic underlying type such as int32 is shared
	// with every Go type of that kind.
	st, ok := named.Underlying().(*types.Struct)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	scope := named.Obj().Pkg().Scope()
	for _, name := range scope.Names() {
		if !strings.HasPrefix(name, "_Ctype_") {
			continue
		}
		if obj, ok := scope.Lookup(name).(*types.TypeName); ok && obj.Type().Underlying() == st {
			return true
		}
	}
	return false
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
