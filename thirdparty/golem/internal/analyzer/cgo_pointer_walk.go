package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// The textual pointer-check walk. readCgoFile parses a cgo file fully, and
// this file classifies every C.f(...) call it contains: the shape cgo's
// pointer check will use for each argument, whose memory the argument points
// into, and whether the enclosing function pinned the value first. The
// results are the per-call-site records on the cgo evidence and, for the
// arguments checked with no type information, the cgo-pointer-check-untyped
// signals.
//
// Everything here is intraprocedural and path-insensitive, by construction:
// the textual read has no type information and no control-flow graph, only
// one parse of one file. Each approximation states its limit where it is
// made.

// Cgo pointer-check finding categories.
const (
	CgoCategoryUntypedCheck      = "cgo-pointer-check-untyped"
	CgoCategoryUnpinnedReachable = "cgo-unpinned-reachable"
	CgoCategoryGocheckDisabled   = "cgocheck-disabled"
	CgoCategoryGocheck2Enabled   = "cgocheck2-enabled"
)

// Memory owners a call-site argument can name.
const (
	cgoOwnerGo      = "go"
	cgoOwnerC       = "c"
	cgoOwnerUnknown = "unknown"
)

// cgoHelperChecks records, for the conversion helpers cgo synthesises itself,
// which arguments rewriteCall would check. Their C prototypes are cgo's own
// knowledge rather than declarations in a header: C.CString takes a
// `const char *`, which bounds the pointee to a scalar, so no check is
// emitted, while C.free takes a `void *`, which cgo maps to unsafe.Pointer,
// the one parameter type that always needs a check. C.malloc is absent
// because rewriteCall skips it by name.
var cgoHelperChecks = map[string][]bool{
	"CString":   {false},
	"CBytes":    {false},
	"GoString":  {false},
	"GoStringN": {false, false},
	"GoBytes":   {true, false},
	"free":      {true},
}

// cgoWalkFilePointerChecks classifies the C calls of one parsed cgo file.
// packagePath attributes the records and signals; it may be empty at walk
// time, and the caller rewrites it when a go.mod layout names the package
// later.
func cgoWalkFilePointerChecks(fset *token.FileSet, file *ast.File, path, packagePath string) *cgoFilePointerCheck {
	walker := &cgoPointerWalker{path: path, packagePath: packagePath, fset: fset}
	preamble := cgoParsePreamble(file)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		walker.walkFunction(fn, preamble)
	}
	sort.Slice(walker.check.callSites, func(i, j int) bool {
		a, b := walker.check.callSites[i].Position, walker.check.callSites[j].Position
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.Filename < b.Filename
	})
	// Findings are collected in call order and reported in the same order the
	// call sites are; sortReport applies its own total order afterwards.
	walker.check.signals = append(walker.check.signals, walker.findings...)
	return &walker.check
}

// cgoFilePointerCheck is the pointer-check view of one cgo file.
type cgoFilePointerCheck struct {
	callSites []model.NativeCallSite
	signals   []model.SecuritySignal
}

// cgoPointerWalker walks one file, one function body at a time.
type cgoPointerWalker struct {
	path        string
	packagePath string
	fset        *token.FileSet
	check       cgoFilePointerCheck
	findings    []model.SecuritySignal
}

// cgoCallEvent is one C.f(...) call found in a function body, plus the
// function-level facts its classification needs.
type cgoCallEvent struct {
	call  *ast.CallExpr
	name  string
	pos   token.Pos
	facts *cgoFunctionFacts
}

// cgoPinEvent is one (*runtime.Pinner).Pin or .Unpin call, in source order.
// The pin analysis is intraprocedural: a value pinned in one function is
// invisible to another, and a pin on a path the walker cannot see (an
// if-branch it walked but which does not dominate the call) still counts.
//
// Pin(v) pins the object v points to. What cgo's check asks about is the Go
// pointers STORED in the memory it scans, so the targets are the rendered
// pinned expressions (`s.other` for Pin(s.other)), which the classification
// compares with the expressions that load those stored pointers. Pin(&s.other)
// pins s itself and leaves s.other's target unpinned; the runtime panics on
// it, and the different rendering keeps it from reading as pinned.
type cgoPinEvent struct {
	pos     token.Pos
	unpin   bool
	inLoop  bool            // the call sits inside a for or range statement
	targets map[string]bool // rendered pinned expressions, plus their single definitions
}

// cgoPreamble is what the walker could read out of the C preamble text: the
// prototypes of the functions it defines or declares, and the type names it
// typedefs. Both are optional evidence; a preamble that leaves either out
// falls back to the approximation that needs it less.
type cgoPreamble struct {
	prototypes map[string][]string // function name -> parameter types
	typedefs   map[string]bool     // names usable as C.<name> conversions
}

// cgoParsePreamble reads function prototypes and typedefs out of the comment
// groups of a cgo file, which is where the preamble lives. Only the
// single-line forms are read: a declaration or definition whose parameter
// list opens and closes on one line. Multi-line C declarations fall back to
// the no-prototype approximation.
func cgoParsePreamble(file *ast.File) *cgoPreamble {
	preamble := &cgoPreamble{prototypes: map[string][]string{}, typedefs: map[string]bool{}}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for _, line := range preambleLines(comment.Text) {
				if name, params, ok := cgoParsePrototype(line); ok {
					preamble.prototypes[name] = params
					continue
				}
				if name, ok := cgoParseTypedef(line); ok {
					preamble.typedefs[name] = true
				}
			}
		}
	}
	return preamble
}

// cgoParsePrototype reads `static void take(void *p) {` and
// `int add(int, int);` into a name and a list of C parameter types. A
// parameter list containing parentheses (function pointers, macro calls)
// cannot be split on commas safely, so the prototype is dropped rather than
// misapplied.
func cgoParsePrototype(line string) (name string, params []string, ok bool) {
	open := strings.Index(line, "(")
	if open <= 0 {
		return "", nil, false
	}
	depth := 0
	close := -1
	for i := open; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				close = i
			}
		case '{':
			// A definition body opened before the parameter list closed:
			// this is not a readable prototype.
			if depth != 0 {
				return "", nil, false
			}
		}
		if close >= 0 {
			break
		}
	}
	if close < 0 {
		return "", nil, false
	}
	rest := strings.TrimSpace(line[close+1:])
	if rest != "" && rest[0] != ';' && rest[0] != '{' {
		return "", nil, false
	}
	head := strings.Fields(line[:open])
	if len(head) < 2 {
		// A name with no return type is a function pointer or a macro use,
		// neither of which this reader understands.
		return "", nil, false
	}
	name = head[len(head)-1]
	if !isCIdentifier(name) || strings.Contains(name, "*") {
		return "", nil, false
	}
	inner := strings.TrimSpace(line[open+1 : close])
	if inner == "" {
		return name, nil, true
	}
	if strings.Contains(inner, "(") {
		return "", nil, false
	}
	for _, param := range strings.Split(inner, ",") {
		params = append(params, cParamType(param))
	}
	for _, param := range params {
		if param == "..." || param == "" {
			return "", nil, false
		}
	}
	return name, params, true
}

// cParamType reduces one C parameter declaration to its type text: the
// parameter name, the qualifiers that do not change what a pointer may point
// at, and array sizes go; the type and its pointer stars stay. `void *p`
// becomes `void *`, `const char *s` becomes `char *`, and `int arr[4]`
// becomes `int *` because C passes arrays as pointers.
func cParamType(param string) string {
	fields := strings.Fields(param)
	if len(fields) == 0 {
		return ""
	}
	var typeFields []string
	for _, field := range fields {
		switch field {
		case "const", "volatile", "signed", "unsigned", "register", "struct", "union", "enum":
			// struct/union/enum only decorate the tag; the aggregate is
			// unknown either way, which is what the type check needs to know.
			continue
		}
		typeFields = append(typeFields, field)
	}
	if len(typeFields) == 0 {
		return ""
	}
	last := typeFields[len(typeFields)-1]
	if isCIdentifier(last) && len(typeFields) > 1 && !strings.ContainsAny(last, "*[]") {
		// The last plain identifier is the parameter name, unless it is the
		// only field left, which is an untyped `int`-style parameter.
		typeFields = typeFields[:len(typeFields)-1]
	} else if strings.HasPrefix(last, "*") && isCIdentifier(strings.TrimPrefix(last, "*")) && len(typeFields) > 1 {
		// `char *p` parses as two fields where the star is glued to the
		// name; the star belongs to the type and the name goes.
		typeFields[len(typeFields)-1] = "*"
	}
	for i, field := range typeFields {
		if strings.Contains(field, "[") {
			// An array parameter decays to a pointer: `arr[8]` and `*v[]`
			// keep their stars, lose the name, and gain one star per
			// dimension.
			stars := strings.Count(field, "[")
			field = cArrayDims.ReplaceAllString(field, "")
			field = strings.TrimRight(field, "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
			typeFields[i] = field + strings.Repeat("*", stars)
		}
	}
	return strings.TrimSpace(strings.Join(typeFields, " "))
}

// cArrayDims matches the array dimensions of a C parameter declarator.
var cArrayDims = regexp.MustCompile(`\[[^\]]*\]`)

// cgoParseTypedef reads `typedef int myint;` and records the name it declares,
// so C.<name> conversions can be recognised the way gcc.go's isType recognises
// them through its typedef table.
func cgoParseTypedef(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "typedef" {
		return "", false
	}
	name := fields[len(fields)-1]
	name = strings.TrimSuffix(name, ";")
	if !isCIdentifier(name) || name == fields[0] {
		return "", false
	}
	return name, true
}

// isCIdentifier reports whether name could be a C identifier.
func isCIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// cgoIsCTypeSelector reports whether the selector C.<name> names a type: one
// of the names cgo always synthesises, a _Ctype_ name, a struct, union or
// enum selector form, or a name the preamble typedefs. This extends the pure
// cgoIsType approximation with the typedef evidence the preamble carries.
func cgoIsCTypeSelector(name string, preamble *cgoPreamble) bool {
	if cgoBaseTypeNames[name] || strings.HasPrefix(name, "_Ctype_") ||
		strings.HasPrefix(name, "struct_") || strings.HasPrefix(name, "union_") ||
		strings.HasPrefix(name, "enum_") {
		return true
	}
	// The stdint and sys(types) names, size_t and friends, are typedefs by C
	// convention and can never name a function, so a call spelled C.<name>_t
	// is a conversion whatever the preamble says. Without this,
	// C.uintptr_t(...) in the syscall wrappers of the module cache reads as
	// a C call and its argument is reported as if cgo would check it.
	if strings.HasSuffix(name, "_t") {
		return true
	}
	return preamble != nil && preamble.typedefs[name]
}

// cCParamNeedsCheck mirrors needsPointerCheck for a C parameter type read
// from the preamble: a scalar parameter needs no check, a pointer needs one
// when the pointee may itself contain a pointer (gcc.go's hasPointer with
// top=false), and `void *` always needs one because cgo maps it to
// unsafe.Pointer, which its own selector rule cannot resolve. Aggregates are
// unknown without their definitions, and unknown means a check, the same
// direction gcc.go resolves unknown types.
func cCParamNeedsCheck(paramType string) bool {
	t := strings.TrimSpace(paramType)
	depth := strings.Count(t, "*")
	if depth == 0 {
		return false
	}
	if depth > 1 {
		return true
	}
	base := strings.TrimSpace(strings.TrimSuffix(t, "*"))
	if base == "void" {
		// cgo maps `void *` parameters to unsafe.Pointer, and hasPointer
		// cannot resolve that selector, so it answers true.
		return true
	}
	if cgoBaseTypeNames[base] {
		return false
	}
	return true
}

// cgoFunctionFacts is what one function body shows about its values: every
// assignment with the block it happened in, the runtime.Pinner variables,
// and the Pinner calls in source order. The textual walk and the compiled
// pass over cgo-generated files both collect it, which is why it is a
// structure and not local state.
type cgoFunctionFacts struct {
	defs       map[string][]cgoDef
	pinnerVars map[string]bool
	pins       []cgoPinEvent
	// parent is the enclosing scope's facts, set when the compiled pass
	// resolves a closure argument that names identifiers defined outside the
	// closure. Lookups fall through to it.
	parent *cgoFunctionFacts
}

// cgoDef is one assignment to a name, with the innermost block-like node it
// happened in. The block bounds where the assignment can be the one a later
// use reads.
type cgoDef struct {
	pos   token.Pos
	expr  ast.Expr
	scope ast.Node
}

// lookup finds the assignment of name that a use at pos reads: the latest
// one before pos whose block encloses pos, falling through to the parent
// scope. This is a path-insensitive reaching definition. A `:=` is bounded
// by its block, which separates the `p := ...` of two switch cases; a `=`
// is visible to every later use, because it writes a variable declared
// further out. The latest assignment wins, so when two branches both assign
// a name the later one in the source is read. A use with no position
// resolves only a name assigned exactly once.
func (f *cgoFunctionFacts) lookup(name string, pos token.Pos) (ast.Expr, bool) {
	for scope := f; scope != nil; scope = scope.parent {
		defs := scope.defs[name]
		if len(defs) == 0 {
			continue
		}
		if pos == token.NoPos {
			if len(defs) == 1 {
				return defs[0].expr, true
			}
			return nil, false
		}
		var best *cgoDef
		for i := range defs {
			def := &defs[i]
			if def.pos >= pos {
				continue
			}
			if def.scope != nil && (pos < def.scope.Pos() || pos >= def.scope.End()) {
				continue
			}
			if best == nil || def.pos > best.pos {
				best = def
			}
		}
		if best != nil {
			return best.expr, true
		}
		// Assigned in this scope but not before the use: the use reads a
		// parameter or an outer variable, which the parent may know.
	}
	return nil, false
}

// pinnedBefore returns the rendered expressions pinned before pos. An Unpin
// call releases everything: the walker does not tell two pinners apart, and
// treating the later pins as the only live ones is the safe reading.
func (f *cgoFunctionFacts) pinnedBefore(pos token.Pos) (pinned map[string]bool, loopPin bool) {
	pinned = map[string]bool{}
	for _, pin := range f.pins {
		if pin.pos >= pos {
			break
		}
		if pin.unpin {
			pinned = map[string]bool{}
			loopPin = false
			continue
		}
		for target := range pin.targets {
			pinned[target] = true
		}
		loopPin = loopPin || pin.inLoop
	}
	return pinned, loopPin
}

// cgoIsScopeNode reports whether n opens a block that bounds the assignments
// made in it.
func cgoIsScopeNode(n ast.Node) bool {
	switch n.(type) {
	case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause, *ast.IfStmt,
		*ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.FuncLit:
		return true
	}
	return false
}

// cgoCollectFacts walks one function body and collects its facts.
func cgoCollectFacts(body ast.Node) *cgoFunctionFacts {
	facts := &cgoFunctionFacts{
		defs:       map[string][]cgoDef{},
		pinnerVars: map[string]bool{},
	}
	// The ancestors of the node being visited, for the block of each
	// assignment and the loop test of each Pin call.
	var stack []ast.Node
	innermostScope := func() ast.Node {
		for i := len(stack) - 1; i >= 0; i-- {
			if cgoIsScopeNode(stack[i]) {
				return stack[i]
			}
		}
		return nil
	}
	inLoop := func() bool {
		for i := len(stack) - 1; i >= 0; i-- {
			switch stack[i].(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				return true
			case *ast.FuncLit:
				return false
			}
		}
		return false
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				// `:=` declares a name that lives in its block. `=` writes a
				// variable declared further out, and the value stays after the
				// block closes: `var p *T; if n > 0 { p = &b[0] }; C.f(p)`
				// reads the assignment made inside the if.
				scope := innermostScope()
				if node.Tok != token.DEFINE {
					scope = nil
				}
				for i, lhs := range node.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || id.Name == "_" {
						continue
					}
					facts.record(id, node.Rhs[i], scope)
					if cgoIsPinnerValue(node.Rhs[i]) {
						facts.pinnerVars[id.Name] = true
					}
				}
			}
		case *ast.GenDecl:
			for _, spec := range node.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if node.Tok == token.VAR && cgoIsPinnerTypeExpr(valueSpec.Type) {
					for _, name := range valueSpec.Names {
						facts.pinnerVars[name.Name] = true
					}
				}
				for i, name := range valueSpec.Names {
					if i < len(valueSpec.Values) {
						facts.record(name, valueSpec.Values[i], innermostScope())
						if cgoIsPinnerValue(valueSpec.Values[i]) {
							facts.pinnerVars[name.Name] = true
						}
					}
				}
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if recv, ok := sel.X.(*ast.Ident); ok && facts.pinnerVars[recv.Name] {
					switch sel.Sel.Name {
					case "Pin":
						if len(node.Args) == 1 {
							facts.pins = append(facts.pins, cgoPinEvent{
								pos:     node.Pos(),
								inLoop:  inLoop(),
								targets: facts.pinTargets(node.Args[0], node.Pos()),
							})
						}
					case "Unpin":
						facts.pins = append(facts.pins, cgoPinEvent{pos: node.Pos(), unpin: true})
					}
				}
			}
		}
		stack = append(stack, n)
		return true
	})
	return facts
}

// record notes one assignment. Its position is the end of the assigned
// expression, so `p = f(p)` reads the previous p inside f(p) and the new one
// after the statement.
func (f *cgoFunctionFacts) record(id *ast.Ident, expr ast.Expr, scope ast.Node) {
	f.defs[id.Name] = append(f.defs[id.Name], cgoDef{pos: expr.End(), expr: expr, scope: scope})
}

// pinTargets renders the pinned expression, and its definition when it is a
// name assigned before the pin, so `n := head.next; pin.Pin(n)` covers a
// later load of head.next. Conversions are stripped: Pin(unsafe.Pointer(p))
// pins what p points to.
func (f *cgoFunctionFacts) pinTargets(arg ast.Expr, pos token.Pos) map[string]bool {
	targets := map[string]bool{}
	expr := cgoUnparen(cgoStripConversions(arg))
	targets[types.ExprString(expr)] = true
	if id, ok := expr.(*ast.Ident); ok {
		if def, ok := f.lookup(id.Name, pos); ok {
			targets[types.ExprString(cgoUnparen(cgoStripConversions(def)))] = true
		}
	}
	return targets
}

// cgoUnparen removes the parentheses around an expression.
func cgoUnparen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// walkFunction collects the C calls of one function body and classifies each.
func (w *cgoPointerWalker) walkFunction(fn *ast.FuncDecl, preamble *cgoPreamble) {
	facts := cgoCollectFacts(fn.Body)
	var calls []*cgoCallEvent
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if name, ok := cgoCallOf(call); ok {
				calls = append(calls, &cgoCallEvent{call: call, name: name, pos: call.Pos()})
			}
		}
		return true
	})
	for _, event := range calls {
		event.facts = facts
		classified := cgoCallClassification{walker: w, preamble: preamble}
		classified.classify(event)
		w.check.callSites = append(w.check.callSites, classified.site)
		w.findings = append(w.findings, classified.findings...)
	}
}

// cgoIsPinnerTypeExpr reports whether a type expression names runtime.Pinner.
func cgoIsPinnerTypeExpr(t ast.Expr) bool {
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "runtime" && sel.Sel.Name == "Pinner"
}

// cgoIsPinnerValue reports whether an initialiser creates a runtime.Pinner:
// runtime.Pinner{}, &runtime.Pinner{} or new(runtime.Pinner).
func cgoIsPinnerValue(expr ast.Expr) bool {
	switch e := cgoUnparen(expr).(type) {
	case *ast.CompositeLit:
		return cgoIsPinnerTypeExpr(e.Type)
	case *ast.UnaryExpr:
		return e.Op == token.AND && cgoIsPinnerValue(e.X)
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "new" && len(e.Args) == 1 {
			return cgoIsPinnerTypeExpr(e.Args[0])
		}
	}
	return false
}

// cgoCallClassification holds the state of classifying one call event.
type cgoCallClassification struct {
	walker   *cgoPointerWalker
	preamble *cgoPreamble
	site     model.NativeCallSite
	findings []model.SecuritySignal
}

// classify applies rewriteCall's decisions to one call event: which
// parameters would be checked at all, which shape each argument has, whose
// memory it points into, and whether the value was pinned.
func (c *cgoCallClassification) classify(event *cgoCallEvent) {
	call := event.call
	c.site = model.NativeCallSite{
		ID:          stableID("cgo-call-site", c.walker.packagePath, c.walker.path, c.key(call.Pos())),
		PackagePath: c.walker.packagePath,
		Symbol:      "C." + event.name,
		Confidence:  "textual",
	}
	start, _ := c.position(call.Pos(), call.End())
	c.site.Position = start

	// rewriteCall skips malloc by name and every conversion by kind: a call
	// whose callee is a type has no parameters to check.
	if event.name == "malloc" || cgoIsCTypeSelector(event.name, c.preamble) {
		return
	}
	paramChecks, paramChecksKnown := cgoHelperChecks[event.name]
	if !paramChecksKnown {
		if prototype, ok := c.preamble.prototypes[event.name]; ok {
			paramChecksKnown = true
			for _, param := range prototype {
				paramChecks = append(paramChecks, cCParamNeedsCheck(param))
			}
		}
	}
	// gcc.go skips the whole call when argument and parameter counts disagree;
	// the mismatch is a compile error in the generated file.
	if paramChecksKnown && len(call.Args) != len(paramChecks) {
		return
	}
	for i, arg := range call.Args {
		argument := c.classifyArgument(event, i, arg, paramChecksKnown, paramChecks)
		c.site.Arguments = append(c.site.Arguments, argument)
		if argument.Shape == cgoShapeUntyped && argument.Owner != cgoOwnerC {
			c.findings = append(c.findings, c.untypedFinding(event, i, arg))
		}
	}
}

// classifyArgument decides one argument's fate.
func (c *cgoCallClassification) classifyArgument(event *cgoCallEvent, index int, arg ast.Expr, paramChecksKnown bool, paramChecks []bool) model.NativeCallArgument {
	argument := model.NativeCallArgument{Index: index}
	argument.Shape, _ = cgoCheckShape(arg)
	if pos := c.walker.fset.Position(arg.Pos()); pos.IsValid() {
		argument.Position = &model.Position{Filename: pos.Filename, Offset: pos.Offset, Line: pos.Line, Column: pos.Column}
	}

	if paramChecksKnown && !paramChecks[index] {
		// The parameter is a pointer to a scalar or a scalar itself, the one
		// case needsPointerCheck answers false for that the text can see.
		argument.Shape = cgoShapeNoCheck
		argument.Owner = cgoOwnerUnknown
		return argument
	}
	if argument.Shape == cgoShapeNoCheck {
		argument.Owner = cgoOwnerUnknown
		return argument
	}

	argument.Owner = c.argumentOwner(event, arg)
	if !cgoPointerCarrying(arg, event) {
		// Without unsafe.Pointer evidence or a preamble prototype the read
		// cannot say the parameter is checked, so it stays silent: flagging
		// every slice passed to an unknown C function would drown the real
		// cases in guesses.
		argument.Shape = cgoShapeNoCheck
		return argument
	}
	if argument.Owner == cgoOwnerGo && argument.Shape != cgoShapeUntyped {
		// A bounded check covers the memory at the passed address. Without
		// types the read can only see the one stored pointer &E names; the
		// compiled pass answers for untyped checks, which scan a whole object.
		pinned, _ := event.facts.pinnedBefore(event.pos)
		argument.Pinned = cgoStoredPointerPinned(arg, event.facts, arg.Pos(), pinned)
	}
	return argument
}

// cgoStoredPointerPinned reports whether the pointer stored at the address
// the argument passes was pinned: the argument resolves, through conversions
// and the assignments that reach it, to &E, and E was pinned (Pin(E)). That
// is the condition cgo's check enforces for an addressed value, and it is
// deliberately not "the object containing E was pinned": Pin(&s.other) pins
// s and leaves s.other's target unpinned, and the runtime panics on it.
func cgoStoredPointerPinned(arg ast.Expr, facts *cgoFunctionFacts, pos token.Pos, pinned map[string]bool) bool {
	if len(pinned) == 0 || facts == nil {
		return false
	}
	expr := arg
	for depth := 0; depth < 8; depth++ {
		expr = cgoUnparen(cgoStripConversions(cgoUnparen(expr)))
		switch e := expr.(type) {
		case *ast.Ident:
			def, ok := facts.lookup(e.Name, pos)
			if !ok {
				return false
			}
			expr, pos = def, def.Pos()
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return false
			}
			return pinned[types.ExprString(cgoUnparen(e.X))]
		default:
			return false
		}
	}
	return false
}

// cgoPointerCarrying approximates needsPointerCheck without the C prototype:
// the argument's expression, or the assignment that reaches an identifier
// argument in the same function, must contain an unsafe.Pointer(...) of an
// expression that is not itself a C call result.
func cgoPointerCarrying(arg ast.Expr, event *cgoCallEvent) bool {
	expr := arg
	if id, ok := arg.(*ast.Ident); ok && event != nil && event.facts != nil {
		if def, ok := event.facts.lookup(id.Name, id.Pos()); ok {
			expr = def
		} else {
			return false
		}
	}
	return cgoContainsUnsafePointer(expr, event, 0)
}

// cgoContainsUnsafePointer walks expr for an unsafe.Pointer(...) conversion
// whose argument is not rooted in C-owned memory. depth caps the definition
// chase; the map form of the argument's own scope arrives via event.
func cgoContainsUnsafePointer(expr ast.Expr, event *cgoCallEvent, depth int) bool {
	if depth > 8 {
		return false
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "unsafe" && sel.Sel.Name == "Pointer" && len(e.Args) == 1 {
				if !cgoIsCRooted(e.Args[0], event, depth+1) && cgoDerivesGoAddress(e.Args[0], event, depth+1) {
					return true
				}
			}
		}
		for _, sub := range e.Args {
			if cgoContainsUnsafePointer(sub, event, depth+1) {
				return true
			}
		}
		return false
	case *ast.ParenExpr:
		return cgoContainsUnsafePointer(e.X, event, depth+1)
	case *ast.StarExpr:
		return cgoContainsUnsafePointer(e.X, event, depth+1)
	case *ast.UnaryExpr:
		return cgoContainsUnsafePointer(e.X, event, depth+1)
	case *ast.BinaryExpr:
		return cgoContainsUnsafePointer(e.X, event, depth+1) || cgoContainsUnsafePointer(e.Y, event, depth+1)
	case *ast.IndexExpr:
		return cgoContainsUnsafePointer(e.X, event, depth+1) || cgoContainsUnsafePointer(e.Index, event, depth+1)
	case *ast.SliceExpr:
		return cgoContainsUnsafePointer(e.X, event, depth+1)
	}
	return false
}

// cgoDerivesGoAddress reports whether expr takes the address of Go memory
// somewhere the function shows: &x, &x[i], a slice expression, or
// unsafe.SliceData / unsafe.StringData of a Go value, through conversions and
// the assignments that reach a name. An unsafe.Pointer of a struct field, a
// parameter or a helper's result has no visible origin; libraries keep C
// handles in exactly those places (go-sqlite3's argBuf, colvals and
// newHandle results), so the text leaves them to the compiled pass, which
// sees their types.
func cgoDerivesGoAddress(expr ast.Expr, event *cgoCallEvent, depth int) bool {
	if depth > 8 {
		return false
	}
	switch e := cgoUnparen(expr).(type) {
	case *ast.UnaryExpr:
		return e.Op == token.AND
	case *ast.SliceExpr:
		return true
	case *ast.CallExpr:
		if len(e.Args) != 1 {
			return false
		}
		if cgoIsUnsafeData(e.Fun, false) {
			return true
		}
		if cgoIsType(e.Fun) {
			return cgoDerivesGoAddress(e.Args[0], event, depth+1)
		}
	case *ast.Ident:
		if event != nil && event.facts != nil {
			if def, ok := event.facts.lookup(e.Name, e.Pos()); ok {
				return cgoDerivesGoAddress(def, event, depth+1)
			}
		}
	}
	return false
}

// cgoIsCRooted reports whether expr evaluates to memory C owns: the result of
// a C call, or something a C-owned identifier already points into.
func cgoIsCRooted(expr ast.Expr, event *cgoCallEvent, depth int) bool {
	if depth > 8 {
		return false
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		if _, ok := cgoCallOf(e); ok {
			return true
		}
		// In generated code the same call appears as _Cfunc_<name>, and the
		// conversion helpers cgo synthesises appear only in that form.
		if isCgoWrapperCall(e) {
			return true
		}
		// A C call with checked arguments is rewritten into an immediately
		// invoked closure that returns the wrapper's result:
		// ptr := func() T { ...; return _Cfunc_f(...) }().
		if literal, ok := cgoUnparen(e.Fun).(*ast.FuncLit); ok && len(e.Args) == 0 {
			rooted := false
			ast.Inspect(literal.Body, func(n ast.Node) bool {
				if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
					if call, ok := cgoUnparen(ret.Results[0]).(*ast.CallExpr); ok && isCgoWrapperCall(call) {
						rooted = true
					}
				}
				return !rooted
			})
			return rooted
		}
		if len(e.Args) == 1 {
			return cgoIsCRooted(e.Args[0], event, depth+1)
		}
		return false
	case *ast.Ident:
		if event == nil || event.facts == nil {
			return false
		}
		if def, ok := event.facts.lookup(e.Name, e.Pos()); ok {
			return cgoIsCRooted(def, event, depth+1)
		}
		return false
	case *ast.ParenExpr:
		return cgoIsCRooted(e.X, event, depth+1)
	case *ast.StarExpr:
		return cgoIsCRooted(e.X, event, depth+1)
	case *ast.UnaryExpr:
		return cgoIsCRooted(e.X, event, depth+1)
	case *ast.IndexExpr:
		return cgoIsCRooted(e.X, event, depth+1)
	case *ast.SliceExpr:
		return cgoIsCRooted(e.X, event, depth+1)
	case *ast.SelectorExpr:
		// A bare C.<name> reference is a C symbol (a function pointer taken
		// by name, a C variable): the memory behind it is C-side whatever the
		// conversion around it says.
		if id, ok := e.X.(*ast.Ident); ok && id.Name == "C" {
			return true
		}
		return cgoIsCRooted(e.X, event, depth+1)
	}
	return false
}

// argumentOwner names whose memory the argument points into. The three
// recognised shapes address Go memory by construction; a C-rooted argument is
// C memory; everything else is unknown.
func (c *cgoCallClassification) argumentOwner(event *cgoCallEvent, arg ast.Expr) string {
	if cgoIsCRooted(arg, event, 0) {
		return cgoOwnerC
	}
	switch arg.(type) {
	case *ast.Ident:
		// A bare identifier the read cannot type: with a definition the
		// carrying rule saw it, without one the memory is not decidable.
		return cgoOwnerUnknown
	}
	return cgoOwnerGo
}

// untypedFinding builds the signal for one argument cgo checks with no type
// information. The description states the textual approximation: without the
// C prototype, a parameter that points at a scalar would make the check
// disappear and the signal spurious.
func (c *cgoCallClassification) untypedFinding(event *cgoCallEvent, index int, arg ast.Expr) model.SecuritySignal {
	start, end := c.position(arg.Pos(), arg.End())
	return model.SecuritySignal{
		ID:             stableID("cgo-untyped-check", c.walker.packagePath, c.walker.path, c.key(arg.Pos()), "arg", strconv.Itoa(index)),
		Category:       CgoCategoryUntypedCheck,
		Severity:       "medium",
		Confidence:     "textual",
		PackagePath:    c.walker.packagePath,
		Symbol:         "C." + event.name,
		Description:    "cgo checks this argument with no type information: the runtime scans the entire heap object behind the pointer and panics when any pointer field of that object holds an unpinned Go pointer.",
		Recommendation: "Take the address inside the call, for example C.f(unsafe.Pointer(&s.field)), so cgo checks only that field, or pass memory C owns.",
		Range:          model.Range{Start: start, End: end},
	}
}

// position maps a token range onto the positions the report carries.
func (c *cgoCallClassification) position(from, to token.Pos) (model.Position, model.Position) {
	start := c.walker.fset.Position(from)
	end := c.walker.fset.Position(to)
	return model.Position{Filename: start.Filename, Offset: start.Offset, Line: start.Line, Column: start.Column},
		model.Position{Filename: end.Filename, Offset: end.Offset, Line: end.Line, Column: end.Column}
}

// key renders a token position for identifier construction.
func (c *cgoCallClassification) key(pos token.Pos) string {
	return strconv.Itoa(int(pos))
}
