package analyzer

import (
	"go/ast"
	"go/token"
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
	call     *ast.CallExpr
	name     string
	pos      token.Pos
	defs     map[string]ast.Expr
	setTwice map[string]bool
	cOwned   map[string]bool
	pins     []cgoPinEvent
}

// cgoPinEvent is one (*runtime.Pinner).Pin or .Unpin call, in source order.
// The pin analysis is intraprocedural: a value pinned in one function is
// invisible to another, and a pin on a path the walker cannot see (an
// if-branch it walked but which does not dominate the call) still counts.
type cgoPinEvent struct {
	pos    token.Pos
	unpin  bool
	target string // the identifier passed to Pin; empty for Unpin
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
	}
	for i, field := range typeFields {
		if strings.Contains(field, "[") {
			// An array parameter decays to a pointer.
			typeFields[i] = strings.ReplaceAll(field, "[4]", "*")
		}
	}
	return strings.Join(typeFields, " ")
}

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

// walkFunction collects the C calls, the single-assignment definitions, the
// C-owned identifiers and the Pinner calls of one function body, then
// classifies each call. Definitions are collected per function rather than
// per block: a name assigned twice anywhere in the function is ambiguous and
// resolves to nothing, which is the safe reading, and a closure variable that
// shadows an outer one is the known limit of that choice.
func (w *cgoPointerWalker) walkFunction(fn *ast.FuncDecl, preamble *cgoPreamble) {
	defs := map[string]ast.Expr{}
	setTwice := map[string]bool{}
	cOwned := map[string]bool{}
	pinnerVars := map[string]bool{}
	var pins []cgoPinEvent
	var calls []*cgoCallEvent

	record := func(name string, expr ast.Expr) {
		if _, seen := defs[name]; seen {
			setTwice[name] = true
		}
		defs[name] = expr
		if cgoIsCRooted(expr, nil, 0) {
			cOwned[name] = true
		}
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
						record(id.Name, node.Rhs[i])
					}
				}
			}
		case *ast.GenDecl:
			for _, spec := range node.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if cgoIsPinnerType(node, valueSpec) {
					for _, name := range valueSpec.Names {
						pinnerVars[name.Name] = true
					}
				}
				for i, name := range valueSpec.Names {
					if i < len(valueSpec.Values) {
						record(name.Name, valueSpec.Values[i])
					}
				}
			}
		case *ast.CallExpr:
			if name, ok := cgoCallOf(node); ok {
				calls = append(calls, &cgoCallEvent{call: node, name: name, pos: node.Pos()})
				// Calls nested inside a C call's arguments are separate C
				// calls in cgo's own walk; ast.Inspect still visits them.
				return true
			}
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if recv, ok := sel.X.(*ast.Ident); ok && pinnerVars[recv.Name] {
					switch sel.Sel.Name {
					case "Pin":
						if len(node.Args) == 1 {
							if id, ok := node.Args[0].(*ast.Ident); ok {
								pins = append(pins, cgoPinEvent{pos: node.Pos(), target: id.Name})
							}
						}
					case "Unpin":
						pins = append(pins, cgoPinEvent{pos: node.Pos(), unpin: true})
					}
				}
			}
		}
		return true
	})

	for _, event := range calls {
		event.defs = defs
		event.setTwice = setTwice
		event.cOwned = cOwned
		event.pins = pins
		classified := cgoCallClassification{walker: w, preamble: preamble}
		classified.classify(event)
		w.check.callSites = append(w.check.callSites, classified.site)
		w.findings = append(w.findings, classified.findings...)
	}
}

// cgoIsPinnerType reports whether a declaration introduces a runtime.Pinner
// variable.
func cgoIsPinnerType(decl *ast.GenDecl, spec *ast.ValueSpec) bool {
	if decl.Tok != token.VAR {
		return false
	}
	if sel, ok := typeOfSpec(spec).(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "runtime" && sel.Sel.Name == "Pinner" {
			return true
		}
	}
	return false
}

func typeOfSpec(spec *ast.ValueSpec) ast.Expr {
	return spec.Type
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
		argument.Pinned = c.argumentPinned(event, arg)
	}
	return argument
}

// cgoPointerCarrying approximates needsPointerCheck without the C prototype:
// the argument's expression, or the single assignment that defines an
// identifier argument in the same function, must contain an
// unsafe.Pointer(...) of an expression that is not itself a C call result. A
// defined identifier assigned twice resolves to nothing, the safe reading.
func cgoPointerCarrying(arg ast.Expr, event *cgoCallEvent) bool {
	expr := arg
	if id, ok := arg.(*ast.Ident); ok && event != nil {
		if event.setTwice[id.Name] {
			return false
		}
		if def, ok := event.defs[id.Name]; ok {
			expr = def
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
				if !cgoIsCRooted(e.Args[0], event, depth+1) {
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
		if len(e.Args) == 1 {
			return cgoIsCRooted(e.Args[0], event, depth+1)
		}
		return false
	case *ast.Ident:
		if event == nil {
			return false
		}
		if event.cOwned[e.Name] {
			return true
		}
		if event.setTwice[e.Name] {
			return false
		}
		if def, ok := event.defs[e.Name]; ok {
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

// argumentPinned reports whether every identifier the argument is rooted in
// was passed to a Pinner before the call, with no Unpin of that pinner in
// between. Only what one function body shows can count; this is the
// intraprocedural limit the report states.
func (c *cgoCallClassification) argumentPinned(event *cgoCallEvent, arg ast.Expr) bool {
	bases := cgoBaseIdents(arg, nil, 0)
	if len(bases) == 0 {
		return false
	}
	var lastUnpin token.Pos
	for _, pin := range event.pins {
		if pin.pos >= event.pos {
			break
		}
		if pin.unpin {
			lastUnpin = pin.pos
			continue
		}
		if pin.pos < lastUnpin {
			continue
		}
		if bases[pin.target] {
			delete(bases, pin.target)
		}
	}
	return len(bases) == 0
}

// cgoBaseIdents collects the identifiers an expression is rooted in, chasing
// single definitions so a pinned variable's alias still reads as pinned.
func cgoBaseIdents(expr ast.Expr, event *cgoCallEvent, depth int) map[string]bool {
	out := map[string]bool{}
	var collect func(ast.Expr, int)
	collect = func(e ast.Expr, d int) {
		if d > 8 {
			return
		}
		switch v := e.(type) {
		case *ast.Ident:
			out[v.Name] = true
			if event != nil && !event.setTwice[v.Name] {
				if def, ok := event.defs[v.Name]; ok {
					collect(def, d+1)
				}
			}
		case *ast.ParenExpr:
			collect(v.X, d+1)
		case *ast.StarExpr:
			collect(v.X, d+1)
		case *ast.UnaryExpr:
			collect(v.X, d+1)
		case *ast.CallExpr:
			for _, sub := range v.Args {
				collect(sub, d+1)
			}
		case *ast.IndexExpr:
			collect(v.X, d+1)
		case *ast.SliceExpr:
			collect(v.X, d+1)
		case *ast.SelectorExpr:
			collect(v.X, d+1)
		}
	}
	collect(expr, depth)
	return out
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
