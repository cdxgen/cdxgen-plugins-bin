package analyzer

import (
	"go/ast"
	"go/token"
	"strings"
)

// The cgo pointer check. When cgo rewrites a call C.f(a1, a2, ...) it decides,
// per argument, how the runtime pointer check is allowed to see the value:
// three syntactic shapes (the address of an indexed element, the address of a
// variable or field, a slice expression) produce a bounded check of exactly
// that memory, and every other argument that needs a check at all is checked
// with no type information, which makes runtime.cgoCheckUnknownPointer scan the
// entire heap object behind the pointer. This file ports the classification
// rules; cgo_pointer_walk.go applies them to golem's textual read of the
// source and, with CGO_ENABLED=1, to the checks cgo itself emitted.
//
// Every rule here mirrors a named function of go1.27.4 cmd/cgo/gcc.go. The
// ports are structural (they read the same ast nodes in the same order) rather
// than textual, and each deviation from gcc.go is stated where it happens.

// Cgo check shapes, in the vocabulary the report carries. The first four are
// the shapes rewriteCall recognises; "unchecked" covers the arguments cgo
// emits no _cgoCheckPointer call for.
const (
	cgoShapeAddr    = "addr"      // checkAddr: &x, including &s.field: check only the addressed field
	cgoShapeIndex   = "index"     // checkIndex: &x[i]: check only the indexed slice or array
	cgoShapeSlice   = "slice"     // checkSlice: x[i:j]: check only the sliced array
	cgoShapeUntyped = "untyped"   // _cgoCheckPointer(_cgoN, nil): scan the whole heap object
	cgoShapeNoCheck = "unchecked" // nothing emitted: nil argument or unsafe.StringData result
)

// cgoCheckShape classifies one argument expression the way rewriteCall does
// before emitting a check: needsPointerCheck's nil case and
// checkUnsafeStringData remove the argument from checking entirely, then the
// three shapes are tried in checkIndex, checkAddr, checkSlice order, and
// whatever survives is checked with nil type information.
//
// The reason return value explains an "unchecked" result for the call-site
// records; it is "nil" or "string-data" and "" for every other shape.
func cgoCheckShape(arg ast.Expr) (shape, reason string) {
	// needsPointerCheck: an untyped nil needs no check, and _cgoCheckPointer
	// would turn it into a failing type assertion, so cgo skips it.
	if id, ok := arg.(*ast.Ident); ok && id.Name == "nil" {
		return cgoShapeNoCheck, "nil"
	}
	// checkUnsafeStringData: a StringData result cannot contain a pointer.
	if cgoCheckUnsafeStringData(arg) {
		return cgoShapeNoCheck, "string-data"
	}
	x := cgoStripConversions(arg)
	// checkIndex before checkAddr: &a[i] is the more specific shape and needs
	// a different runtime hint, so it must win.
	switch e := x.(type) {
	case *ast.UnaryExpr:
		if e.Op != token.AND {
			break
		}
		if _, ok := e.X.(*ast.IndexExpr); ok {
			return cgoShapeIndex, ""
		}
		return cgoShapeAddr, ""
	case *ast.SliceExpr:
		return cgoShapeSlice, ""
	}
	return cgoShapeUntyped, ""
}

// cgoStripConversions removes the type conversions checkIndex, checkAddr and
// checkSlice all unwrap before matching their shape: a single-argument call
// whose callee is a type, unsafe.SliceData or unsafe.StringData. The loop is
// theirs verbatim; ParenExpr is deliberately NOT unwrapped, because gcc.go
// does not unwrap it either, which is why unsafe.Pointer((&s.f)) falls through
// to the untyped check.
func cgoStripConversions(arg ast.Expr) ast.Expr {
	x := arg
	for {
		call, ok := x.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return x
		}
		if !cgoIsType(call.Fun) && !cgoIsUnsafeData(call.Fun, false) {
			return x
		}
		x = call.Args[0]
	}
}

// cgoBaseTypeNames lists the C type names cgo synthesises a _Ctype_ typedef
// for unconditionally, from gcc.go's nameToC map and the base list the cgo
// documentation states. A C.<name> selector outside this list may still be a
// type declared in a header, but gcc.go's own isType answers false for an
// unknown identifier, so this port answers false too: the cost of a false
// "not a type" is only that a conversion stays wrapped and the argument
// classifies as untyped, while the cost of a false "is a type" would be
// swallowing a real nested C call.
var cgoBaseTypeNames = map[string]bool{
	"bool": true, "char": true, "complexfloat": true, "complexdouble": true,
	"double": true, "float": true, "int": true, "long": true, "longlong": true,
	"schar": true, "short": true, "uchar": true, "uint": true, "ulong": true,
	"ulonglong": true, "ushort": true, "void": true,
}

// cgoIsType ports isType, which decides whether a callee of a single-argument
// call is a type and the conversion may be stripped. isType consults cgo's
// typedef table for C.<name> selectors; golem reads the file without the C
// preamble's declarations, so the exact table is unavailable and the fixed
// base-type names, the struct_/union_/enum_ selector forms cname produces, and
// the _Ctype_ prefix stand in for it. The limit is stated above.
func cgoIsType(t ast.Expr) bool {
	switch t := t.(type) {
	case *ast.SelectorExpr:
		id, ok := t.X.(*ast.Ident)
		if !ok {
			return false
		}
		// cgo's generated code spells unsafe.Pointer as _cgo_unsafe.Pointer.
		if (id.Name == "unsafe" || id.Name == "_cgo_unsafe") && t.Sel.Name == "Pointer" {
			return true
		}
		if id.Name == "C" {
			return cgoIsCTypeSelector(t.Sel.Name, nil)
		}
		return false
	case *ast.Ident:
		switch t.Name {
		case "unsafe.Pointer", "bool", "byte",
			"complex64", "complex128",
			"error",
			"float32", "float64",
			"int", "int8", "int16", "int32", "int64",
			"rune", "string",
			"uint", "uint8", "uint16", "uint32", "uint64", "uintptr":
			return true
		}
		if strings.HasPrefix(t.Name, "_Ctype_") {
			return true
		}
	case *ast.ParenExpr:
		return cgoIsType(t.X)
	case *ast.StarExpr:
		return cgoIsType(t.X)
	case *ast.ArrayType, *ast.StructType, *ast.FuncType, *ast.InterfaceType,
		*ast.MapType, *ast.ChanType:
		return true
	}
	return false
}

// cgoIsUnsafeData ports isUnsafeData: unsafe.StringData, and also
// unsafe.SliceData unless onlyStringData narrows the question, which
// checkUnsafeStringData does.
func cgoIsUnsafeData(x ast.Expr, onlyStringData bool) bool {
	sel, ok := x.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if id.Name != "unsafe" {
		return false
	}
	if !onlyStringData && sel.Sel.Name == "SliceData" {
		return true
	}
	return sel.Sel.Name == "StringData"
}

// cgoCheckUnsafeStringData ports checkUnsafeStringData: the argument is the
// result of unsafe.StringData, directly or behind type conversions, and cgo
// emits no check for it.
func cgoCheckUnsafeStringData(arg ast.Expr) bool {
	x := arg
	for {
		call, ok := x.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return false
		}
		if cgoIsUnsafeData(call.Fun, true) {
			return true
		}
		if !cgoIsType(call.Fun) {
			return false
		}
		x = call.Args[0]
	}
}

// cgoCallOf reports the C function a call expression names, when the call is
// the C.f(...) form the pointer check applies to.
func cgoCallOf(call *ast.CallExpr) (name string, ok bool) {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return "", false
	}
	id, isIdent := sel.X.(*ast.Ident)
	if !isIdent || id.Name != "C" {
		return "", false
	}
	return sel.Sel.Name, true
}
