package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The table drives cgoCheckShape through every branch of the gcc.go port: the
// three recognised shapes, the two unchecked ones, conversion stripping
// (single and nested, including conversions whose callee is only a type
// because of the C-name approximation), and the parenthesis and multi-call
// traps that make rewriteCall fall through to the untyped check.
func TestCgoCheckShape(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		wantShape string
		wantWhy   string
	}{
		{"nil literal", `nil`, cgoShapeNoCheck, "nil"},
		{"string data direct", `unsafe.StringData(s)`, cgoShapeNoCheck, "string-data"},
		{"string data behind conversion", `unsafe.Pointer(unsafe.StringData(s))`, cgoShapeNoCheck, "string-data"},
		{"string data behind c conversion", `(*C.char)(unsafe.StringData(s))`, cgoShapeNoCheck, "string-data"},
		{"addr of field", `unsafe.Pointer(&s.field)`, cgoShapeAddr, ""},
		{"addr of variable", `&x`, cgoShapeAddr, ""},
		{"addr of whole array", `unsafe.Pointer(&arr)`, cgoShapeAddr, ""},
		{"addr behind c conversion", `(*C.int)(&x)`, cgoShapeAddr, ""},
		{"addr behind uintptr conversion", `uintptr(unsafe.Pointer(&x))`, cgoShapeAddr, ""},
		{"addr of indexed element", `unsafe.Pointer(&buf[0])`, cgoShapeIndex, ""},
		{"addr of indexed element behind conversion", `(*C.char)(unsafe.Pointer(&buf[0]))`, cgoShapeIndex, ""},
		{"addr of slice of indexed element", `unsafe.Pointer(&buf[1:4][0])`, cgoShapeIndex, ""},
		{"addr of reslice is addr, not index", `unsafe.Pointer(&buf[2:5])`, cgoShapeAddr, ""},
		{"slice expression", `buf[1:4]`, cgoShapeSlice, ""},
		{"slice behind conversion", `unsafe.Pointer(buf[1:4])`, cgoShapeSlice, ""},
		{"slice behind c conversion", `(*C.char)(unsafe.Pointer(buf[1:4]))`, cgoShapeSlice, ""},
		// SliceData is a stripping passthrough, not a recognised shape: after
		// the conversions are gone a bare identifier survives, which is the
		// untyped check. Verified against go1.27.4 cmd/cgo output.
		{"slice data strips to untyped", `unsafe.SliceData(buf)`, cgoShapeUntyped, ""},
		{"slice data behind unsafe.Pointer", `unsafe.Pointer(unsafe.SliceData(buf))`, cgoShapeUntyped, ""},
		{"untyped identifier", `p`, cgoShapeUntyped, ""},
		{"paren defeats addr", `unsafe.Pointer((&s.field))`, cgoShapeUntyped, ""},
		{"paren around whole arg", `(&s.field)`, cgoShapeUntyped, ""},
		{"nested calls are not conversions", `wrapper(unsafe.Pointer(&s.field))`, cgoShapeUntyped, ""},
		{"multi-argument call is not a conversion", `cgoFill(dst, src)`, cgoShapeUntyped, ""},
		{"c function call is not a conversion", `C.GoString(cs)`, cgoShapeUntyped, ""},
		{"unknown c selector is not a type", `C.custom(x)`, cgoShapeUntyped, ""},
		{"string data behind two conversions", `(*C.char)(unsafe.Pointer(unsafe.StringData(s)))`, cgoShapeNoCheck, "string-data"},
		{"string data behind slice type conversion", `[]byte(unsafe.StringData(s))`, cgoShapeNoCheck, "string-data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := parseTestExpr(t, tt.arg)
			shape, why := cgoCheckShape(expr)
			if shape != tt.wantShape {
				t.Errorf("cgoCheckShape(%s) shape = %q, want %q", tt.arg, shape, tt.wantShape)
			}
			if why != tt.wantWhy {
				t.Errorf("cgoCheckShape(%s) reason = %q, want %q", tt.arg, why, tt.wantWhy)
			}
		})
	}
}

// The conversions cgoIsType accepts must not swallow calls that name a C
// function or an unknown selector: rewriteCall only strips what isType
// certifies, and every survivor is checked with nil type information.
func TestCgoIsTypeRejectsNonTypes(t *testing.T) {
	for _, expr := range []string{
		`C.take(p)`,
		`C.custom(x)`,
		`fill(x)`,
	} {
		call := parseTestExpr(t, expr).(*ast.CallExpr)
		if cgoIsType(call.Fun) {
			t.Errorf("cgoIsType accepted the non-type callee of %q", expr)
		}
	}
	for _, expr := range []string{
		`unsafe.Pointer(x)`,
		`C.int(x)`,
		`C.char(x)`,
		`C.uchar(x)`,
		`(*C.struct_stat)(x)`,
		`C._Ctype_int(x)`,
		`[]byte(x)`,
		`map[string]int(x)`,
		`chan int(x)`,
		`(int)(x)`,
	} {
		call := parseTestExpr(t, expr).(*ast.CallExpr)
		if !cgoIsType(call.Fun) {
			t.Errorf("cgoIsType rejected the conversion callee of %q", expr)
		}
	}
}

// cgoStripConversions unwraps conversions until the first callee it cannot
// certify, and never consumes a multi-argument call, which gcc.go guards with
// the len(c.Args) != 1 check shared by all three shape matchers.
func TestCgoStripConversionsStops(t *testing.T) {
	// unsafe.Pointer is a type, C.f is not: the chain stops at the nested
	// call, exactly as gcc.go's stripping loops do.
	nested := parseTestExpr(t, `unsafe.Pointer(C.f(1))`).(*ast.CallExpr)
	got := cgoStripConversions(nested)
	if _, ok := got.(*ast.CallExpr); !ok {
		t.Fatalf("stripping reduced %q to %T, want the inner C.f call", "unsafe.Pointer(C.f(1))", got)
	}
	if got.Pos() != nested.Args[0].Pos() {
		t.Errorf("stripping stopped at %v, want the inner C.f(1) call", got.Pos())
	}
	plain := parseTestExpr(t, `C.f(1)`).(*ast.CallExpr)
	if result := cgoStripConversions(plain); result != ast.Expr(plain) {
		t.Errorf("stripping consumed the C.f(1) call even though C.f is not a type")
	}
	two := parseTestExpr(t, `unsafe.Pointer(x)`).(*ast.CallExpr)
	two.Args = append(two.Args, two.Args[0])
	if result := cgoStripConversions(two); result != ast.Expr(two) {
		t.Errorf("stripping consumed a two-argument call")
	}
}

// parseTestExpr parses one expression, wrapped in a C-calling function so the
// C and unsafe identifiers resolve the way the walker sees them.
func parseTestExpr(t *testing.T, expr string) ast.Expr {
	t.Helper()
	src := "package p\n\n/*\n#include <stdlib.h>\n*/\nimport \"C\"\n\nimport \"unsafe\"\n\nvar s struct{ field *int }\nvar x int\nvar buf []byte\nvar arr [4]int\nvar cs *C.char\nvar dst, src []byte\nvar cgoFill func(a, b []byte)\nvar fill func(p unsafe.Pointer)\nvar wrapper func(p unsafe.Pointer)\nvar p unsafe.Pointer\nvar custom int\n\nfunc _() {\n	_ = " + expr + "\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing the wrapper for %q: %v", expr, err)
	}
	var found ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		if found == nil {
			found = assign.Rhs[0]
		}
		return true
	})
	if found == nil {
		t.Fatalf("no expression found for %q", expr)
	}
	return found
}

func mustShape(arg ast.Expr) string {
	s, _ := cgoCheckShape(arg)
	return s
}
