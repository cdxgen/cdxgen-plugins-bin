package native

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrimCgoPrefix(t *testing.T) {
	cases := map[string]struct {
		symbol string
		ok     bool
	}{
		"_Cfunc_sqlite3_open":      {"sqlite3_open", true},
		"_cgo_Cfunc_sqlite3_close": {"sqlite3_close", true},
		"_Cfunc_GoString":          {"GoString", true},
		"Handler":                  {"", false},
		"_Cgo_ptr":                 {"", false},
	}
	for name, want := range cases {
		symbol, ok := trimCgoPrefix(name)
		if symbol != want.symbol || ok != want.ok {
			t.Errorf("trimCgoPrefix(%q) = %q,%v; want %q,%v", name, symbol, ok, want.symbol, want.ok)
		}
	}
}

// TestCgoHelpersAreNotReportedAsCSymbols guards the distinction between a
// symbol the project links against and a conversion cgo wrote for itself.
// Reporting C.GoString as an external C function named "GoString" would send a
// reader looking for a declaration that does not exist.
func TestCgoHelpersAreNotReportedAsCSymbols(t *testing.T) {
	for name, helper := range cgoHelpers {
		if helper.direction != DirectionGoToC && helper.direction != DirectionCToGo {
			t.Errorf("helper %s has direction %q", name, helper.direction)
		}
	}
	for _, name := range []string{"GoString", "GoStringN", "GoBytes"} {
		if cgoHelpers[name].direction != DirectionCToGo {
			t.Errorf("%s moves data from C to Go, but is recorded as %q", name, cgoHelpers[name].direction)
		}
	}
	for _, name := range []string{"CString", "CBytes"} {
		if cgoHelpers[name].direction != DirectionGoToC {
			t.Errorf("%s moves data from Go to C, but is recorded as %q", name, cgoHelpers[name].direction)
		}
	}
}

func TestParseLinkname(t *testing.T) {
	local, target, ok := parseLinkname("go:linkname runCommand example.com/pkg.runCmd")
	if !ok || local != "runCommand" || target != "example.com/pkg.runCmd" {
		t.Errorf("parsed %q,%q,%v", local, target, ok)
	}
	// The one-argument form only publishes a symbol and names no target.
	if _, _, ok := parseLinkname("go:linkname runCommand"); ok {
		t.Error("a directive with no target was accepted")
	}
	if _, _, ok := parseLinkname("go:generate stringer"); ok {
		t.Error("an unrelated pragma parsed as a linkname")
	}
}

func TestSplitQualified(t *testing.T) {
	pkg, name, ok := splitQualified("net/http.HandlerFunc")
	if !ok || pkg != "net/http" || name != "HandlerFunc" {
		t.Errorf("splitQualified = %q,%q,%v", pkg, name, ok)
	}
	if _, _, ok := splitQualified("bare"); ok {
		t.Error("an unqualified name was split")
	}
}

func TestPreambleReadsIncludesAndLibraries(t *testing.T) {
	preamble := &cgoPreamble{}
	for _, line := range []string{
		"#cgo LDFLAGS: -lsqlite3 -lm",
		"#cgo CFLAGS: -I/usr/local/include",
		`#include <sqlite3.h>`,
	} {
		preamble.absorb(line)
	}
	if len(preamble.libraries) != 2 || preamble.libraries[0] != "-lsqlite3" {
		t.Errorf("libraries = %v", preamble.libraries)
	}
	if got := preamble.headerFor("sqlite3_open"); got != "sqlite3.h" {
		t.Errorf("headerFor = %q, want sqlite3.h", got)
	}
	// With two includes there is no way to tell which declared the symbol, and
	// a wrong attribution is worse than none.
	preamble.absorb(`#include "extra.h"`)
	if got := preamble.headerFor("sqlite3_open"); got != "" {
		t.Errorf("headerFor guessed %q from an ambiguous preamble", got)
	}
}

// TestBuildConstraintOfReadsTheExpression is the difference between a useful
// diagnostic and a guess: `//go:build !cgo` is the most interesting exclusion
// in a hybrid project and no filename encodes it.
func TestBuildConstraintOfReadsTheExpression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fallback.go")
	if err := os.WriteFile(path, []byte("//go:build !cgo\n\npackage p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := buildConstraintOf(path); got != "!cgo" {
		t.Errorf("buildConstraintOf = %q, want !cgo", got)
	}

	named := filepath.Join(dir, "sys_windows.go")
	if err := os.WriteFile(named, []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := buildConstraintOf(named); got != "GOOS=windows" {
		t.Errorf("buildConstraintOf = %q, want GOOS=windows", got)
	}

	plain := filepath.Join(dir, "plain.go")
	if err := os.WriteFile(plain, []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := buildConstraintOf(plain); got != "" {
		t.Errorf("buildConstraintOf invented a constraint %q for an unconstrained file", got)
	}
}
