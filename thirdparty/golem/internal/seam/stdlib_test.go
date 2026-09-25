package seam

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// TestIsStandardLibraryPackageUsesLoadMetadata pins the standard-library
// classification to package metadata. The dot-less module cases are the ones
// the old path-shape rule got wrong.
func TestIsStandardLibraryPackageUsesLoadMetadata(t *testing.T) {
	goroot := filepath.Join(t.TempDir(), "go")
	gopath := filepath.Join(t.TempDir(), "gopath")
	module := &packages.Module{Path: "myapp", Main: true}
	cases := []struct {
		name   string
		pkg    *packages.Package
		goroot string
		want   bool
	}{
		{"standard package", &packages.Package{PkgPath: "net/http", Dir: filepath.Join(goroot, "src", "net", "http")}, goroot, true},
		{"vendored standard package", &packages.Package{PkgPath: "vendor/golang.org/x/net/idna", Dir: filepath.Join(goroot, "src", "vendor", "golang.org", "x", "net", "idna")}, goroot, true},
		{"located by its files", &packages.Package{PkgPath: "fmt", GoFiles: []string{filepath.Join(goroot, "src", "fmt", "print.go")}}, goroot, true},
		{"dot-less main module", &packages.Package{PkgPath: "myapp", Dir: "/work/myapp", Module: module}, goroot, false},
		{"dot-less module sub-package", &packages.Package{PkgPath: "myapp/scrub", Dir: "/work/myapp/scrub", Module: module}, goroot, false},
		{"dot-less module named like a carrier", &packages.Package{PkgPath: "encoding/app", Dir: "/work/app", Module: &packages.Module{Path: "encoding/app", Main: true}}, goroot, false},
		{"dot-less GOPATH package", &packages.Package{PkgPath: "myapp", Dir: filepath.Join(gopath, "src", "myapp")}, goroot, false},
		{"sibling of GOROOT's src", &packages.Package{PkgPath: "fmt", Dir: filepath.Join(goroot, "srcx", "fmt")}, goroot, false},
		{"no GOROOT falls back to the path", &packages.Package{PkgPath: "net/http", Dir: "/elsewhere/net/http"}, "", true},
		{"no location falls back to the path", &packages.Package{PkgPath: "example.com/app"}, goroot, false},
		{"nil package", nil, goroot, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsStandardLibraryPackage(tc.pkg, tc.goroot); got != tc.want {
				t.Errorf("IsStandardLibraryPackage = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEngineStandardClassificationFallsBackToModule covers a path with no load
// metadata: a module that owns it still keeps it out of the standard library.
func TestEngineStandardClassificationFallsBackToModule(t *testing.T) {
	e := NewEngine(DefaultOptions())
	e.moduleByPath = map[string]*model.Module{"myapp": {Path: "myapp", Main: true}}
	e.standardByPath = map[string]bool{"fmt": true}
	for path, want := range map[string]bool{"fmt": true, "myapp/scrub": false, "net/http": true, "example.com/x": false} {
		if got := e.isStandardPackage(path); got != want {
			t.Errorf("isStandardPackage(%q) = %v, want %v", path, got, want)
		}
	}
}
