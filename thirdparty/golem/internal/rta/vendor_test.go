package rta

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A vendored copy rots in two directions, and both are silent without a
// test. Bump x/tools and this copy quietly stays at the old release while
// everything around it moves; ship the upstream fix and this copy quietly
// outlives its reason. TestVendoredCopyMatchesUpstream and
// TestVendoredVersionMatchesGoMod make each of those a failure.

// TestVendoredVersionMatchesGoMod pins upstreamVersion to the x/tools
// release golem actually compiles against.
func TestVendoredVersionMatchesGoMod(t *testing.T) {
	gomod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	var required string
	for _, line := range strings.Split(string(gomod), "\n") {
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "require ")))
		if len(fields) >= 2 && fields[0] == "golang.org/x/tools" {
			required = fields[1]
			break
		}
	}
	if required == "" {
		t.Fatal("no golang.org/x/tools requirement in go.mod")
	}
	if required != upstreamVersion {
		t.Fatalf("go.mod has x/tools %s but internal/rta was vendored from %s.\n"+
			"Re-vendor go/callgraph/rta/rta.go and internal/typesinternal/element.go from %s,\n"+
			"or — if %s carries the golang/go#80973 fix — delete internal/rta and restore the\n"+
			"golang.org/x/tools/go/callgraph/rta import in internal/analyzer/callgraph.go.",
			required, upstreamVersion, required, required)
	}
}

// TestVendoredCopyMatchesUpstream holds the copy to its promise: every
// upstream line, in order, plus nothing but the #80973 guards. A drift
// here means someone edited the copy as if it were golem's own code,
// which is how a vendored fix becomes an unreviewable fork.
func TestVendoredCopyMatchesUpstream(t *testing.T) {
	root := upstreamRoot(t)
	for _, f := range []struct {
		vendored string
		upstream string
		rewrite  func(string) string
	}{
		// The rewrites are the whole licence to differ: a package
		// clause, and the two references to x/tools' internal
		// typesinternal package, which cannot be imported from here.
		{"rta.go", filepath.Join("go", "callgraph", "rta", "rta.go"), func(s string) string {
			return strings.NewReplacer(
				`package rta // import "golang.org/x/tools/go/callgraph/rta"`,
				"package rta // golem: vendored; see vendor.go",
				"\t\"golang.org/x/tools/internal/typesinternal\"\n", "",
				"typesinternal.ForEachElement(", "forEachElement(",
			).Replace(s)
		}},
		{"element.go", filepath.Join("internal", "typesinternal", "element.go"), func(s string) string {
			return strings.NewReplacer(
				"package typesinternal", "package rta // golem: vendored; see vendor.go",
				"ForEachElement", "forEachElement",
			).Replace(s)
		}},
	} {
		t.Run(f.vendored, func(t *testing.T) {
			upstream := f.rewrite(readFile(t, filepath.Join(root, f.upstream)))
			vendored := readFile(t, f.vendored)

			// The upstream fix landing is the signal to delete this
			// directory, not to keep diffing against it.
			if strings.Contains(upstream, "#80973") || strings.Contains(upstream, "cmethod == nil") {
				t.Fatalf("x/tools %s appears to carry the golang/go#80973 fix: delete internal/rta and "+
					"restore the golang.org/x/tools/go/callgraph/rta import in internal/analyzer/callgraph.go", upstreamVersion)
			}
			assertUpstreamPreserved(t, upstream, vendored)
		})
	}
}

// assertUpstreamPreserved checks that vendored contains every line of
// upstream in order, and that each run of inserted lines is a guard: it
// mentions the issue the guard exists for. Package documentation is
// compared too — a vendored copy whose doc drifts stops being diffable.
func assertUpstreamPreserved(t *testing.T, upstream, vendored string) {
	t.Helper()
	want := strings.Split(upstream, "\n")
	got := strings.Split(vendored, "\n")

	var inserted []string
	flush := func(at int) {
		if len(inserted) == 0 {
			return
		}
		if !strings.Contains(strings.Join(inserted, "\n"), "#80973") {
			t.Errorf("lines added at vendored line %d are not part of a #80973 guard:\n\t%s",
				at-len(inserted)+1, strings.Join(inserted, "\n\t"))
		}
		inserted = nil
	}

	w := 0
	for g, line := range got {
		if w < len(want) && line == want[w] {
			flush(g)
			w++
			continue
		}
		inserted = append(inserted, line)
	}
	flush(len(got))
	if w != len(want) {
		t.Errorf("upstream line %d is missing from the vendored copy (matched %d of %d lines): %q",
			w+1, w, len(want), want[w])
	}
}

// upstreamRoot locates the pinned x/tools in the module cache, skipping
// when it is absent: the copy is self-contained, so a vendor check that
// needs the network must not be the reason a build fails.
func upstreamRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("cannot locate the module cache: %v", err)
	}
	root := filepath.Join(strings.TrimSpace(string(out)), "golang.org", "x", "tools@"+upstreamVersion)
	if _, err := os.Stat(root); err != nil {
		t.Skipf("x/tools %s is not extracted in the module cache: %v", upstreamVersion, err)
	}
	return root
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
