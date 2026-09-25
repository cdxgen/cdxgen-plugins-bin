package analyzer

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestSimdFlowKeysArchitectureIndependent is the acceptance criterion for the
// simd intrinsic rule: the emitted flowKeys must be identical when the same
// fixture is loaded for amd64 (bodiless stubs), arm64 (bodiless stubs) and
// riscv64 (real emulated bodies). A rule keyed on body presence could not hold
// this; one keyed on the callee's package path must.
//
// The target travels through Options.Env — the same plumbing --goexperiment
// and the corpus's golem:env directive use — because tests in this package run
// in parallel and must not touch the process environment. GOOS is pinned to
// linux for all three legs because darwin has no riscv64 target; the fixture is
// pure Go, so the GOOS choice is otherwise immaterial.
func TestSimdFlowKeysArchitectureIndependent(t *testing.T) {
	skipIfShort(t, "loads the simd fixture for three target architectures")
	dir := filepath.Join(corpusRoot, "simd-chunked-loop")
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err != nil {
		t.Skipf("simd fixture not available: %v", err)
	}
	targets := []string{"amd64", "arm64", "riscv64"}
	var want []string
	for _, goarch := range targets {
		env := []string{
			"GOEXPERIMENT=simd",
			"GOOS=linux",
			"GOARCH=" + goarch,
		}
		report, err := Analyze(Options{
			Dir:                   dir,
			IncludeLocal:          true,
			CallGraphMode:         "rta",
			DataFlowMode:          "security",
			DataFlowCallGraphMode: "rta",
			DataFlowMax:           200,
			Env:                   env,
			ToolVersion:           "test",
		})
		if err != nil {
			t.Fatalf("load %s for linux/%s: %v", dir, goarch, err)
		}
		if report.DataFlow == nil || len(report.DataFlow.Slices) == 0 {
			t.Fatalf("linux/%s: no data-flow slices; the simd fixture produced no analysis", goarch)
		}
		var keys []string
		for _, s := range report.DataFlow.Slices {
			keys = append(keys, s.FlowKey)
		}
		sort.Strings(keys)
		if report.Runtime.TargetGOARCH != goarch || report.Runtime.GoExperiment != "simd" {
			t.Errorf("linux/%s: runtime reports targetGoos=%q targetGoarch=%q goExperiment=%q; want linux/%s/simd",
				goarch, report.Runtime.TargetGOOS, report.Runtime.TargetGOARCH, report.Runtime.GoExperiment, goarch)
		}
		if want == nil {
			want = keys
			continue
		}
		if joinedWant, joinedGot := joinOrEmpty(want), joinOrEmpty(keys); joinedWant != joinedGot {
			t.Errorf("linux/%s: flowKeys differ from linux/amd64\n  amd64:  %s\n  %s: %s",
				goarch, joinedWant, goarch, joinedGot)
		}
	}
}

func joinOrEmpty(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += "\n  "
		}
		out += s
	}
	return out
}
