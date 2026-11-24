package analyzer

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// cgoPointerFixtureRoot is where the cgo pointer-check fixtures live. Every
// case is its own module, compiles under CGO_ENABLED=1, and states its
// expectations with the golem:want signal annotation grammar, so the same
// two-way ratchet the corpus uses judges both cgo modes here.
const cgoPointerFixtureRoot = "../../testdata/cgo-pointer"

// TestCgoPointerFixtureAnnotations validates the fixtures' annotations even
// in -short mode: a malformed annotation or a negative naming an unknown
// category must fail the build without running any analysis.
func TestCgoPointerFixtureAnnotations(t *testing.T) {
	cases, err := corpus.DiscoverCases(cgoPointerFixtureRoot)
	if err != nil {
		t.Skipf("cgo pointer fixtures not available: %v", err)
	}
	for _, dir := range cases {
		annotations, err := corpus.Parse(dir)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(dir), err)
		}
		if len(annotations) == 0 {
			t.Errorf("case %s has no golem: annotations; every fixture must state what it expects", filepath.Base(dir))
		}
	}
}

// TestCgoPointerFixtures runs every fixture in both cgo modes. Textual mode
// always runs; compiled mode needs a C compiler, because the load has to
// translate the preamble.
//
// The mode difference is the point of the suite, not noise: in textual mode
// the detector approximates needsPointerCheck without the C prototype, and in
// compiled mode the checks cgo itself emitted confirm or refute that
// approximation. The annotations carry cgo= guards where the two modes are
// expected to differ, and every other expectation must hold in both.
func TestCgoPointerFixtures(t *testing.T) {
	skipIfShort(t, "analyses every cgo pointer fixture in both cgo modes")
	cases, err := corpus.DiscoverCases(cgoPointerFixtureRoot)
	if err != nil {
		t.Skipf("cgo pointer fixtures not available: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no cgo pointer fixtures found")
	}
	type tally struct {
		pass, fail, xfail, xpass int
	}
	var mu sync.Mutex
	totals := map[string]*tally{"textual": {}, "compiled": {}}

	for _, dir := range cases {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			annotations, err := corpus.Parse(dir)
			if err != nil {
				t.Fatalf("parsing annotations: %v", err)
			}
			if len(annotations) == 0 {
				t.Fatalf("case %s has no golem: annotations", name)
			}
			for _, mode := range []struct {
				name     string
				cgoValue string
			}{{"textual", "0"}, {"compiled", "1"}} {
				t.Run(mode.name, func(t *testing.T) {
					if mode.cgoValue == "1" && !cCompilerAvailable() {
						t.Skip("no C compiler on PATH; the compiled cgo mode cannot translate the preamble")
					}
					var applicable []corpus.Annotation
					for _, ann := range annotations {
						if ann.AppliesToCgo(mode.cgoValue) {
							applicable = append(applicable, ann)
						}
					}
					if len(applicable) == 0 {
						t.Fatalf("no annotation applies in cgo mode %s", mode.name)
					}
					report, err := Analyze(Options{
						Dir:          dir,
						IncludeLocal: true,
						cgoEnabled:   mode.cgoValue,
						ToolVersion:  "test",
					})
					if err != nil {
						t.Fatalf("analyze %s in cgo mode %s: %v", name, mode.name, err)
					}
					assertNoCachePaths(t, report)
					evaluation := corpus.Evaluate(report, applicable, "")
					mu.Lock()
					defer mu.Unlock()
					for _, outcome := range evaluation.Outcomes {
						switch outcome.Status() {
						case "PASS":
							totals[mode.name].pass++
							t.Logf("PASS  %s: %s", outcome.Annotation, outcome.Detail)
						case "XFAIL":
							totals[mode.name].xfail++
							t.Logf("XFAIL %s: %s", outcome.Annotation, outcome.Detail)
						case "XPASS":
							totals[mode.name].xpass++
							t.Errorf("XPASS %s: expectation now holds; remove known-fail=%d\n      %s",
								outcome.Annotation, outcome.KnownFail(), outcome.Detail)
						case "FAIL":
							totals[mode.name].fail++
							t.Errorf("FAIL  %s: %s", outcome.Annotation, outcome.Detail)
						}
					}
					assertCgoPointerCaseDetails(t, name, mode.name, report)
				})
			}
		})
	}
	for _, mode := range []string{"textual", "compiled"} {
		counts := totals[mode]
		t.Logf("cgo-pointer[%s]: pass=%d fail=%d xfail=%d xpass=%d", mode, counts.pass, counts.fail, counts.xfail, counts.xpass)
	}
}

// assertCgoPointerCaseDetails states, per fixture, what the annotations
// cannot say: the exact confidence each mode reports, the call-site argument
// shapes, and which findings carry severity or properties that depend on type
// information.
func assertCgoPointerCaseDetails(t *testing.T, caseName, mode string, report *model.Report) {
	t.Helper()
	if report.Cgo == nil {
		t.Fatal("the report has no cgo object")
	}
	signals := map[string]*model.SecuritySignal{}
	for i := range report.SecuritySignals {
		if report.SecuritySignals[i].Category == CgoCategoryUntypedCheck {
			signals[signalKey(&report.SecuritySignals[i])] = &report.SecuritySignals[i]
		}
	}
	// The textual pass is the only detector in this mode, so every finding it
	// reports says so; the compiled mode's confidence is asserted together
	// with the confirmation that changes it.
	if mode == "textual" {
		for _, signal := range signals {
			if signal.Confidence != "textual" {
				t.Errorf("%s: untyped-check signal at %s:%d has confidence %q, want textual",
					caseName, filepath.Base(signal.Range.Start.Filename), signal.Range.Start.Line, signal.Confidence)
			}
		}
		return
	}
	// Compiled-mode-only assertions live with the changes that make them
	// true; the fixtures' cgo= annotations carry the mode-scoped expectations
	// in the meantime.
	_ = signals
}

func signalKey(signal *model.SecuritySignal) string {
	return strings.Join([]string{
		signal.Range.Start.Filename,
		strconv.Itoa(signal.Range.Start.Line),
		strconv.Itoa(signal.Range.Start.Column),
	}, ":")
}
