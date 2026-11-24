package analyzer

import (
	"path/filepath"
	"strconv"
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
// cannot say: the exact confidence each mode reports, the severities and
// properties the type escalation adds, and the absence of findings on the
// calls whose arguments are C-owned or pinned.
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
	if mode == "textual" {
		// The textual pass is the only detector in this mode, so every
		// finding it reports says so.
		for _, signal := range signals {
			if signal.Confidence != "textual" {
				t.Errorf("%s: untyped-check signal at %s:%d has confidence %q, want textual",
					caseName, filepath.Base(signal.Range.Start.Filename), signal.Range.Start.Line, signal.Confidence)
			}
			if signal.Severity != "medium" {
				t.Errorf("%s: textual signal at %s:%d has severity %q, want medium without type information",
					caseName, filepath.Base(signal.Range.Start.Filename), signal.Range.Start.Line, signal.Severity)
			}
			if len(signal.Properties) != 0 {
				t.Errorf("%s: textual signal at %s:%d carries properties %v; escalation needs type information",
					caseName, filepath.Base(signal.Range.Start.Filename), signal.Range.Start.Line, signal.Properties)
			}
		}
		return
	}
	for _, signal := range signals {
		if signal.Confidence != "high" {
			t.Errorf("%s: compiled signal at %s:%d has confidence %q, want high: the compiled pass is exact",
				caseName, filepath.Base(signal.Range.Start.Filename), signal.Range.Start.Line, signal.Confidence)
		}
	}
	// Per-fixture escalation verdicts, from the types the generated files
	// carry. (line, severity, properties)
	type want struct {
		line  int
		col   int
		props map[string]string
	}
	switch caseName {
	case "addr-shapes":
		// Both untyped arguments scan a pair object whose other field holds
		// a Go pointer: panic risk, one pointer slot.
		for _, key := range []string{"39:9", "49:9"} {
			signal, ok := signals["main.go:"+key]
			if !ok {
				t.Errorf("addr-shapes: no compiled finding at main.go:%s", key)
				continue
			}
			if signal.Severity != "high" {
				t.Errorf("addr-shapes: finding at main.go:%s has severity %q, want high: the object holds a Go pointer", key, signal.Severity)
			}
			if signal.Properties["panicRisk"] != "true" || signal.Properties["pointerSlots"] != "1" {
				t.Errorf("addr-shapes: finding at main.go:%s has properties %v, want panicRisk and pointerSlots=1", key, signal.Properties)
			}
		}
	case "plain-struct":
		if signal, ok := signals["main.go:27:9"]; ok && (signal.Severity != "medium" || len(signal.Properties) != 0) {
			t.Errorf("plain-struct: finding at main.go:27 has severity %q and properties %v; a struct without pointer fields stays medium",
				signal.Severity, signal.Properties)
		}
	case "c-memory":
		if _, ok := signals["main.go:23:9"]; ok {
			t.Error("c-memory: C.free over a C.CString result produced a finding; the runtime stops at non-Go memory")
		}
		if _, ok := signals["main.go:32:9"]; ok {
			t.Error("c-memory: handing C-owned memory to another C function produced a finding")
		}
		if signal, ok := signals["main.go:43:9"]; ok {
			if signal.Severity != "medium" {
				t.Errorf("c-memory: the Go-memory contrast finding has severity %q, want medium: a byte slice holds no pointers", signal.Severity)
			}
		} else {
			t.Error("c-memory: the Go-memory contrast produced no compiled finding")
		}
	case "pin-state":
		if signal, ok := signals["main.go:30:9"]; ok {
			if signal.Severity != "high" || signal.Properties["panicRisk"] != "true" {
				t.Errorf("pin-state: the unpinned finding has severity %q properties %v, want high with panicRisk", signal.Severity, signal.Properties)
			}
		} else {
			t.Error("pin-state: the unpinned call produced no compiled finding")
		}
		if signal, ok := signals["main.go:47:9"]; ok {
			if signal.Severity != "medium" || signal.Properties["pinned"] != "true" {
				t.Errorf("pin-state: the pinned finding has severity %q properties %v, want medium with pinned=true: a pinned object cannot panic the scan",
					signal.Severity, signal.Properties)
			}
		} else {
			t.Error("pin-state: the pinned call produced no compiled finding")
		}
	case "buffer-shapes":
		if signal, ok := signals["main.go:59:9"]; ok {
			if signal.Severity != "medium" {
				t.Errorf("buffer-shapes: the SliceData finding has severity %q, want medium: the buffer elements are C ints", signal.Severity)
			}
		} else {
			t.Error("buffer-shapes: the SliceData call produced no compiled finding")
		}
	}
}

func signalKey(signal *model.SecuritySignal) string {
	return filepath.Base(signal.Range.Start.Filename) + ":" +
		strconv.Itoa(signal.Range.Start.Line) + ":" + strconv.Itoa(signal.Range.Start.Column)
}
