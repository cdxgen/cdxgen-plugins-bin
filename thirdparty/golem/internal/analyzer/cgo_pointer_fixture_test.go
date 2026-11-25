package analyzer

import (
	"path/filepath"
	"sort"
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
						CgoEnabled:   mode.cgoValue,
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
		// Line 40 reaches the struct through a *plain: the scanned object is
		// the plain value, so it must not read as a pointer slot.
		for _, key := range []string{"27:9", "40:9"} {
			signal, ok := signals["main.go:"+key]
			if !ok {
				t.Errorf("plain-struct: no compiled finding at main.go:%s", key)
				continue
			}
			if signal.Severity != "medium" || len(signal.Properties) != 0 {
				t.Errorf("plain-struct: finding at main.go:%s has severity %q and properties %v; a struct without pointer fields stays medium",
					key, signal.Severity, signal.Properties)
			}
		}
	case "c-memory":
		if _, ok := signals["main.go:25:9"]; ok {
			t.Error("c-memory: C.free over a C.CString result produced a finding; the runtime stops at non-Go memory")
		}
		if _, ok := signals["main.go:34:9"]; ok {
			t.Error("c-memory: handing C-owned memory to another C function produced a finding")
		}
		if signal, ok := signals["main.go:45:9"]; ok {
			if signal.Severity != "medium" {
				t.Errorf("c-memory: the Go-memory contrast finding has severity %q, want medium: a byte slice holds no pointers", signal.Severity)
			}
		} else {
			t.Error("c-memory: the Go-memory contrast produced no compiled finding")
		}
		if signal, ok := signals["main.go:80:9"]; ok {
			if signal.Severity != "low" || signal.Properties["memoryOwner"] != "unknown" {
				t.Errorf("c-memory: the parameter finding has severity %q properties %v, want low with memoryOwner=unknown", signal.Severity, signal.Properties)
			}
		} else {
			t.Error("c-memory: the unsafe.Pointer parameter produced no compiled finding")
		}
	case "pin-state":
		if signal, ok := signals["main.go:30:9"]; ok {
			if signal.Severity != "high" || signal.Properties["panicRisk"] != "true" {
				t.Errorf("pin-state: the unpinned finding has severity %q properties %v, want high with panicRisk", signal.Severity, signal.Properties)
			}
		} else {
			t.Error("pin-state: the unpinned call produced no compiled finding")
		}
		if signal, ok := signals["main.go:48:9"]; ok {
			if signal.Severity != "medium" || signal.Properties["pinned"] != "true" {
				t.Errorf("pin-state: the pinned finding has severity %q properties %v, want medium with pinned=true: every pointer the scan meets is pinned",
					signal.Severity, signal.Properties)
			}
		} else {
			t.Error("pin-state: the pinned call produced no compiled finding")
		}
		// Pin(&s.other) pins s, not s.other's target, and panics at run time.
		if signal, ok := signals["main.go:67:9"]; ok {
			if signal.Severity != "high" || signal.Properties["panicRisk"] != "true" || signal.Properties["pinned"] != "" {
				t.Errorf("pin-state: the wrong-pin finding has severity %q properties %v, want high with panicRisk and no pinned",
					signal.Severity, signal.Properties)
			}
		} else {
			t.Error("pin-state: the wrong-pin call produced no compiled finding")
		}
		pinnedArgs := map[int]bool{}
		for _, site := range report.Cgo.CallSites {
			for _, argument := range site.Arguments {
				pinnedArgs[site.Position.Line] = argument.Pinned
			}
		}
		if pinnedArgs[30] || !pinnedArgs[48] || pinnedArgs[67] {
			t.Errorf("pin-state: call-site pinned flags by line = %v, want only line 48 pinned", pinnedArgs)
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
	// The unpinned-reachable findings of the linked-list case: the recursive
	// type behind the unpinned and the head-only-pinned calls, and silence for
	// the loop-pinned list and the two-level structures next to them.
	if caseName == "linked-list" && mode == "compiled" {
		var reachable []*model.SecuritySignal
		for i := range report.SecuritySignals {
			if report.SecuritySignals[i].Category == CgoCategoryUnpinnedReachable {
				reachable = append(reachable, &report.SecuritySignals[i])
			}
		}
		var lines []string
		for _, s := range reachable {
			lines = append(lines, strconv.Itoa(s.Range.Start.Line))
			if s.Confidence != "type-resolved" {
				t.Errorf("linked-list: finding at line %d has confidence %q, want type-resolved", s.Range.Start.Line, s.Confidence)
			}
			// The list is recursive; the c0 chain is finite and three levels
			// deep, one more than the check follows.
			wantProps := map[string]string{"recursive": "true"}
			if s.Range.Start.Line == 113 {
				wantProps = map[string]string{"pointerChainDepth": "3"}
			}
			for key, value := range wantProps {
				if s.Properties[key] != value {
					t.Errorf("linked-list: finding at line %d has properties %v, want %s=%s", s.Range.Start.Line, s.Properties, key, value)
				}
			}
		}
		sort.Strings(lines)
		if strings.Join(lines, ",") != "113,41,53" {
			t.Errorf("linked-list: unpinned-reachable findings at lines %v, want exactly 41, 53 and 113", lines)
		}
		if got := report.Cgo.UnpinnedReachableCount; got != len(reachable) {
			t.Errorf("linked-list: unpinnedReachableCount = %d, want %d, one per finding", got, len(reachable))
		}
	}
}

func signalKey(signal *model.SecuritySignal) string {
	return filepath.Base(signal.Range.Start.Filename) + ":" +
		strconv.Itoa(signal.Range.Start.Line) + ":" + strconv.Itoa(signal.Range.Start.Column)
}

// TestCgoGocheckEnvDisabled covers the environment half of the
// cgocheck-disabled finding: the load environment naming cgocheck=0 marks
// the cgo object, names the GODEBUG override, and stays silent in a module
// without cgo. The process environment is process-wide, which is why this
// test cannot run beside the parallel fixture suite.
func TestCgoGocheckEnvDisabled(t *testing.T) {
	t.Setenv("GODEBUG", "cgocheck=0")
	report, err := Analyze(Options{Dir: filepath.Join(cgoPointerFixtureRoot, "docker-gocheck"), IncludeLocal: true, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("analyze docker-gocheck with GODEBUG=cgocheck=0: %v", err)
	}
	if report.Cgo == nil || !report.Cgo.GocheckEnvDisabled {
		t.Fatal("the load environment carried cgocheck=0 and the cgo object does not say so")
	}
	if !containsString(report.Cgo.EnvOverrideNames, "GODEBUG") {
		t.Errorf("env override names = %v, want GODEBUG among them", report.Cgo.EnvOverrideNames)
	}
	if !containsString(report.Cgo.RiskCategories, CgoCategoryGocheckDisabled) {
		t.Errorf("risk categories = %v, want cgocheck-disabled", report.Cgo.RiskCategories)
	}
	if got := report.Cgo.GocheckFileDisabledCount; got != 1 {
		t.Errorf("file disabled count = %d, want the Dockerfile hit", got)
	}
	pure, err := Analyze(Options{Dir: filepath.Join(cgoPointerFixtureRoot, "pure-go-check"), IncludeLocal: true, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("analyze pure-go-check with GODEBUG=cgocheck=0: %v", err)
	}
	if pure.Cgo != nil && (pure.Cgo.GocheckEnvDisabled || pure.Cgo.GocheckDisabled) {
		t.Error("a module without cgo reported cgocheck-disabled from the environment")
	}
}

// TestCgoGocheckEnvHelpers pins the value parsing: a GODEBUG value with
// other knobs beside cgocheck=0 still disables, cgocheck=1 does not, and
// cgocheck=011 is not zero. GOEXPERIMENT=cgocheck2 is the informational
// stronger check, not a disablement.
func TestCgoGocheckEnvHelpers(t *testing.T) {
	disabling := [][]string{
		{"GODEBUG=cgocheck=0"},
		{"GODEBUG=asyncpreemptoff=1,cgocheck=0"},
		{"GODEBUG=cgocheck=0,madvdontneed=1"},
		{"other=x", "GODEBUG=cgocheck=0"},
	}
	for _, environ := range disabling {
		if !gocheckDisabledInEnv(environ) {
			t.Errorf("gocheckDisabledInEnv(%v) = false, want true", environ)
		}
	}
	benign := [][]string{
		{"GODEBUG=cgocheck=1"},
		{"GODEBUG=asyncpreemptoff=1"},
		{"GODEBUG=cgocheck=011"},
		{"GODEBUG=cgocheck=0,cgocheck=1"},
		{"GODEBUG=nocgocheck=0"},
		{"GODEBUG="},
		{"CGO_ENABLED=1"},
		nil,
	}
	for _, environ := range benign {
		if gocheckDisabledInEnv(environ) {
			t.Errorf("gocheckDisabledInEnv(%v) = true, want false", environ)
		}
	}
	if !gocheck2EnabledInEnv("cgocheck2", nil) {
		t.Error("GOEXPERIMENT=cgocheck2 from the toolchain probe was not seen")
	}
	if !gocheck2EnabledInEnv("", []string{"GOEXPERIMENT=cgocheck2"}) {
		t.Error("GOEXPERIMENT=cgocheck2 from the environment was not seen")
	}
	if gocheck2EnabledInEnv("simd", []string{"GOEXPERIMENT=notcgocheck2"}) {
		t.Error("a non-cgocheck2 experiment was reported as cgocheck2")
	}
	if !gocheck2EnabledInEnv("", []string{"GOEXPERIMENT=simd,cgocheck2"}) {
		t.Error("cgocheck2 inside a GOEXPERIMENT list was not seen")
	}
	if gocheck2EnabledInEnv("cgocheck2,nocgocheck2", nil) {
		t.Error("a later nocgocheck2 did not turn the experiment back off")
	}
}

// TestGocheckLineDisables covers the one-line configuration forms: shell and
// Dockerfile assignments, compose map and list entries, and the names that
// only contain GODEBUG.
func TestGocheckLineDisables(t *testing.T) {
	for _, line := range []string{
		`ENV GODEBUG=cgocheck=0`,
		`ENV GODEBUG cgocheck=0`,
		`ENV A=1 GODEBUG=cgocheck=0`,
		`export GODEBUG="madvdontneed=1,cgocheck=0"`,
		`GODEBUG := cgocheck=0`,
		`      GODEBUG: "cgocheck=0"`,
		`      - GODEBUG=cgocheck=0`,
		`GODEBUG=cgocheck=0 ./server # disable the check`,
	} {
		if !gocheckLineDisables(line) {
			t.Errorf("gocheckLineDisables(%q) = false, want true", line)
		}
	}
	for _, line := range []string{
		`# ENV GODEBUG=cgocheck=0`,
		`ENV MY_GODEBUG=cgocheck=0`,
		`ENV GODEBUGGER=cgocheck=0`,
		`ENV GODEBUG=cgocheck=1`,
		`ENV GODEBUG=cgocheck=0,cgocheck=1`,
		`ENV GODEBUG=http2debug=1`,
	} {
		if gocheckLineDisables(line) {
			t.Errorf("gocheckLineDisables(%q) = true, want false", line)
		}
	}
}

// TestCgoBufferTaintTextualMode runs the corpus taint case with cgo off.
// The package cannot load — the loader refuses its cgo files — so the
// http-input flow cannot exist in this mode, and the textual boundary
// signal is what the report still carries. The point of the test is that
// both statements stay true: no flow in textual mode, the flow in compiled
// mode (which the corpus driver asserts), and a cgo object in both.
func TestCgoBufferTaintTextualMode(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and analyses the cgo taint case")
	}
	report, err := Analyze(Options{
		Dir:          "../../testdata/corpus/cgo-buffer-taint",
		IncludeLocal: true,
		CgoEnabled:   "0",
		DataFlowMode: "security",
		ToolVersion:  "test",
	})
	if err != nil {
		t.Fatalf("analyze cgo-buffer-taint with cgo off: %v", err)
	}
	if report.Cgo == nil || report.Cgo.FileCount != 1 {
		t.Fatalf("the textual read lost the cgo file: %+v", report.Cgo)
	}
	if findSignal(report, "native-interop") == nil {
		t.Error("the textual boundary signal is missing in the disabled mode")
	}
	if report.DataFlow != nil {
		for _, slice := range report.DataFlow.Slices {
			if slice.SourceCategory == "http-input" && slice.SinkCategory == "native-interop" {
				t.Errorf("a textual-mode run produced the compiled-only flow %s; the package cannot load with cgo off", slice.FlowKey)
			}
		}
	}
}
