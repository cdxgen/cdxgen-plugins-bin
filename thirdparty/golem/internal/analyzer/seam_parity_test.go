package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// parityExceptionsPath lists corpus cases where SEAM is knowingly allowed to
// differ from the legacy engine, each with a reason.
const parityExceptionsPath = "../../testdata/seam-parity.json"

// parityExceptions is the exception list, keyed by "case/mode".
type parityExceptions struct {
	Note  string            `json:"note"`
	Cases map[string]string `json:"cases"`
}

func loadParityExceptions(t *testing.T) parityExceptions {
	t.Helper()
	data, err := os.ReadFile(parityExceptionsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return parityExceptions{Cases: map[string]string{}}
		}
		t.Fatalf("reading %s: %v", parityExceptionsPath, err)
	}
	var out parityExceptions
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parsing %s: %v", parityExceptionsPath, err)
	}
	if out.Cases == nil {
		out.Cases = map[string]string{}
	}
	return out
}

// flowShapes summarises a report as the multiset of source→sink categories it
// reported. Comparing shapes rather than slice identifiers lets the two engines
// differ in how they name and split evidence while still being held to
// reporting the same findings.
func flowShapes(report *model.Report) []string {
	if report == nil || report.DataFlow == nil {
		return nil
	}
	counts := map[string]int{}
	for _, slice := range report.DataFlow.Slices {
		counts[slice.SourceCategory+"->"+slice.SinkCategory]++
	}
	out := make([]string, 0, len(counts))
	for shape, count := range counts {
		out = append(out, fmt.Sprintf("%s x%d", shape, count))
	}
	sort.Strings(out)
	return out
}

func analyzeWithEngine(t *testing.T, dir, mode, engine string) *model.Report {
	t.Helper()
	report, err := Analyze(Options{
		Dir:                   dir,
		IncludeLocal:          true,
		CallGraphMode:         "rta",
		DataFlowMode:          mode,
		DataFlowCallGraphMode: "rta",
		DataFlowMax:           200,
		TaintEngine:           engine,
		ToolVersion:           "test",
	})
	if err != nil {
		t.Fatalf("analyze %s with engine %s in mode %s: %v", dir, engine, mode, err)
	}
	return report
}

// TestSeamParity holds the SEAM engine to the bar it must clear before it is
// worth asking whether it is better: on every corpus case it must report the
// same findings as the shipping engine, and the evidence it emits must be
// well-formed.
//
// Well-formed is the part the legacy engine cannot claim and SEAM exists to
// fix, so it is checked unconditionally: every identifier a slice references
// must exist in the report, and every slice must carry a path that actually
// connects its source to its sink.
//
// The exception list in testdata/seam-parity.json is a ratchet in both
// directions. A case that differs without being listed fails; a listed case
// that has started matching also fails, asking for its entry to be removed.
func TestSeamParity(t *testing.T) {
	skipIfShort(t, "analyses every corpus case under both engines")
	cases, err := corpus.DiscoverCases(corpusRoot)
	if err != nil {
		t.Skipf("corpus not available: %v", err)
	}
	exceptions := loadParityExceptions(t)
	var mu sync.Mutex
	matched := map[string]bool{}

	for _, dir := range cases {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, mode := range corpusSuiteModes() {
				key := name + "/" + mode
				t.Run(mode, func(t *testing.T) {
					legacy := analyzeWithEngine(t, dir, mode, "legacy")
					seam := analyzeWithEngine(t, dir, mode, "seam")

					if seam.DataFlow == nil || seam.DataFlow.Engine != "seam" {
						t.Fatalf("report was not produced by SEAM: engine=%q", engineOf(seam))
					}

					// Well-formedness is never excused.
					if violations := reportIntegrityViolations(seam); len(violations) > 0 {
						t.Errorf("SEAM emitted references it does not define: %s", strings.Join(violations, "; "))
					}
					if connectivity, reasons := corpus.Connectivity(seam.DataFlow); connectivity < 1 {
						t.Errorf("SEAM edge-connectivity %.3f: %s", connectivity, strings.Join(reasons, "; "))
					}

					legacyShapes := flowShapes(legacy)
					seamShapes := flowShapes(seam)
					same := strings.Join(legacyShapes, ", ") == strings.Join(seamShapes, ", ")
					reason, excused := exceptions.Cases[key]
					if same {
						mu.Lock()
						matched[key] = true
						mu.Unlock()
					}
					switch {
					case same && excused:
						t.Errorf("SEAM now matches the legacy engine; remove %q from %s (was: %s)", key, parityExceptionsPath, reason)
					case !same && !excused:
						t.Errorf("SEAM disagrees with the legacy engine.\n  legacy: %v\n  seam:   %v\n  If this difference is intended, record it in %s with a reason.",
							legacyShapes, seamShapes, parityExceptionsPath)
					case !same:
						t.Logf("known difference (%s): legacy=%v seam=%v", reason, legacyShapes, seamShapes)
					}
				})
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	for key := range exceptions.Cases {
		if matched[key] {
			continue
		}
		if _, err := os.Stat(filepath.Join(corpusRoot, strings.SplitN(key, "/", 2)[0])); err != nil {
			t.Errorf("%s lists %q, which is not a corpus case", parityExceptionsPath, key)
		}
	}
}

func engineOf(report *model.Report) string {
	if report == nil || report.DataFlow == nil {
		return "<no dataFlow>"
	}
	return report.DataFlow.Engine
}
