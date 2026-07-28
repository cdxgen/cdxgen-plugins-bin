package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func writeCase(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	source := "package fixture\n\n" + body + "\nfunc F() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestParseFlowAnnotation(t *testing.T) {
	dir := writeCase(t, "// golem:want flow source=http-input sink=command-execution count=2 mode=all connected known-fail=8")
	annotations, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(annotations) != 1 {
		t.Fatalf("got %d annotations, want 1", len(annotations))
	}
	got := annotations[0]
	if !got.Want || got.Kind != KindFlow || got.Source != "http-input" || got.Sink != "command-execution" {
		t.Errorf("unexpected annotation: %+v", got)
	}
	if got.Count != 2 || got.Mode != "all" || !got.Connected || got.KnownFail != 8 {
		t.Errorf("unexpected modifiers: %+v", got)
	}
	if got.Line != 3 {
		t.Errorf("line = %d, want 3", got.Line)
	}
	if !got.AppliesTo("all") || got.AppliesTo("security") {
		t.Errorf("mode gating is wrong for %+v", got)
	}
}

func TestParseRejectsUnknownCategory(t *testing.T) {
	dir := writeCase(t, "// golem:want-not flow source=http-input sink=sql-injection")
	_, err := Parse(dir)
	if err == nil {
		t.Fatal("expected an error for a category the analyzer cannot emit")
	}
	if !strings.Contains(err.Error(), "unknown category") {
		t.Errorf("error = %v, want it to mention the unknown category", err)
	}
}

func TestParseRejectsMalformedAnnotations(t *testing.T) {
	for _, body := range []string{
		"// golem:wish flow source=cli sink=logging",
		"// golem:want flows source=cli sink=logging",
		"// golem:want flow source=cli sink=logging count=many",
		"// golem:want flow source=cli sink=logging bogus=1",
		"// golem:want flow count=2",
		"// golem:want-not flow source=cli sink=logging count=2",
		"// golem:want edge",
		"// golem:want reachable from=main.main",
	} {
		if _, err := Parse(writeCase(t, body)); err == nil {
			t.Errorf("%q parsed without error", body)
		}
	}
}

func TestParseRecursesIntoSubpackages(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "internal", "helper")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "helper.go"), []byte("package helper\n\n// golem:want flow source=cli sink=logging\nfunc H() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	annotations, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(annotations) != 1 {
		t.Fatalf("got %d annotations, want 1 from the nested package", len(annotations))
	}
}

func TestMatches(t *testing.T) {
	for _, tc := range []struct {
		expected, actual string
		want             bool
	}{
		{"", "anything", true},
		{"http-input", "http-input", true},
		{"http-input", "HTTP-INPUT", true},
		{"http", "http-input", false},
		{"~http", "http-input", true},
		{"~INPUT", "http-input", true},
		{"http-input", "http-response", false},
	} {
		if got := Matches(tc.expected, tc.actual); got != tc.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tc.expected, tc.actual, got, tc.want)
		}
	}
}

func report(nodes []model.DataFlowNode, edges []model.DataFlowEdge, slices []model.DataFlowSlice) *model.Report {
	return &model.Report{DataFlow: &model.DataFlowEvidence{Nodes: nodes, Edges: edges, Slices: slices}}
}

func TestConnectivityDetectsEvictedSourceNode(t *testing.T) {
	nodes := []model.DataFlowNode{{ID: "src"}, {ID: "mid"}, {ID: "sink"}}
	edges := []model.DataFlowEdge{{ID: "e1", SourceID: "src", TargetID: "mid"}, {ID: "e2", SourceID: "mid", TargetID: "sink"}}

	whole := model.DataFlowSlice{ID: "s1", SourceID: "src", SinkID: "sink", NodeIDs: []string{"src", "mid", "sink"}, EdgeIDs: []string{"e1", "e2"}}
	if connectivity, _ := Connectivity(&model.DataFlowEvidence{Nodes: nodes, Edges: edges, Slices: []model.DataFlowSlice{whole}}); connectivity != 1 {
		t.Errorf("connectivity of a complete path = %v, want 1", connectivity)
	}

	// A trace accumulator that drops its oldest entry produces exactly this:
	// the source is still named but no longer listed or reachable.
	evicted := model.DataFlowSlice{ID: "s2", SourceID: "src", SinkID: "sink", NodeIDs: []string{"mid", "sink"}, EdgeIDs: []string{"e2"}}
	connectivity, reasons := Connectivity(&model.DataFlowEvidence{Nodes: nodes, Edges: edges, Slices: []model.DataFlowSlice{evicted}})
	if connectivity != 0 {
		t.Errorf("connectivity of a truncated path = %v, want 0", connectivity)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "omit the source") {
		t.Errorf("reasons = %v, want the omitted source to be named", reasons)
	}

	disjoint := model.DataFlowSlice{ID: "s3", SourceID: "src", SinkID: "sink", NodeIDs: []string{"src", "mid", "sink"}, EdgeIDs: []string{"e1"}}
	if connectivity, _ := Connectivity(&model.DataFlowEvidence{Nodes: nodes, Edges: edges, Slices: []model.DataFlowSlice{disjoint}}); connectivity != 0 {
		t.Errorf("connectivity of a broken chain = %v, want 0", connectivity)
	}

	dangling := model.DataFlowSlice{ID: "s4", SourceID: "src", SinkID: "sink", NodeIDs: []string{"src", "ghost", "sink"}, EdgeIDs: []string{"e1", "e2"}}
	_, reasons = Connectivity(&model.DataFlowEvidence{Nodes: nodes, Edges: edges, Slices: []model.DataFlowSlice{dangling}})
	if len(reasons) != 1 || !strings.Contains(reasons[0], "unknown node") {
		t.Errorf("reasons = %v, want the dangling node reported", reasons)
	}
}

func TestEvaluateCountsUnsanctionedFlowsAsFalsePositives(t *testing.T) {
	nodes := []model.DataFlowNode{{ID: "src"}, {ID: "sink"}}
	edges := []model.DataFlowEdge{{ID: "e1", SourceID: "src", TargetID: "sink"}}
	slices := []model.DataFlowSlice{
		{ID: "wanted", SourceID: "src", SinkID: "sink", SourceCategory: "http-input", SinkCategory: "command-execution", NodeIDs: []string{"src", "sink"}, EdgeIDs: []string{"e1"}},
		{ID: "noise1", SourceID: "src", SinkID: "sink", SourceCategory: "http-input", SinkCategory: "logging", NodeIDs: []string{"src", "sink"}, EdgeIDs: []string{"e1"}},
		{ID: "noise2", SourceID: "src", SinkID: "sink", SourceCategory: "http-input", SinkCategory: "logging", NodeIDs: []string{"src", "sink"}, EdgeIDs: []string{"e1"}},
	}
	annotations := []Annotation{{Want: true, Kind: KindFlow, Source: "http-input", Sink: "command-execution"}}

	evaluation := Evaluate(report(nodes, edges, slices), annotations, "all")
	if evaluation.TruePositives != 1 {
		t.Errorf("TruePositives = %d, want 1", evaluation.TruePositives)
	}
	// Both copies of the unannotated flow count: a tool that reports one true
	// finding among many spurious ones is not perfectly precise.
	if evaluation.FalsePositives != 2 {
		t.Errorf("FalsePositives = %d, want 2", evaluation.FalsePositives)
	}
	if got := evaluation.Precision(); got > 0.34 || got < 0.33 {
		t.Errorf("Precision = %v, want about 1/3", got)
	}
}

func TestEvaluateViolatedWantNotIsAFalsePositive(t *testing.T) {
	nodes := []model.DataFlowNode{{ID: "src"}, {ID: "sink"}}
	edges := []model.DataFlowEdge{{ID: "e1", SourceID: "src", TargetID: "sink"}}
	slices := []model.DataFlowSlice{{ID: "bad", SourceID: "src", SinkID: "sink", SourceCategory: "parameter", SinkCategory: "filesystem", NodeIDs: []string{"src", "sink"}, EdgeIDs: []string{"e1"}}}
	annotations := []Annotation{{Kind: KindFlow, Source: "parameter", Sink: "filesystem"}}

	evaluation := Evaluate(report(nodes, edges, slices), annotations, "all")
	if evaluation.FalsePositives == 0 {
		t.Fatal("a violated want-not must count as a false positive")
	}
	if len(evaluation.Unexpected) != 1 || evaluation.Unexpected[0].Status() != "FAIL" {
		t.Errorf("unexpected = %+v, want one FAIL", evaluation.Unexpected)
	}
}

func TestOutcomeStatusRatchet(t *testing.T) {
	for _, tc := range []struct {
		satisfied bool
		knownFail int
		want      string
	}{
		{true, 0, "PASS"},
		{false, 0, "FAIL"},
		{false, 13, "XFAIL"},
		{true, 13, "XPASS"},
	} {
		got := Outcome{Satisfied: tc.satisfied, Annotation: Annotation{KnownFail: tc.knownFail}}.Status()
		if got != tc.want {
			t.Errorf("Status(satisfied=%v, knownFail=%d) = %s, want %s", tc.satisfied, tc.knownFail, got, tc.want)
		}
	}
}

func TestEvaluateConnectedRequirementRejectsBrokenPath(t *testing.T) {
	nodes := []model.DataFlowNode{{ID: "src"}, {ID: "sink"}}
	slices := []model.DataFlowSlice{{ID: "broken", SourceID: "src", SinkID: "sink", SourceCategory: "cli", SinkCategory: "logging", NodeIDs: []string{"src", "sink"}}}
	annotations := []Annotation{{Want: true, Kind: KindFlow, Source: "cli", Sink: "logging", Connected: true}}

	evaluation := Evaluate(report(nodes, nil, slices), annotations, "all")
	if evaluation.TruePositives != 0 || evaluation.FalseNegatives != 1 {
		t.Errorf("a flow with no connecting edges must not satisfy a connected expectation: %+v", evaluation)
	}
}

func TestEvaluateEdgeAndReachable(t *testing.T) {
	callGraph := &model.CallGraph{
		Nodes: []model.CallGraphNode{{ID: "pkg.main", Label: "pkg.main"}, {ID: "pkg.mid", Label: "pkg.mid"}, {ID: "pkg.sink", Label: "pkg.sink"}},
		Edges: []model.CallGraphEdge{
			{ID: "e1", SourceID: "pkg.main", TargetID: "pkg.mid", SourceName: "pkg.main", TargetName: "pkg.mid", CallType: "static"},
			{ID: "e2", SourceID: "pkg.mid", TargetID: "pkg.sink", SourceName: "pkg.mid", TargetName: "pkg.sink", CallType: "interface"},
		},
	}
	rep := &model.Report{CallGraph: callGraph}

	edgeWant := Annotation{Want: true, Kind: KindEdge, Source: "pkg.mid", Sink: "pkg.sink", CallType: "interface"}
	if outcome := evaluateAnnotation(rep, edgeWant); !outcome.Satisfied {
		t.Errorf("edge expectation not satisfied: %s", outcome.Detail)
	}
	wrongType := edgeWant
	wrongType.CallType = "static"
	if outcome := evaluateAnnotation(rep, wrongType); outcome.Satisfied {
		t.Error("edge expectation matched despite the wrong call type")
	}

	reach := Annotation{Want: true, Kind: KindReachable, Symbol: "pkg.sink", Source: "pkg.main", MaxDepth: 2}
	if outcome := evaluateAnnotation(rep, reach); !outcome.Satisfied {
		t.Errorf("reachability expectation not satisfied: %s", outcome.Detail)
	}
	tooDeep := reach
	tooDeep.MaxDepth = 1
	if outcome := evaluateAnnotation(rep, tooDeep); outcome.Satisfied {
		t.Error("reachability expectation ignored maxdepth")
	}
}

// TestEngineScopedKnownFail covers the mechanism that lets one corpus describe
// two engines. Without it a defect closed in the candidate engine and open in
// the default one cannot be recorded at all: removing the marker breaks the
// build for the default engine, and keeping it reports the candidate's progress
// as an unexpected pass.
func TestEngineScopedKnownFail(t *testing.T) {
	ann, err := parseAnnotation("want flow source=http-input sink=command-execution known-fail=legacy:11")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if got := ann.KnownFailFor("legacy"); got != 11 {
		t.Errorf("legacy known-fail = %d, want 11", got)
	}
	if got := ann.KnownFailFor("seam"); got != 0 {
		t.Errorf("seam known-fail = %d, want 0: the marker was scoped to legacy", got)
	}
	// An unnamed engine resolves to DefaultEngine. Assert both directions
	// against whichever engine that is, so the test keeps its meaning if the
	// default changes: a marker scoped to the default must be found, and a
	// marker scoped to any other engine must not be.
	other := "seam"
	if DefaultEngine == other {
		other = "legacy"
	}
	scopedToDefault, err := parseAnnotation("want flow source=http-input sink=command-execution known-fail=" + DefaultEngine + ":11")
	if err != nil {
		t.Fatal(err)
	}
	if got := scopedToDefault.KnownFailFor(""); got != 11 {
		t.Errorf("unnamed engine known-fail = %d, want 11 from the %s-scoped marker", got, DefaultEngine)
	}
	scopedToOther, err := parseAnnotation("want flow source=http-input sink=command-execution known-fail=" + other + ":11")
	if err != nil {
		t.Fatal(err)
	}
	if got := scopedToOther.KnownFailFor(""); got != 0 {
		t.Errorf("unnamed engine known-fail = %d, want 0: the marker is scoped to %s and the default is %s", got, other, DefaultEngine)
	}

	both, err := parseAnnotation("want flow source=http-input sink=command-execution known-fail=9")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	for _, engine := range append([]string{""}, KnownEngines...) {
		if got := both.KnownFailFor(engine); got != 9 {
			t.Errorf("unscoped marker not applied to engine %q: got %d", engine, got)
		}
	}

	if _, err := parseAnnotation("want flow source=http-input sink=data known-fail=nosuch:3"); err == nil {
		t.Error("a marker naming an unknown engine was accepted; a typo would silently never apply")
	}
	if _, err := parseAnnotation("want flow source=http-input sink=data known-fail=seam:1 known-fail=seam:2"); err == nil {
		t.Error("a marker naming the same engine twice was accepted")
	}
}
