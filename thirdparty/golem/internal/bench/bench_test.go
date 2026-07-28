package bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func writeManifest(t *testing.T, manifest Manifest) string {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadManifestRejectsUnpinnedRemote(t *testing.T) {
	path := writeManifest(t, Manifest{Version: "1", Fixtures: []Fixture{
		{Name: "upstream", Type: "remote", Repo: "https://example.com/repo", Commit: "main"},
	}})
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "40-character SHA") {
		t.Fatalf("err = %v, want a complaint about the unpinned commit", err)
	}
}

func TestLoadManifestRejectsDuplicatesAndUnknownFields(t *testing.T) {
	path := writeManifest(t, Manifest{Version: "1", Fixtures: []Fixture{{Name: "a", Type: "corpus"}, {Name: "a", Type: "corpus"}}})
	if _, err := LoadManifest(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want a duplicate-fixture complaint", err)
	}

	path = filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"version":"1","fixtures":[{"name":"a","type":"corpus","typo":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil || !strings.Contains(err.Error(), "typo") {
		t.Fatalf("err = %v, want the unknown field named", err)
	}
}

func TestSelectTierAndNameFilter(t *testing.T) {
	manifest := &Manifest{Fixtures: []Fixture{
		{Name: "small", Type: "corpus", Tier: TierQuick},
		{Name: "untiered", Type: "corpus"},
		{Name: "big", Type: "remote", Tier: TierFull, Repo: "r", Commit: strings.Repeat("a", 40)},
	}}
	quick := manifest.Select(TierQuick, nil)
	if len(quick) != 2 {
		t.Errorf("quick tier selected %d fixtures, want 2 (untiered fixtures default to quick)", len(quick))
	}
	if len(manifest.Select(TierFull, nil)) != 3 {
		t.Error("full tier must include every fixture")
	}
	only := manifest.Select(TierFull, []string{"big"})
	if len(only) != 1 || only[0].Name != "big" {
		t.Errorf("name filter selected %+v", only)
	}
	if len(quick[0].Matrix) == 0 {
		t.Error("Select must fill in the default matrix")
	}
}

func TestSelectDefaultMatrixCoversShippingMode(t *testing.T) {
	// A matrix that only measures --dataflow all cannot observe the default
	// mode's behaviour, which is what cdxgen and dep-scan actually run.
	var labels []string
	for _, slot := range DefaultMatrix() {
		labels = append(labels, slot.DataFlow)
	}
	if !slices.Contains(labels, "security") || !slices.Contains(labels, "all") {
		t.Errorf("default matrix modes = %v, want both security and all", labels)
	}
}

func TestMaterializeCorpusFixture(t *testing.T) {
	root := t.TempDir()
	caseDir := filepath.Join(root, "example")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := Fixture{Name: "example", Type: "corpus"}.Materialize(root, "")
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if filepath.Base(dir) != "example" {
		t.Errorf("dir = %s, want the corpus case directory", dir)
	}
	if _, err := (Fixture{Name: "missing", Type: "corpus"}).Materialize(root, ""); err == nil {
		t.Error("a missing corpus fixture must be an error, not a silent skip")
	}
}

func TestCountDependencyCrossingSlices(t *testing.T) {
	main := &model.Module{Path: "example.com/app", Main: true}
	dependency := &model.Module{Path: "example.com/lib", Version: "v1.2.3"}
	report := &model.Report{DataFlow: &model.DataFlowEvidence{
		Nodes: []model.DataFlowNode{
			{ID: "src", Module: main, PURL: "pkg:golang/example.com/app"},
			{ID: "hop", Module: dependency, PURL: "pkg:golang/example.com/lib@v1.2.3"},
			{ID: "sink", Module: main, PURL: "pkg:golang/example.com/app"},
			{ID: "local", Module: main},
		},
		Slices: []model.DataFlowSlice{
			{ID: "crosses", SourceID: "src", SinkID: "sink", NodeIDs: []string{"src", "hop", "sink"}},
			{ID: "local", SourceID: "src", SinkID: "local", NodeIDs: []string{"src", "local"}},
		},
	}}
	// Every Go purl starts with pkg:golang/, so a prefix test on the purl can
	// never see a dependency; the count has to come from module identity.
	if got := countDependencyCrossingSlices(report); got != 1 {
		t.Errorf("countDependencyCrossingSlices = %d, want 1", got)
	}
}

func TestCountIntegrityViolations(t *testing.T) {
	report := &model.Report{
		DataFlow: &model.DataFlowEvidence{
			Nodes:  []model.DataFlowNode{{ID: "a"}},
			Edges:  []model.DataFlowEdge{{ID: "e", SourceID: "a", TargetID: "ghost"}},
			Slices: []model.DataFlowSlice{{ID: "s", SourceID: "a", SinkID: "ghost", NodeIDs: []string{"a", "ghost"}, EdgeIDs: []string{"e", "missing"}}},
		},
		CallGraph: &model.CallGraph{
			Nodes: []model.CallGraphNode{{ID: "n"}},
			Edges: []model.CallGraphEdge{{ID: "ce", SourceID: "n", TargetID: "absent"}},
		},
	}
	if got := countIntegrityViolations(report); got != 5 {
		t.Errorf("countIntegrityViolations = %d, want 5 (dangling edge target, slice sink, slice node, slice edge, call-graph target)", got)
	}
	if got := countIntegrityViolations(&model.Report{}); got != 0 {
		t.Errorf("an empty report has %d violations, want 0", got)
	}
}

func baselineWith(result Result) *Baseline {
	return &Baseline{Version: BaselineVersion, Results: []Result{result}}
}

func TestCompareFlagsRegressionsAndImprovements(t *testing.T) {
	base := Result{Name: "fx", Config: "security", Annotated: true, Recall: 0.8, Precision: 0.9, F1: 0.85, EdgeConnectivity: 1, DepCrossingSlices: 3, WallClockMs: 1000}

	worse := base
	worse.Recall = 0.5
	regressions := Compare(baselineWith(worse), baselineWith(base), DefaultCompareOptions())
	if len(Blocking(regressions)) != 1 || regressions[0].Metric != "recall" {
		t.Fatalf("regressions = %+v, want one blocking recall regression", regressions)
	}

	better := base
	better.Recall = 0.95
	regressions = Compare(baselineWith(better), baselineWith(base), DefaultCompareOptions())
	if len(Blocking(regressions)) != 0 {
		t.Errorf("an improvement must not block: %+v", regressions)
	}
	if len(regressions) != 1 || !strings.Contains(regressions[0].Message, "refresh the baseline") {
		t.Errorf("an improvement must still be reported so the baseline gets refreshed: %+v", regressions)
	}

	fewerDeps := base
	fewerDeps.DepCrossingSlices = 1
	if len(Blocking(Compare(baselineWith(fewerDeps), baselineWith(base), DefaultCompareOptions()))) != 1 {
		t.Error("losing dependency-crossing flows must block")
	}

	slower := base
	slower.WallClockMs = 2000
	if len(Blocking(Compare(baselineWith(slower), baselineWith(base), DefaultCompareOptions()))) != 1 {
		t.Error("a 2x slowdown must block")
	}
}

func TestCompareFlagsUnexpectedOutcomesAndCoverageGaps(t *testing.T) {
	base := Result{Name: "fx", Config: "security"}

	failing := base
	failing.UnexpectedFailures = 2
	if len(Blocking(Compare(baselineWith(failing), baselineWith(base), DefaultCompareOptions()))) != 1 {
		t.Error("unexpected annotation failures must block")
	}

	violating := base
	violating.IntegrityViolations = 1
	if len(Blocking(Compare(baselineWith(violating), baselineWith(base), DefaultCompareOptions()))) != 1 {
		t.Error("integrity violations must block")
	}

	xpass := base
	xpass.UnexpectedPasses = 1
	regressions := Compare(baselineWith(xpass), baselineWith(base), DefaultCompareOptions())
	if len(Blocking(regressions)) != 0 || len(regressions) != 1 {
		t.Errorf("an unexpected pass must be reported without blocking: %+v", regressions)
	}

	// A fixture absent from the baseline must be called out, otherwise a new
	// fixture is measured but never compared.
	novel := Result{Name: "new", Config: "security"}
	regressions = Compare(&Baseline{Results: []Result{novel}}, baselineWith(base), DefaultCompareOptions())
	var sawNew, sawMissing bool
	for _, regression := range regressions {
		if regression.Key == "new/security" && regression.Metric == "coverage" {
			sawNew = true
		}
		if regression.Key == "fx/security" && regression.Metric == "coverage" {
			sawMissing = true
		}
	}
	if !sawNew || !sawMissing {
		t.Errorf("coverage gaps not reported in %+v", regressions)
	}
}

func TestBaselineRoundTripIsDeterministic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	baseline := &Baseline{Results: []Result{
		{Name: "b", Config: "all"}, {Name: "a", Config: "security"}, {Name: "a", Config: "all"},
	}}
	if err := baseline.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, result := range loaded.Results {
		keys = append(keys, result.Key())
	}
	want := []string{"a/all", "a/security", "b/all"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("keys = %v, want %v", keys, want)
	}
	if loaded.Version != BaselineVersion {
		t.Errorf("version = %q, want %q", loaded.Version, BaselineVersion)
	}
}

func TestDigestDiffAndSize(t *testing.T) {
	report := &model.Report{
		SchemaVersion: "v1",
		Options:       model.AnalysisOptions{Directory: "/tmp/fixture"},
		Stats:         model.Stats{PackageCount: 2, FileCount: 5},
		CallGraph: &model.CallGraph{Algorithm: "rta",
			Nodes: []model.CallGraphNode{{ID: "pkg.main", Kind: "function"}, {ID: "pkg.helper", Kind: "function", Synthetic: true}},
			Edges: []model.CallGraphEdge{{ID: "e", SourceID: "pkg.main", TargetID: "pkg.helper", CallType: "static"}},
		},
		DataFlow: &model.DataFlowEvidence{Mode: "security",
			Nodes:  []model.DataFlowNode{{ID: "src", Position: model.Position{Filename: "/tmp/fixture/main.go", Line: 7}}, {ID: "sink", Position: model.Position{Filename: "/tmp/fixture/main.go", Line: 9}}},
			Edges:  []model.DataFlowEdge{{ID: "e1", SourceID: "src", TargetID: "sink"}},
			Slices: []model.DataFlowSlice{{ID: "s", SourceID: "src", SinkID: "sink", FlowKey: "k", SourceCategory: "http-input", SinkCategory: "command-execution", Severity: "critical", NodeIDs: []string{"src", "sink"}, EdgeIDs: []string{"e1"}}},
		},
	}
	digest := BuildDigest("fixture", strings.Repeat("a", 40), "security", "/tmp/fixture", report)

	if digest.DataFlow.EdgeConnectivity != 1 {
		t.Errorf("edgeConnectivity = %v, want 1", digest.DataFlow.EdgeConnectivity)
	}
	if !digest.DataFlow.SampleFlows[0].Connected {
		t.Error("sample flow should be marked connected")
	}
	if got := digest.DataFlow.SampleFlows[0].SinkAt; got != "main.go:9" {
		t.Errorf("sinkAt = %q, want a fixture-relative position", got)
	}
	if digest.CallGraph.SyntheticNodes != 1 {
		t.Errorf("syntheticNodes = %d, want 1", digest.CallGraph.SyntheticNodes)
	}
	if diff := digest.Diff(digest); len(diff) != 0 {
		t.Errorf("a digest must not differ from itself: %v", diff)
	}

	changed := BuildDigest("fixture", strings.Repeat("a", 40), "security", "/tmp/fixture", report)
	changed.DataFlow.SliceCount = 99
	diff := digest.Diff(changed)
	if len(diff) != 1 || !strings.Contains(diff[0], "sliceCount") {
		t.Errorf("diff = %v, want the changed sliceCount", diff)
	}

	// The digest exists so goldens stay small enough to review in a diff.
	encoded, err := json.MarshalIndent(digest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 8*1024 {
		t.Errorf("digest is %d bytes; goldens must stay small enough to read", len(encoded))
	}
}

func TestSummarize(t *testing.T) {
	summary := Summarize([]Result{
		{Name: "a", Annotated: true, Recall: 1, Precision: 0.5, EdgeConnectivity: 1, Annotations: 2, ExpectedFailures: 1, DepCrossingSlices: 1, WallClockMs: 100, PeakRSSMB: 50},
		{Name: "b", Annotated: true, Recall: 0, Precision: 1, EdgeConnectivity: 0.5, Annotations: 1, UnexpectedFailures: 1, WallClockMs: 200, PeakRSSMB: 90},
	})
	if summary.Fixtures != 2 || summary.Annotations != 3 || summary.UnexpectedFailures != 1 || summary.ExpectedFailures != 1 {
		t.Errorf("summary counts wrong: %+v", summary)
	}
	if summary.MeanRecall != 0.5 || summary.MeanPrecision != 0.75 || summary.AnnotatedFixtures != 2 {
		t.Errorf("means wrong: %+v", summary)
	}

	// An unannotated fixture has no ground truth, so it must not drag the means
	// toward zero: a repository nobody has labelled is not a precision failure.
	withUnannotated := Summarize([]Result{
		{Name: "a", Annotated: true, Recall: 1, Precision: 1, EdgeConnectivity: 1},
		{Name: "upstream", EdgeConnectivity: 0.8},
	})
	if withUnannotated.MeanRecall != 1 || withUnannotated.MeanPrecision != 1 {
		t.Errorf("unannotated fixture polluted the means: %+v", withUnannotated)
	}
	if withUnannotated.AnnotatedFixtures != 1 || withUnannotated.Fixtures != 2 {
		t.Errorf("fixture counts wrong: %+v", withUnannotated)
	}
	if withUnannotated.MinConnectivity != 0.8 {
		t.Errorf("connectivity is measurable without annotations: %+v", withUnannotated)
	}
	if summary.MinConnectivity != 0.5 {
		t.Errorf("MinConnectivity = %v, want the worst fixture's value", summary.MinConnectivity)
	}
	if summary.PeakRSSMB != 90 || summary.TotalWallClockMs != 300 {
		t.Errorf("resource aggregation wrong: %+v", summary)
	}
}
