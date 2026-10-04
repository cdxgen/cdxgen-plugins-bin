package analyzer

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func boolValue(v *bool) (bool, bool) {
	if v == nil {
		return false, false
	}
	return *v, true
}

// analyzeFlowRoot runs the fixture: one library main calls, one library main
// only blank-imports, both with the same parameter-to-sink flow. The blank
// import keeps the unused package's slices in the report under
// --include-all-flows; reachability has to say which flow the application can
// actually drive.
func analyzeFlowRoot(t *testing.T, options Options) *model.Report {
	t.Helper()
	options.Dir = filepath.Join("..", "..", "testdata", "flowroot")
	options.IncludeLocal = true
	options.DataFlowMode = "all"
	options.DataFlowCallGraphMode = "static"
	options.DataFlowMax = 100
	options.ToolVersion = "test"
	report, err := Analyze(options)
	if err != nil {
		t.Fatal(err)
	}
	if report.DataFlow == nil {
		t.Fatal("expected data-flow evidence")
	}
	return report
}

// expectedRooted is the verdict each flowroot stub library's slices must
// carry. Matching is on the exact package path: "unusedlib" contains
// "usedlib" as a substring, so prefix matching would merge the two buckets.
var expectedRooted = map[string]bool{
	"example.com/usedlib":   true,  // direct call
	"example.com/ifacelib":  true,  // interface dispatch only
	"example.com/fnvallib":  true,  // func value from a map only
	"example.com/drvlib":    true,  // blank import + database/sql registration
	"example.com/unusedlib": false, // blank import and nothing else
}

// assertSliceVerdicts checks every slice against expectedRooted and that every
// stub library contributed at least one slice, so a shape that silently stops
// producing slices cannot pass.
func assertSliceVerdicts(t *testing.T, report *model.Report) {
	t.Helper()
	seen := map[string]int{}
	for _, slice := range report.DataFlow.Slices {
		value, present := boolValue(slice.ReachableFromRoots)
		if !present {
			t.Fatalf("expected reachableFromRoots on every slice, got none on %#v", slice)
		}
		want, known := expectedRooted[slice.SourcePackagePath]
		if !known {
			t.Fatalf("unexpected slice source package %q in flowroot fixture", slice.SourcePackagePath)
		}
		if value != want {
			t.Fatalf("slice in %s: reachableFromRoots=%v, want %v", slice.SourcePackagePath, value, want)
		}
		seen[slice.SourcePackagePath]++
	}
	for pkg := range expectedRooted {
		if seen[pkg] == 0 {
			t.Fatalf("expected at least one slice from %s, got %v", pkg, seen)
		}
	}
	info := report.DataFlow.SliceReachability
	if info == nil || info.Status != "computed" || info.Algorithm != "rta" {
		t.Fatalf("expected computed rta sliceReachability, got %#v", info)
	}
	unrooted := seen["example.com/unusedlib"]
	if info.UnrootedSliceCount != unrooted || info.RootedSliceCount != len(report.DataFlow.Slices)-unrooted {
		t.Fatalf("sliceReachability counts disagree with the slices: %#v (unrooted=%d of %d)", info, unrooted, len(report.DataFlow.Slices))
	}
}

// TestAnalyzeDataFlowSliceReachabilityIndependentOfCallGraphMode pins the
// verdict to RTA whatever --callgraph is: static and VTA miss interface and
// func-value dispatch, CHA marks the blank-imported library reachable, and
// none builds no report graph at all.
func TestAnalyzeDataFlowSliceReachabilityIndependentOfCallGraphMode(t *testing.T) {
	for _, mode := range []string{"none", "static", "cha", "rta", "vta"} {
		t.Run(mode, func(t *testing.T) {
			assertSliceVerdicts(t, analyzeFlowRoot(t, Options{CallGraphMode: mode, IncludeAllFlows: true}))
		})
	}
}

func TestAnalyzeDataFlowSliceReachabilityDefaultView(t *testing.T) {
	// The default (collapse) view applies after annotation; local replacement
	// libraries are not module-cache paths, so their slices survive the view
	// and keep the verdict computed on the full graph.
	assertSliceVerdicts(t, analyzeFlowRoot(t, Options{CallGraphMode: "static"}))
}

// TestAnalyzeDataFlowSliceReachabilityLibraryWithheld covers a module with no
// main: its only roots are initializers, so the verdict is withheld (absent)
// rather than written as false for the whole exported API.
func TestAnalyzeDataFlowSliceReachabilityLibraryWithheld(t *testing.T) {
	report, err := Analyze(Options{
		Dir:                   filepath.Join("..", "..", "testdata", "flowrootlib"),
		IncludeLocal:          true,
		DataFlowMode:          "all",
		DataFlowCallGraphMode: "static",
		DataFlowMax:           100,
		CallGraphMode:         "static",
		ToolVersion:           "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.DataFlow == nil || len(report.DataFlow.Slices) == 0 {
		t.Fatal("expected the library's exported API to produce a slice")
	}
	for _, slice := range report.DataFlow.Slices {
		if slice.ReachableFromRoots != nil {
			t.Fatalf("library slice must carry no verdict, got %v on %#v", *slice.ReachableFromRoots, slice)
		}
	}
	info := report.DataFlow.SliceReachability
	if info == nil || info.Status != "skipped" || info.Reason != "no-entry-roots" {
		t.Fatalf("expected skipped/no-entry-roots, got %#v", info)
	}
}

// TestSliceReachabilityCountsSerializeZero guards the tri-state: zero rooted
// slices is an answer and must appear in the JSON, not vanish like "not
// computed" does.
func TestSliceReachabilityCountsSerializeZero(t *testing.T) {
	raw, err := json.Marshal(model.DataFlowSliceReachability{Status: "computed", Algorithm: "rta"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"rootedSliceCount":0`, `"unrootedSliceCount":0`, `"rootCount":0`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("expected %s in %s", key, raw)
		}
	}
}

func TestMergeSliceReachability(t *testing.T) {
	a := &model.DataFlowSliceReachability{Status: "computed", Algorithm: "rta", RootKinds: []string{"main"}, RootCount: 2}
	b := &model.DataFlowSliceReachability{Status: "skipped", Reason: "no-entry-roots", RootKinds: []string{"init"}, RootCount: 1}
	c := &model.DataFlowSliceReachability{Status: "computed", Algorithm: "cha", RootCount: 1}
	merged := mergeSliceReachability(nil, a)
	merged = mergeSliceReachability(merged, b)
	merged = mergeSliceReachability(merged, c)
	if merged.Status != "partial" || merged.Reason != "no-entry-roots" || merged.Algorithm != "cha,rta" || merged.RootCount != 4 {
		t.Fatalf("unexpected merge result %#v", merged)
	}
	if strings.Join(merged.RootKinds, ",") != "init,main" {
		t.Fatalf("expected unioned root kinds, got %v", merged.RootKinds)
	}
	if a.Status != "computed" {
		t.Fatal("merge must not mutate the first child's metadata")
	}
}

func TestAnnotateSliceReachability(t *testing.T) {
	df := &model.DataFlowEvidence{
		Nodes: []model.DataFlowNode{
			{ID: "src-reached", FunctionID: "pkg.reached"},
			{ID: "snk-reached", FunctionID: "pkg.reached"},
			{ID: "src-unreached", FunctionID: "pkg.unreached"},
			{ID: "snk-unreached", FunctionID: "pkg.unreached"},
			{ID: "src-nofn", FunctionID: ""},
		},
		Slices: []model.DataFlowSlice{
			{ID: "s1", SourceID: "src-reached", SinkID: "snk-reached"},
			{ID: "s2", SourceID: "src-unreached", SinkID: "snk-unreached", NodeIDs: []string{"src-unreached", "snk-unreached"}},
			{ID: "s3", SourceID: "src-nofn", SinkID: "snk-unreached"},
		},
	}
	df.SliceReachability = &model.DataFlowSliceReachability{Status: "computed"}
	annotateSliceReachability(df, map[string]bool{"pkg.reached": true})
	if value, present := boolValue(df.Slices[0].ReachableFromRoots); !present || !value {
		t.Fatalf("expected s1 rooted, got present=%v value=%v", present, value)
	}
	if value, present := boolValue(df.Slices[1].ReachableFromRoots); !present || value {
		t.Fatalf("expected s2 present and not rooted, got present=%v value=%v", present, value)
	}
	if value, present := boolValue(df.Slices[2].ReachableFromRoots); !present || value {
		t.Fatalf("expected s3 present and not rooted (no function attribution on the source), got present=%v value=%v", present, value)
	}
	if df.SliceReachability.RootedSliceCount != 1 || df.SliceReachability.UnrootedSliceCount != 2 {
		t.Fatalf("expected rooted=1 unrooted=2, got %#v", df.SliceReachability)
	}
}

func TestAnnotateSliceReachabilityIntermediateHop(t *testing.T) {
	// A slice can enter reachable code in the middle: the source function is
	// unreachable but a hop on the path sits in a reachable wrapper.
	df := &model.DataFlowEvidence{
		Nodes: []model.DataFlowNode{
			{ID: "n1", FunctionID: "pkg.dead"},
			{ID: "n2", FunctionID: "pkg.live"},
		},
		Slices: []model.DataFlowSlice{
			{ID: "s1", SourceID: "n1", SinkID: "n2", NodeIDs: []string{"n1", "n2"}},
		},
	}
	annotateSliceReachability(df, map[string]bool{"pkg.live": true})
	if value, _ := boolValue(df.Slices[0].ReachableFromRoots); !value {
		t.Fatalf("expected slice rooted through its intermediate hop, got %#v", df.Slices[0])
	}
}
