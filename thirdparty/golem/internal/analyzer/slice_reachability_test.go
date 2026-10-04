package analyzer

import (
	"path/filepath"
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

// sliceRootedStates asserts every slice carries a verdict, the called
// library's slices are rooted, and the never-called library's are not, and
// returns how many of each were seen. The match is on the exact package path:
// "unusedlib" contains "usedlib" as a substring, so prefix matching would
// classify both libraries into one bucket.
func sliceRootedStates(t *testing.T, report *model.Report) (usedSlices, unusedSlices int) {
	t.Helper()
	for _, slice := range report.DataFlow.Slices {
		value, present := boolValue(slice.ReachableFromRoots)
		if !present {
			t.Fatalf("expected reachableFromRoots on every slice, got none on %#v", slice)
		}
		switch slice.SourcePackagePath {
		case "example.com/usedlib":
			if !value {
				t.Fatalf("slice in the CALLED library must be rooted, got %#v", slice)
			}
			usedSlices++
		case "example.com/unusedlib":
			if value {
				t.Fatalf("slice in the blank-imported, never-called library must not be rooted, got %#v", slice)
			}
			unusedSlices++
		default:
			t.Fatalf("unexpected slice source package %q in flowroot fixture", slice.SourcePackagePath)
		}
	}
	return usedSlices, unusedSlices
}

func TestAnalyzeDataFlowSliceReachabilityFromRoots(t *testing.T) {
	report := analyzeFlowRoot(t, Options{CallGraphMode: "static", IncludeAllFlows: true})
	if len(report.DataFlow.Slices) < 2 {
		t.Fatalf("expected one slice per stub library, got %#v", report.DataFlow.Slices)
	}
	usedSlices, unusedSlices := sliceRootedStates(t, report)
	if usedSlices == 0 {
		t.Fatal("expected the called library's slice to be rooted")
	}
	if unusedSlices == 0 {
		t.Fatal("expected the unused library's slice to be kept by --include-all-flows")
	}
	if report.DataFlow.Stats.RootedSliceCount != usedSlices {
		t.Fatalf("expected rootedSliceCount=%d, got %d", usedSlices, report.DataFlow.Stats.RootedSliceCount)
	}
	// The slice flags must agree with the call-graph section they join
	// against: the only unusedlib node the roots reach is its init (the blank
	// import runs it), and no slice traverses init.
	for _, node := range report.CallGraph.Reachability.Nodes {
		if node.ReachableFromRoots && node.NodeID == "example.com/unusedlib.Run" {
			t.Fatalf("unusedlib.Run must not be reachable from the roots")
		}
	}
}

func TestAnalyzeDataFlowSliceReachabilityWithoutCallGraph(t *testing.T) {
	// --callgraph none must still annotate: the fallback computes root
	// reachability on the static graph the taint engines already build.
	report := analyzeFlowRoot(t, Options{CallGraphMode: "none", IncludeAllFlows: true})
	if len(report.DataFlow.Slices) < 2 {
		t.Fatalf("expected one slice per stub library, got %#v", report.DataFlow.Slices)
	}
	usedSlices, unusedSlices := sliceRootedStates(t, report)
	if usedSlices == 0 || unusedSlices == 0 {
		t.Fatalf("expected rooted and unrooted slices without a call graph, got used=%d unused=%d", usedSlices, unusedSlices)
	}
}

func TestAnalyzeDataFlowSliceReachabilityDefaultView(t *testing.T) {
	// The default (collapse) view applies after annotation; local replacement
	// libraries are not module-cache paths, so their slices survive the view
	// and keep the verdict computed on the full graph.
	report := analyzeFlowRoot(t, Options{CallGraphMode: "static"})
	if len(report.DataFlow.Slices) < 2 {
		t.Fatalf("expected one slice per stub library under the default view, got %#v", report.DataFlow.Slices)
	}
	usedSlices, unusedSlices := sliceRootedStates(t, report)
	if usedSlices == 0 || unusedSlices == 0 {
		t.Fatalf("expected annotated slices after the default view, got used=%d unused=%d", usedSlices, unusedSlices)
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
	if df.Stats.RootedSliceCount != 1 {
		t.Fatalf("expected rootedSliceCount=1, got %d", df.Stats.RootedSliceCount)
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
