package analyzer

import (
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func viewGraph() *model.CallGraph {
	return &model.CallGraph{
		Nodes: []model.CallGraphNode{
			{ID: "local.caller", Visibility: "local", Label: "local.caller"},
			{ID: "std.wrapper", Visibility: "stdlib", Label: "std.wrapper", PackagePath: "net/http"},
			{ID: "std.inner", Visibility: "stdlib", Label: "std.inner", PackagePath: "net/http"},
			{ID: "local.handler", Visibility: "local", Label: "local.handler"},
			{ID: "dep.entry", Visibility: "dependency", Label: "dep.entry", Position: model.Position{Filename: "/go/pkg/mod/example.com/lib/a.go"}},
			{ID: "dep.inner", Visibility: "dependency", Label: "dep.inner", Position: model.Position{Filename: "/go/pkg/mod/example.com/lib/b.go"}},
		},
		Edges: []model.CallGraphEdge{
			{ID: "e1", SourceID: "local.caller", TargetID: "std.wrapper", CallType: "static"},
			{ID: "e2", SourceID: "std.wrapper", TargetID: "std.inner", CallType: "static"},
			{ID: "e3", SourceID: "std.inner", TargetID: "local.handler", CallType: "func-value"},
			{ID: "e4", SourceID: "local.caller", TargetID: "dep.entry", CallType: "static"},
			{ID: "e5", SourceID: "dep.entry", TargetID: "dep.inner", CallType: "static"},
		},
	}
}

func edgeBetween(cg *model.CallGraph, source, target string) *model.CallGraphEdge {
	for i := range cg.Edges {
		if cg.Edges[i].SourceID == source && cg.Edges[i].TargetID == target {
			return &cg.Edges[i]
		}
	}
	return nil
}

func hasNode(cg *model.CallGraph, id string) bool {
	for _, node := range cg.Nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}

// TestExcludedScopeIsBridgedNotSevered is the regression test for the defect
// that motivated the whole view rework: hiding a node used to delete every edge
// touching it, so a handler invoked through the standard library looked
// unreachable from the code that registered it.
func TestExcludedScopeIsBridgedNotSevered(t *testing.T) {
	report := &model.Report{CallGraph: viewGraph()}
	applyReportView(report, Options{IncludeLocal: true, DependencyDetail: "full"})
	cg := report.CallGraph

	if hasNode(cg, "std.wrapper") || hasNode(cg, "std.inner") {
		t.Error("standard-library nodes must not appear when --include-stdlib is off")
	}
	bridge := edgeBetween(cg, "local.caller", "local.handler")
	if bridge == nil {
		t.Fatal("no edge from the caller to the handler it reaches through the standard library")
	}
	if !bridge.Collapsed || bridge.CollapsedHops != 3 {
		t.Errorf("bridge = %+v, want collapsed with 3 hops", bridge)
	}
	if bridge.CallType != "func-value" {
		t.Errorf("bridge call type = %q, want the dispatch kind of the final hop", bridge.CallType)
	}
	if len(bridge.Via) == 0 {
		t.Error("bridge must record the packages it traversed")
	}
	for _, edge := range cg.Edges {
		if !hasNode(cg, edge.SourceID) || !hasNode(cg, edge.TargetID) {
			t.Errorf("edge %s references a node absent from the view", edge.ID)
		}
	}
}

// TestBridgeDoesNotWalkSpeculativeDispatch keeps the bridge from multiplying
// over-approximated dispatch inside hidden code, which on a mid-sized service
// turned a few thousand edges into tens of thousands.
func TestBridgeDoesNotWalkSpeculativeDispatch(t *testing.T) {
	cg := viewGraph()
	cg.Edges[1].CallType = "interface" // std.wrapper -> std.inner is now a guess
	report := &model.Report{CallGraph: cg}
	applyReportView(report, Options{IncludeLocal: true, DependencyDetail: "full"})

	if edge := edgeBetween(report.CallGraph, "local.caller", "local.handler"); edge != nil {
		t.Errorf("bridged through an unresolved interior dispatch: %+v", edge)
	}
}

// TestDependencyDetailKeepsTheBoundary checks that dependency nodes stay
// visible. An edge from local code into a dependency is the evidence a
// reachability consumer wants; only the interior is pruned.
func TestDependencyDetailKeepsTheBoundary(t *testing.T) {
	for _, detail := range []string{"drop", "collapse"} {
		report := &model.Report{CallGraph: viewGraph()}
		applyReportView(report, Options{IncludeStdlib: true, IncludeLocal: true, DependencyDetail: detail})
		cg := report.CallGraph

		if edgeBetween(cg, "local.caller", "dep.entry") == nil {
			t.Errorf("%s: the boundary edge into the dependency was removed", detail)
		}
		if edgeBetween(cg, "dep.entry", "dep.inner") != nil {
			t.Errorf("%s: the dependency interior edge should not be shown", detail)
		}
		if hasNode(cg, "dep.inner") {
			t.Errorf("%s: an unreferenced dependency-interior node should be pruned", detail)
		}
	}
}

func TestDependencyDetailFullKeepsEverything(t *testing.T) {
	report := &model.Report{CallGraph: viewGraph()}
	applyReportView(report, Options{IncludeStdlib: true, IncludeLocal: true, DependencyDetail: "full"})
	if len(report.CallGraph.Edges) != 5 || len(report.CallGraph.Nodes) != 6 {
		t.Errorf("full detail changed the graph: %d nodes, %d edges", len(report.CallGraph.Nodes), len(report.CallGraph.Edges))
	}
}

// TestViewPrunesReachabilityReferences stops the view from leaving reachability
// entries and witness paths pointing at nodes it removed.
func TestViewPrunesReachabilityReferences(t *testing.T) {
	cg := viewGraph()
	cg.Roots = []model.CallGraphRoot{{ID: "local.caller", Function: "local.caller", RootReason: "exported"}, {ID: "std.wrapper", Function: "std.wrapper", RootReason: "exported"}}
	cg.Reachability = &model.ReachabilityInfo{
		Nodes: []model.ReachableNode{
			{NodeID: "local.handler", ReachableFromRoots: true, MinDepth: 3, RootIDs: []string{"local.caller", "std.wrapper"}},
			{NodeID: "std.inner", ReachableFromRoots: true, MinDepth: 2, RootIDs: []string{"local.caller"}},
		},
		Paths: []model.WitnessPath{
			{Symbol: "local.handler", NodeIDs: []string{"local.caller", "std.wrapper", "local.handler"}, Depth: 3},
			{Symbol: "local.handler", NodeIDs: []string{"local.caller", "local.handler"}, Depth: 1},
		},
	}
	report := &model.Report{CallGraph: cg}
	applyReportView(report, Options{IncludeLocal: true, DependencyDetail: "full"})

	for _, entry := range report.CallGraph.Reachability.Nodes {
		if !hasNode(report.CallGraph, entry.NodeID) {
			t.Errorf("reachability entry for removed node %s survived", entry.NodeID)
		}
		for _, root := range entry.RootIDs {
			if !hasNode(report.CallGraph, root) {
				t.Errorf("reachability entry references removed root %s", root)
			}
		}
	}
	for _, path := range report.CallGraph.Reachability.Paths {
		for _, id := range path.NodeIDs {
			if !hasNode(report.CallGraph, id) {
				t.Errorf("witness path references removed node %s", id)
			}
		}
	}
	for _, root := range report.CallGraph.Roots {
		if !hasNode(report.CallGraph, root.ID) {
			t.Errorf("root list references removed node %s", root.ID)
		}
	}
}

// TestViewIsDeterministic guards the sort order the golden digests depend on.
func TestViewIsDeterministic(t *testing.T) {
	var previous []string
	for i := 0; i < 3; i++ {
		report := &model.Report{CallGraph: viewGraph()}
		applyReportView(report, Options{IncludeLocal: true, DependencyDetail: "collapse"})
		var ids []string
		for _, edge := range report.CallGraph.Edges {
			ids = append(ids, edge.ID)
		}
		if previous != nil {
			if len(ids) != len(previous) {
				t.Fatalf("run %d produced %d edges, previous run produced %d", i, len(ids), len(previous))
			}
			for j := range ids {
				if ids[j] != previous[j] {
					t.Fatalf("run %d edge %d = %s, previous run had %s", i, j, ids[j], previous[j])
				}
			}
		}
		previous = ids
	}
}
