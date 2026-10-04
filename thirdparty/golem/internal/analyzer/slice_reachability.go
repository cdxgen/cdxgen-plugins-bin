package analyzer

import (
	"golang.org/x/tools/go/callgraph"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// annotateDataFlowReachability states, on every data-flow slice, whether any
// function the slice traverses is reachable from the resolved roots.
//
// --include-all-flows deliberately keeps slices that live entirely inside a
// dependency the application never calls — dropping them would lose the
// dependency-internal flows that flag exists to preserve — so the report has
// to carry the distinction instead of the filter making it. The join key is
// the SSA function string: data-flow nodes record it as functionId and
// call-graph nodes use it as their id, so no re-attribution is needed.
//
// The verdict comes from the report's own callGraph.reachability when one was
// built, so the two sections always agree; a --callgraph none run computes it
// here from the static graph the taint engines already build. Either way the
// annotation runs before applyReportView, on the unfiltered graph, so a slice
// the view later collapses or prunes still carries the verdict the full graph
// supports.
func (a *Analyzer) annotateDataFlowReachability(report *model.Report, ctx *ssaContext) {
	if report == nil || report.DataFlow == nil || len(report.DataFlow.Slices) == 0 {
		return
	}
	reachable, ok := a.functionReachability(report, ctx)
	if !ok {
		return
	}
	annotateSliceReachability(report.DataFlow, reachable)
}

// functionReachability resolves the set of function ids reachable from the
// roots. The report's reachability section wins whenever it holds nodes — it
// is the same verdict a consumer can read per call-graph node — and the
// static-graph worklist covers runs that asked for no call graph at all.
func (a *Analyzer) functionReachability(report *model.Report, ctx *ssaContext) (map[string]bool, bool) {
	if report != nil && report.CallGraph != nil && report.CallGraph.Reachability != nil && len(report.CallGraph.Reachability.Nodes) > 0 {
		reachable := make(map[string]bool, len(report.CallGraph.Reachability.Nodes))
		for _, node := range report.CallGraph.Reachability.Nodes {
			if node.ReachableFromRoots {
				reachable[node.NodeID] = true
			}
		}
		return reachable, true
	}
	return a.staticReachability(ctx)
}

// staticReachability walks the static call graph from the resolved roots with
// an explicit worklist, mirroring computeReachability's no-recursion rule:
// deep graphs must not trade a stack overflow for a reachability answer.
func (a *Analyzer) staticReachability(ctx *ssaContext) (map[string]bool, bool) {
	if ctx == nil || ctx.program == nil {
		return nil, false
	}
	graph, _, _ := a.buildRawCallGraph(ctx, "static")
	if graph == nil {
		return nil, false
	}
	adj := adjacencyByFunctionID(graph)
	reachable := map[string]bool{}
	queue := make([]string, 0, len(adj))
	for _, root := range a.resolveRoots(ctx) {
		if root == nil {
			continue
		}
		id := root.String()
		if !reachable[id] {
			reachable[id] = true
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range adj[current] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}
	return reachable, true
}

func adjacencyByFunctionID(graph *callgraph.Graph) map[string][]string {
	adj := map[string][]string{}
	for fn, node := range graph.Nodes {
		if fn == nil || node == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			adj[fn.String()] = append(adj[fn.String()], edge.Callee.Func.String())
		}
	}
	return adj
}

// annotateSliceReachability sets reachableFromRoots on each slice: rooted when
// any data-flow node on its path — source, sink, or an intermediate hop —
// sits in a function the roots reach. Slices are never dropped here; the field
// is the entire point.
func annotateSliceReachability(df *model.DataFlowEvidence, reachable map[string]bool) {
	nodes := make(map[string]model.DataFlowNode, len(df.Nodes))
	for _, node := range df.Nodes {
		nodes[node.ID] = node
	}
	rooted := 0
	for i := range df.Slices {
		s := &df.Slices[i]
		value := sliceTouchesReachableFunction(s, nodes, reachable)
		s.ReachableFromRoots = &value
		if value {
			rooted++
		}
	}
	df.Stats.RootedSliceCount = rooted
}

func sliceTouchesReachableFunction(s *model.DataFlowSlice, nodes map[string]model.DataFlowNode, reachable map[string]bool) bool {
	for _, nodeID := range s.NodeIDs {
		if nodeFunctionReachable(nodes, reachable, nodeID) {
			return true
		}
	}
	return nodeFunctionReachable(nodes, reachable, s.SourceID) || nodeFunctionReachable(nodes, reachable, s.SinkID)
}

func nodeFunctionReachable(nodes map[string]model.DataFlowNode, reachable map[string]bool, nodeID string) bool {
	if nodeID == "" {
		return false
	}
	node, ok := nodes[nodeID]
	if !ok || node.FunctionID == "" {
		return false
	}
	return reachable[node.FunctionID]
}
