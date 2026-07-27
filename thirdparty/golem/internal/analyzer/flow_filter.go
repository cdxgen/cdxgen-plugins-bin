package analyzer

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// filterExternalOnlyModuleCacheFlows applies the configured dependency-detail
// policy to the call graph and data-flow sections of a report. It runs *after*
// reachability has been computed so nothing is lost before consumers can use it.
//
// Policies (--dependency-detail):
//
//	drop     — remove edges where both endpoints are in /pkg/mod/ (the old
//	           behaviour, now opt-in).
//	collapse — replace maximal chains of dependency-only edges with a single
//	           edge annotated collapsed:true, collapsedHops:n, via:[purls…].
//	full     — keep all edges; --include-all-flows is an alias.
func filterExternalOnlyModuleCacheFlows(report *model.Report, includeAllFlows bool, detail string) {
	applyReportView(report, Options{IncludeAllFlows: includeAllFlows, DependencyDetail: detail, IncludeStdlib: true, IncludeLocal: true})
}

// applyReportView reduces a report to the view the caller asked for, after all
// analysis is complete.
//
// Two policies apply in order. Scope classes the caller excluded
// (--include-stdlib, --include-local) are omitted but bridged, so a call routed
// through the standard library — a handler invoked by net/http, a comparison
// function invoked by sort.Slice — still yields an edge between the two
// endpoints the caller can see. Then --dependency-detail decides how much of the
// third-party interior to show.
func applyReportView(report *model.Report, options Options) {
	if report == nil {
		return
	}
	detail := options.DependencyDetail
	// Back-compat: --include-all-flows is an alias for full.
	if options.IncludeAllFlows {
		detail = "full"
	}
	if detail == "" {
		detail = "collapse"
	}
	if report.CallGraph != nil {
		if !options.IncludeStdlib || !options.IncludeLocal {
			applyCallGraphView(report.CallGraph, callGraphViewPolicy{
				hide: func(node model.CallGraphNode) bool {
					switch node.Visibility {
					case "stdlib":
						return !options.IncludeStdlib
					case "local":
						return !options.IncludeLocal
					default:
						return false
					}
				},
				bridge:       true,
				removeHidden: true,
			})
		}
		if detail != "full" {
			filterCallGraphByDetail(report.CallGraph, detail)
		}
	}
	if report.DataFlow != nil && detail != "full" {
		filterDataFlowModuleCacheFlows(report.DataFlow)
	}
}

// filterCallGraphByDetail applies the dependency-detail policy to a call graph.
//
// Dependency nodes stay visible: an edge from local code into a dependency is
// exactly the evidence a reachability consumer wants. Only the dependency
// *interior* is pruned, either dropped outright or replaced by a collapsed edge
// that records how many hops were folded away.
func filterCallGraphByDetail(cg *model.CallGraph, detail string) {
	applyCallGraphView(cg, callGraphViewPolicy{
		hide:         func(node model.CallGraphNode) bool { return callGraphNodeFromModuleCache(node) },
		bridge:       detail == "collapse",
		removeHidden: false,
	})
}

// callGraphViewPolicy describes which nodes a view omits and whether paths
// through them are preserved.
type callGraphViewPolicy struct {
	// hide reports whether a node is omitted from the view.
	hide func(model.CallGraphNode) bool
	// bridge preserves connectivity through omitted nodes by synthesizing one
	// edge per surviving caller/callee pair, annotated with the hop count and the
	// packages traversed. When false, omitted nodes and their edges are dropped.
	bridge bool
	// maxHops bounds how far a bridge walks; 0 uses defaultBridgeHops.
	maxHops int
	// maxBridgesPerNode bounds the fan-out synthesized from one node; 0 uses
	// defaultMaxBridgesPerNode.
	maxBridgesPerNode int
	// removeHidden omits hidden nodes from the view entirely. When false the
	// hidden nodes remain and only the edges between two of them are pruned, so
	// the boundary between visible and hidden code stays visible.
	removeHidden bool
}

const (
	defaultBridgeHops        = 3
	defaultMaxBridgesPerNode = 64
)

// applyCallGraphView removes the nodes a policy hides and, when the policy
// bridges, replaces every path that ran through them with a single annotated
// edge between the surviving endpoints.
//
// Hiding a node without bridging is what disconnected the graph before: an edge
// survived only if both of its endpoints did, so a call routed through a wrapper
// or through the standard library disappeared entirely and the callee looked
// unreachable. Reachability is computed on the full graph before this runs, so
// the view is a presentation concern and never changes what golem concluded.
func applyCallGraphView(cg *model.CallGraph, policy callGraphViewPolicy) {
	if cg == nil || policy.hide == nil {
		return
	}
	hidden := map[string]bool{}
	nodeByID := make(map[string]model.CallGraphNode, len(cg.Nodes))
	for _, node := range cg.Nodes {
		nodeByID[node.ID] = node
		if policy.hide(node) {
			hidden[node.ID] = true
		}
	}
	if len(hidden) == 0 {
		return
	}

	outgoing := map[string][]model.CallGraphEdge{}
	visibleEdges := make([]model.CallGraphEdge, 0, len(cg.Edges))
	existing := map[string]bool{}
	referenced := map[string]bool{}
	for _, edge := range cg.Edges {
		outgoing[edge.SourceID] = append(outgoing[edge.SourceID], edge)
		interior := hidden[edge.SourceID] && hidden[edge.TargetID]
		boundary := hidden[edge.SourceID] != hidden[edge.TargetID]
		keep := !interior
		if policy.removeHidden && boundary {
			keep = false
		}
		if keep {
			visibleEdges = append(visibleEdges, edge)
			existing[edge.SourceID+"\x00"+edge.TargetID] = true
			referenced[edge.SourceID] = true
			referenced[edge.TargetID] = true
		}
	}

	var bridged []model.CallGraphEdge
	if policy.bridge {
		maxHops := policy.maxHops
		if maxHops <= 0 {
			maxHops = defaultBridgeHops
		}
		maxBridges := policy.maxBridgesPerNode
		if maxBridges <= 0 {
			maxBridges = defaultMaxBridgesPerNode
		}
		truncated := 0
		for _, node := range cg.Nodes {
			if hidden[node.ID] {
				continue
			}
			exits, capped := bridgeExits(node.ID, outgoing, hidden, nodeByID, maxHops, maxBridges)
			if capped {
				truncated++
			}
			for _, exit := range exits {
				if existing[node.ID+"\x00"+exit.target] {
					continue
				}
				existing[node.ID+"\x00"+exit.target] = true
				target := nodeByID[exit.target]
				bridged = append(bridged, model.CallGraphEdge{
					ID:            stableEdgeID(node.ID, exit.target, model.Position{}, "collapsed"),
					SourceID:      node.ID,
					TargetID:      exit.target,
					SourceName:    node.Label,
					TargetName:    target.Label,
					SourcePURL:    node.PURL,
					SinkPURL:      target.PURL,
					PURLs:         orderedUniqueStrings(append([]string{node.PURL, target.PURL}, exit.via...)),
					CallType:      exit.callType,
					Static:        exit.callType == "static",
					Collapsed:     true,
					CollapsedHops: exit.hops,
					Via:           exit.via,
					Description:   "path through omitted nodes",
				})
			}
		}
		if truncated > 0 {
			cg.Diagnostics = append(cg.Diagnostics, model.Diagnostic{
				Kind:    "callgraph",
				Message: fmt.Sprintf("bridged edge fan-out capped at %d for %d node(s); some paths through omitted nodes are not represented", maxBridges, truncated),
			})
		}
	}

	for _, edge := range bridged {
		referenced[edge.SourceID] = true
		referenced[edge.TargetID] = true
	}
	keptNodes := make([]model.CallGraphNode, 0, len(cg.Nodes))
	for _, node := range cg.Nodes {
		if !hidden[node.ID] || (!policy.removeHidden && referenced[node.ID]) {
			keptNodes = append(keptNodes, node)
		}
	}
	cg.Nodes = keptNodes
	cg.Edges = append(visibleEdges, bridged...)
	pruneReachability(cg)
	cg.Stats.NodeCount = len(cg.Nodes)
	cg.Stats.EdgeCount = len(cg.Edges)
	sort.Slice(cg.Nodes, func(i, j int) bool { return cg.Nodes[i].ID < cg.Nodes[j].ID })
	sort.Slice(cg.Edges, func(i, j int) bool { return cg.Edges[i].ID < cg.Edges[j].ID })
}

type exitPoint struct {
	target   string
	hops     int
	via      []string
	callType string
}

// bridgeExits walks forward from a visible node through hidden nodes only and
// returns each visible node it can reach, with the shortest hop count and the
// packages traversed on the way. Results are deterministic and capped.
func bridgeExits(start string, outgoing map[string][]model.CallGraphEdge, hidden map[string]bool, nodeByID map[string]model.CallGraphNode, maxHops, maxExits int) ([]exitPoint, bool) {
	type state struct {
		node string
		hops int
		via  []string
	}
	best := map[string]exitPoint{}
	seen := map[string]bool{start: true}
	queue := []state{{node: start}}
	capped := false

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.hops >= maxHops {
			continue
		}
		edges := append([]model.CallGraphEdge{}, outgoing[current.node]...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
		for _, edge := range edges {
			if !hidden[edge.TargetID] {
				// Only a path that actually traversed a hidden node needs a bridge.
				if current.node == start {
					continue
				}
				// The last hop may be a dispatch — that is the callback shape
				// worth preserving, such as net/http invoking a handler value.
				if previous, ok := best[edge.TargetID]; ok && previous.hops <= current.hops+1 {
					continue
				}
				if len(best) >= maxExits {
					capped = true
					continue
				}
				best[edge.TargetID] = exitPoint{target: edge.TargetID, hops: current.hops + 1, via: current.via, callType: bridgedCallType(edge.CallType)}
				continue
			}
			if seen[edge.TargetID] {
				continue
			}
			// Only follow a resolved call between two hidden nodes. Interface and
			// function-value edges inside hidden code are over-approximations, and
			// walking them multiplies speculation: on a mid-sized service that
			// turns a few thousand real edges into tens of thousands of invented
			// ones, all of which a consumer would have to treat as evidence.
			if current.node != start && !isResolvedCall(edge) {
				continue
			}
			seen[edge.TargetID] = true
			via := current.via
			if pkg := nodeByID[edge.TargetID].PackagePath; pkg != "" {
				via = append(append([]string{}, current.via...), pkg)
			}
			queue = append(queue, state{node: edge.TargetID, hops: current.hops + 1, via: via})
		}
	}
	out := make([]exitPoint, 0, len(best))
	for _, exit := range best {
		exit.via = orderedUniqueStrings(exit.via)
		out = append(out, exit)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].target < out[j].target })
	return out, capped
}

// isResolvedCall reports whether an edge represents a statically resolved call
// rather than an over-approximated dispatch.
func isResolvedCall(edge model.CallGraphEdge) bool {
	switch edge.CallType {
	case "interface", "func-value", "reflect":
		return false
	default:
		return true
	}
}

// bridgedCallType keeps a dispatch kind that survives collapsing; anything
// resolved statically at the far end is still reached indirectly.
func bridgedCallType(callType string) string {
	switch callType {
	case "interface", "func-value", "reflect":
		return callType
	default:
		return "static"
	}
}

// pruneReachability drops reachability entries and witness paths that reference
// nodes the view removed, so no consumer is handed an identifier it cannot
// resolve.
func pruneReachability(cg *model.CallGraph) {
	if cg == nil || cg.Reachability == nil {
		return
	}
	present := make(map[string]bool, len(cg.Nodes))
	for _, node := range cg.Nodes {
		present[node.ID] = true
	}
	edges := make(map[string]bool, len(cg.Edges))
	for _, edge := range cg.Edges {
		edges[edge.ID] = true
	}
	nodes := make([]model.ReachableNode, 0, len(cg.Reachability.Nodes))
	for _, entry := range cg.Reachability.Nodes {
		if !present[entry.NodeID] {
			continue
		}
		roots := make([]string, 0, len(entry.RootIDs))
		for _, id := range entry.RootIDs {
			if present[id] {
				roots = append(roots, id)
			}
		}
		entry.RootIDs = roots
		nodes = append(nodes, entry)
	}
	cg.Reachability.Nodes = nodes

	paths := make([]model.WitnessPath, 0, len(cg.Reachability.Paths))
	for _, path := range cg.Reachability.Paths {
		intact := true
		for _, id := range path.NodeIDs {
			if !present[id] {
				intact = false
				break
			}
		}
		for _, id := range path.EdgeIDs {
			if !edges[id] {
				intact = false
				break
			}
		}
		if intact {
			paths = append(paths, path)
		}
	}
	cg.Reachability.Paths = paths

	roots := make([]model.CallGraphRoot, 0, len(cg.Roots))
	for _, root := range cg.Roots {
		if present[root.ID] {
			roots = append(roots, root)
		}
	}
	cg.Roots = roots
}

// Legacy entry points kept for compatibility with existing callers.
func filterCallGraphModuleCacheFlows(cg *model.CallGraph) {
	filterCallGraphByDetail(cg, "drop")
}

func filterDataFlowModuleCacheFlows(df *model.DataFlowEvidence) {
	if df == nil {
		return
	}
	cacheNode := map[string]bool{}
	for _, node := range df.Nodes {
		cacheNode[node.ID] = dataFlowNodeFromModuleCache(node)
	}
	keptSlices := make([]model.DataFlowSlice, 0, len(df.Slices))
	removed := 0
	for _, slice := range df.Slices {
		if dataFlowSliceAllInModuleCache(slice, cacheNode) {
			removed++
			continue
		}
		keptSlices = append(keptSlices, slice)
	}
	if removed == 0 {
		return
	}
	df.Slices = keptSlices
	recomputeDataFlowStats(df)
	sortDataFlowEvidence(df)
}

func dataFlowSliceAllInModuleCache(slice model.DataFlowSlice, cacheNodes map[string]bool) bool {
	nodeIDs := append([]string{}, slice.NodeIDs...)
	nodeIDs = append(nodeIDs, slice.SourceID, slice.SinkID)
	found := false
	for _, nodeID := range nodeIDs {
		if strings.TrimSpace(nodeID) == "" {
			continue
		}
		found = true
		if !cacheNodes[nodeID] {
			return false
		}
	}
	return found
}

func recomputeDataFlowStats(df *model.DataFlowEvidence) {
	if df == nil {
		return
	}
	df.Stats.NodeCount = len(df.Nodes)
	df.Stats.EdgeCount = len(df.Edges)
	df.Stats.SliceCount = len(df.Slices)
	df.Stats.SourceCount = 0
	df.Stats.SinkCount = 0
	df.Stats.UniqueFlowCount = 0
	df.Stats.DuplicateSliceCount = 0
	df.Stats.DuplicateGroupCount = 0
	df.Stats.MaxPathLength = 0
	df.Stats.AveragePathLength = 0
	df.Stats.SanitizedSliceCount = 0
	for _, node := range df.Nodes {
		if node.Source {
			df.Stats.SourceCount++
		}
		if node.Sink {
			df.Stats.SinkCount++
		}
	}
	if len(df.Slices) == 0 {
		return
	}
	countByFlow := map[string]int{}
	totalPath := 0
	for _, slice := range df.Slices {
		if slice.FlowKey != "" {
			countByFlow[slice.FlowKey]++
		}
		if slice.PathLength > df.Stats.MaxPathLength {
			df.Stats.MaxPathLength = slice.PathLength
		}
		totalPath += slice.PathLength
		if len(slice.SanitizerNodeIDs) > 0 {
			df.Stats.SanitizedSliceCount++
		}
	}
	df.Stats.UniqueFlowCount = len(countByFlow)
	for _, count := range countByFlow {
		if count > 1 {
			df.Stats.DuplicateSliceCount += count - 1
			df.Stats.DuplicateGroupCount++
		}
	}
	df.Stats.AveragePathLength = float64(totalPath) / float64(len(df.Slices))
}

func callGraphNodeFromModuleCache(node model.CallGraphNode) bool {
	if isGoModuleCachePath(node.Position.Filename) {
		return true
	}
	return node.Module != nil && isGoModuleCachePath(node.Module.Dir)
}

func dataFlowNodeFromModuleCache(node model.DataFlowNode) bool {
	if isGoModuleCachePath(node.Position.Filename) {
		return true
	}
	return node.Module != nil && isGoModuleCachePath(node.Module.Dir)
}

func isGoModuleCachePath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(strings.TrimSpace(path)))
	if normalized == "" {
		return false
	}
	return strings.Contains(normalized, "/go/pkg/mod/") || strings.Contains(normalized, "/pkg/mod/")
}
