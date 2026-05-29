package analyzer

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func filterExternalOnlyModuleCacheFlows(report *model.Report, includeAllFlows bool) {
	if report == nil || includeAllFlows {
		return
	}
	if report.CallGraph != nil {
		filterCallGraphModuleCacheFlows(report.CallGraph)
	}
	if report.DataFlow != nil {
		filterDataFlowModuleCacheFlows(report.DataFlow)
	}
}

func filterCallGraphModuleCacheFlows(cg *model.CallGraph) {
	if cg == nil {
		return
	}
	cacheNode := map[string]bool{}
	for _, node := range cg.Nodes {
		cacheNode[node.ID] = callGraphNodeFromModuleCache(node)
	}
	keptEdges := make([]model.CallGraphEdge, 0, len(cg.Edges))
	referenced := map[string]bool{}
	for _, edge := range cg.Edges {
		if cacheNode[edge.SourceID] && cacheNode[edge.TargetID] {
			continue
		}
		keptEdges = append(keptEdges, edge)
		referenced[edge.SourceID] = true
		referenced[edge.TargetID] = true
	}
	keptNodes := make([]model.CallGraphNode, 0, len(cg.Nodes))
	for _, node := range cg.Nodes {
		if cacheNode[node.ID] && !referenced[node.ID] {
			continue
		}
		keptNodes = append(keptNodes, node)
	}
	cg.Nodes = keptNodes
	cg.Edges = keptEdges
	cg.Stats.NodeCount = len(cg.Nodes)
	cg.Stats.EdgeCount = len(cg.Edges)
	sort.Slice(cg.Nodes, func(i, j int) bool { return cg.Nodes[i].ID < cg.Nodes[j].ID })
	sort.Slice(cg.Edges, func(i, j int) bool { return cg.Edges[i].ID < cg.Edges[j].ID })
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
