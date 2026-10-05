package analyzer

import (
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// sliceReachabilityMode is the call graph every slice verdict is computed on,
// independent of --callgraph. The verdict is consumed as "may this flow be
// dropped", so the graph has to follow dynamic dispatch: static misses every
// interface call, func value and struct-field callback, and VTA seeds itself
// from the static graph's reachable set and inherits the same holes. RTA
// starts from the roots and adds a method once a concrete type flowing into
// an interface makes it callable, which is what registration patterns
// (database/sql drivers, codecs, http.Handler values) need. CHA would also be
// sound but marks every method of every type implementing a used interface
// reachable, which is exactly the blank-import false positive the field
// exists to remove; it is used only when RTA panics.
const sliceReachabilityMode = "rta"

// annotateDataFlowReachability states, on every data-flow slice, whether any
// function the slice traverses is reachable from the resolved roots, and
// records how that verdict was produced in dataFlow.sliceReachability.
//
// --include-all-flows deliberately keeps slices that live entirely inside a
// dependency the application never calls — dropping them would lose the
// dependency-internal flows that flag exists to preserve — so the report has
// to carry the distinction instead of the filter making it. The join key is
// the SSA function string: data-flow nodes record it as functionId, and it is
// what fn.String() yields for every call-graph node.
//
// The annotation runs before applyReportView, on the unfiltered program, so a
// slice the view later collapses or prunes still carries the full verdict.
func (a *Analyzer) annotateDataFlowReachability(report *model.Report, ctx *ssaContext) {
	if report == nil || report.DataFlow == nil {
		return
	}
	df := report.DataFlow
	info := &model.DataFlowSliceReachability{Status: "skipped"}
	df.SliceReachability = info
	if ctx == nil || ctx.program == nil {
		info.Reason = "callgraph-unavailable"
		return
	}
	roots := a.resolveRoots(ctx)
	info.RootCount = len(roots)
	info.RootKinds = a.rootKinds(roots)
	if !a.hasEntryRoots(roots) {
		// A library has no main; its only roots are package initializers,
		// so every exported API would read as unreachable. That would be a
		// statement about the root heuristic, not about the code, so the
		// verdict is withheld rather than written as false.
		info.Reason = "no-entry-roots"
		return
	}
	reachable, packages, algorithm, ok := a.rootReachability(ctx, roots)
	if !ok {
		info.Reason = "callgraph-unavailable"
		return
	}
	info.Status = "computed"
	info.Algorithm = algorithm
	info.ReachablePackages = packages
	annotateSliceReachability(df, reachable)
}

// hasEntryRoots reports whether the roots include a real entry point: a main
// function, or any non-initializer root the user selected with --roots.
// Synthetic registrations found from a library's init do not count — they
// would make the library's own exported API look unreachable.
func (a *Analyzer) hasEntryRoots(roots []*ssa.Function) bool {
	for _, root := range roots {
		if root == nil {
			continue
		}
		reason := a.rootReasonFor(root)
		if reason == "main" {
			return true
		}
		if len(a.options.Roots) > 0 && reason != "init" {
			return true
		}
	}
	return false
}

func (a *Analyzer) rootKinds(roots []*ssa.Function) []string {
	seen := map[string]bool{}
	var kinds []string
	for _, root := range roots {
		if root == nil {
			continue
		}
		kind := a.rootReasonFor(root)
		if !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}

// rootReachability builds (or reuses) the RTA graph and walks it from the
// roots with an explicit worklist, mirroring computeReachability's
// no-recursion rule: deep graphs must not trade a stack overflow for a
// reachability answer. The walk matters even on RTA, whose graph holds only
// reachable functions, because a CHA fallback graph holds every function.
func (a *Analyzer) rootReachability(ctx *ssaContext, roots []*ssa.Function) (map[string]bool, []string, string, bool) {
	graph, algorithm, _ := a.buildRawCallGraph(ctx, sliceReachabilityMode)
	if graph == nil {
		return nil, nil, algorithm, false
	}
	adj := adjacencyByFunctionID(graph)
	reachable := map[string]bool{}
	queue := make([]string, 0, len(roots))
	for _, root := range roots {
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
	return reachable, a.reachablePackages(graph, reachable), algorithm, true
}

// reachablePackages collects the non-standard packages with a reached
// function that is not a package initializer. Closures defined inside an init
// count: they are code the init handed to someone else to call.
func (a *Analyzer) reachablePackages(graph *callgraph.Graph, reachable map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	for fn := range graph.Nodes {
		if fn == nil || !reachable[fn.String()] || isPackageInitializer(fn) {
			continue
		}
		pkg := fn.Pkg
		if pkg == nil && fn.Origin() != nil {
			pkg = fn.Origin().Pkg
		}
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		path := pkg.Pkg.Path()
		if seen[path] || a.isStandardPackage(path, nil) {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// isPackageInitializer matches a package's init and the numbered init#N
// functions SSA creates for each init declared in its files.
func isPackageInitializer(fn *ssa.Function) bool {
	if fn.Parent() != nil || fn.Signature.Recv() != nil {
		return false
	}
	name := fn.Name()
	return name == "init" || strings.HasPrefix(name, "init#")
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
	for i := range df.Slices {
		s := &df.Slices[i]
		value := sliceTouchesReachableFunction(s, nodes, reachable)
		s.ReachableFromRoots = &value
	}
	countSliceReachability(df)
}

// countSliceReachability refreshes the rooted/unrooted counts from the slices
// currently in the report; the view and the multi-module merge both change
// the slice list after annotation.
func countSliceReachability(df *model.DataFlowEvidence) {
	if df == nil || df.SliceReachability == nil {
		return
	}
	rooted, unrooted := 0, 0
	for _, s := range df.Slices {
		if s.ReachableFromRoots == nil {
			continue
		}
		if *s.ReachableFromRoots {
			rooted++
		} else {
			unrooted++
		}
	}
	df.SliceReachability.RootedSliceCount = rooted
	df.SliceReachability.UnrootedSliceCount = unrooted
}

// mergeSliceReachability folds a child module's sliceReachability into the
// merged report's. Slices keep their own verdicts; this only keeps the
// metadata honest about how they were produced.
func mergeSliceReachability(dst, src *model.DataFlowSliceReachability) *model.DataFlowSliceReachability {
	if src == nil {
		return dst
	}
	if dst == nil {
		copied := *src
		copied.RootKinds = append([]string(nil), src.RootKinds...)
		copied.ReachablePackages = append([]string(nil), src.ReachablePackages...)
		return &copied
	}
	if dst.Status != src.Status {
		dst.Status = "partial"
	}
	if dst.Reason == "" {
		dst.Reason = src.Reason
	}
	dst.Algorithm = joinUniqueSorted(dst.Algorithm, src.Algorithm)
	dst.RootKinds = unionSorted(dst.RootKinds, src.RootKinds)
	dst.ReachablePackages = unionSorted(dst.ReachablePackages, src.ReachablePackages)
	dst.RootCount += src.RootCount
	return dst
}

func joinUniqueSorted(a, b string) string {
	return strings.Join(unionSorted(strings.Split(a, ","), strings.Split(b, ",")), ",")
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{a, b} {
		for _, v := range list {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
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
