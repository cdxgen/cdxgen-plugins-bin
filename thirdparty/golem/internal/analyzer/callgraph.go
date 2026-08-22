package analyzer

import (
	"fmt"
	"go/build"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func (a *Analyzer) buildCallGraph(ctx *ssaContext) *model.CallGraph {
	cg := &model.CallGraph{Mode: a.options.CallGraphMode, Algorithm: a.options.CallGraphMode}
	if ctx == nil || ctx.program == nil {
		cg.Diagnostics = append(cg.Diagnostics, model.Diagnostic{Kind: "callgraph", Message: "SSA context was not available"})
		return cg
	}
	graph, algorithm, diagnostics := a.buildRawCallGraph(ctx, a.options.CallGraphMode)
	cg.Algorithm = algorithm
	cg.Diagnostics = append(cg.Diagnostics, diagnostics...)
	// Record resolved roots.
	roots := a.resolveRoots(ctx)
	for _, root := range roots {
		cg.Roots = append(cg.Roots, model.CallGraphRoot{
			ID:         root.String(),
			Function:   root.String(),
			RootReason: a.rootReasonFor(root),
		})
	}
	sort.Slice(cg.Roots, func(i, j int) bool { return cg.Roots[i].ID < cg.Roots[j].ID })
	if graph == nil {
		return cg
	}
	cg = a.convertCallGraph(cg, graph)
	a.appendLinknameEdges(cg)

	// Compute reachability from resolved roots using an explicit worklist (avoid
	// stack overflow on large graphs).
	cg.Reachability = a.computeReachability(cg)

	// Compute witness paths if --reachable-symbols was requested.
	if a.options.ReachableSymbols != "" {
		targets, err := readSymbolsFile(a.options.ReachableSymbols)
		if err != nil {
			cg.Diagnostics = append(cg.Diagnostics, model.Diagnostic{Kind: "reachability", Message: fmt.Sprintf("reading symbols file: %v", err)})
		} else if len(targets) > 0 {
			cg.Reachability.Paths = a.computeWitnessPaths(cg, targets, a.options.MaxPathsPerSymbol)
		}
	}

	return cg
}

func (a *Analyzer) buildRawCallGraph(ctx *ssaContext, mode string) (*callgraph.Graph, string, []model.Diagnostic) {
	if ctx == nil || ctx.program == nil {
		return nil, mode, []model.Diagnostic{{Kind: "callgraph", Message: "SSA context was not available"}}
	}
	var graph *callgraph.Graph
	algorithm := mode
	var diagnostics []model.Diagnostic
	switch mode {
	case "", "none":
		return nil, mode, nil
	case "static":
		graph, diagnostics = guardAlgorithm("static", func() *callgraph.Graph { return static.CallGraph(ctx.program) })
	case "cha":
		graph, diagnostics = guardAlgorithm("cha", func() *callgraph.Graph { return cha.CallGraph(ctx.program) })
	case "rta":
		graph, diagnostics = guardAlgorithm("rta", func() *callgraph.Graph {
			// A nil root segfaults inside rta.Analyze; see callableFunctions.
			result := rta.Analyze(callableFunctions(a.resolveRoots(ctx)), true)
			if result == nil {
				return nil
			}
			return result.CallGraph
		})
		if graph == nil && len(diagnostics) == 0 {
			diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph", Message: "RTA requires at least one reachable root function"})
		}
	case "vta":
		graph, diagnostics = guardAlgorithm("vta", func() *callgraph.Graph {
			initial := static.CallGraph(ctx.program)
			return vta.CallGraph(reachableFunctions(initial), initial)
		})
	case "auto":
		graph, algorithm, diagnostics = a.buildAutoCallGraph(ctx)
	default:
		diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph", Message: fmt.Sprintf("unsupported callgraph mode %q", mode)})
	}
	// A panicking algorithm leaves no graph. CHA is the conservative fallback:
	// it needs no roots and no type-flow reasoning, so the shapes that break RTA
	// and VTA do not reach it. A report with a coarser graph and a diagnostic
	// saying so is worth more than no report.
	if graph == nil && algorithm != "cha" && panicked(diagnostics) {
		fallback, fallbackDiags := guardAlgorithm("cha", func() *callgraph.Graph { return cha.CallGraph(ctx.program) })
		diagnostics = append(diagnostics, fallbackDiags...)
		if fallback != nil {
			graph, algorithm = fallback, "cha"
			diagnostics = append(diagnostics, model.Diagnostic{
				Kind:    "callgraph",
				Message: fmt.Sprintf("%s did not complete; fell back to cha, so the graph is coarser than requested", mode),
			})
		}
	}
	return graph, algorithm, diagnostics
}

// guardAlgorithm runs one call-graph algorithm and converts a panic inside it
// into a diagnostic.
//
// The algorithms live in x/tools and are not defensive about the programs golem
// hands them: `rta.(*rta).visitFunc` reads `f.Blocks` with no nil check and
// segfaults on a nil function reaching its worklist, which happens on at least
// one large repository in the benchmark. Letting that abort the process throws
// away a complete source-evidence report — declarations, imports, crypto,
// security signals, supply chain, all already computed — because one optional
// graph could not be built. Recovering keeps the report and says plainly what
// was lost. The panic is never swallowed: it is reported verbatim, since a
// silent degradation is worse than a crash.
func guardAlgorithm(name string, build func() *callgraph.Graph) (graph *callgraph.Graph, diagnostics []model.Diagnostic) {
	defer func() {
		if recovered := recover(); recovered != nil {
			graph = nil
			diagnostics = append(diagnostics, model.Diagnostic{
				Kind:    "callgraph",
				Message: fmt.Sprintf("%s call-graph construction panicked in x/tools and was recovered: %v", name, recovered),
			})
		}
	}()
	return build(), nil
}

// panicked reports whether any diagnostic records a recovered panic, which is
// what distinguishes "the algorithm broke" from "the algorithm legitimately
// produced nothing".
func panicked(diagnostics []model.Diagnostic) bool {
	for _, d := range diagnostics {
		if strings.Contains(d.Message, "panicked in x/tools") {
			return true
		}
	}
	return false
}

func reachableFunctions(graph *callgraph.Graph) map[*ssa.Function]bool {
	funcs := map[*ssa.Function]bool{}
	if graph == nil {
		return funcs
	}
	for fn := range graph.Nodes {
		if fn != nil {
			funcs[fn] = true
		}
	}
	return funcs
}

// appendLinknameEdges connects symbols aliased with //go:linkname.
//
// The directive is a pragma in a comment: neither the type checker nor SSA
// records it, so a call through a linknamed alias is a call into nothing and
// the graph simply stops. That is also why it is a security signal in its own
// right — it is the supported way to reach an unexported or runtime-internal
// function, and it is invisible to every analysis that does not read comments.
//
// The edge always runs local → target. For a pull directive that is the
// dispatch direction outright; for a push, where the local body is published
// under the target's name, it records the alias rather than a call, and the
// `linknameKind` property says which.
func (a *Analyzer) appendLinknameEdges(cg *model.CallGraph) {
	if a.native == nil || cg == nil {
		return
	}
	directives := a.native.Linknames()
	if len(directives) == 0 {
		return
	}
	known := make(map[string]bool, len(cg.Nodes))
	for _, node := range cg.Nodes {
		known[node.ID] = true
	}
	added := 0
	for _, directive := range directives {
		local := a.native.ResolveTarget(directive.PackagePath + "." + directive.Local)
		target := a.native.ResolveTarget(directive.Target)
		if local == nil || target == nil {
			// A directive into the runtime, or into a package this build did
			// not load. Say so: an unresolved linkname is a real hole in the
			// graph, and silence would hide it.
			cg.Diagnostics = append(cg.Diagnostics, model.Diagnostic{
				Kind:    "callgraph",
				Message: fmt.Sprintf("//go:linkname %s %s is unresolved in the loaded program", directive.Local, directive.Target),
			})
			continue
		}
		source, sink := a.callGraphNode(local), a.callGraphNode(target)
		for _, node := range []model.CallGraphNode{source, sink} {
			if !known[node.ID] {
				known[node.ID] = true
				cg.Nodes = append(cg.Nodes, node)
			}
		}
		kind := "push"
		if directive.Pull {
			kind = "pull"
		}
		id := stableEdgeID(source.ID, sink.ID, directive.Position, "linkname")
		cg.Edges = append(cg.Edges, model.CallGraphEdge{
			ID:         id,
			SourceID:   source.ID,
			TargetID:   sink.ID,
			SourceName: local.String(),
			TargetName: target.String(),
			SourcePURL: source.PURL,
			SinkPURL:   sink.PURL,
			PURLs:      orderedUniqueStrings([]string{source.PURL, sink.PURL}),
			CallType:   "linkname",
			Position:   directive.Position,
			Properties: map[string]string{"linknameKind": kind, "linknameTarget": directive.Target},
		})
		added++
	}
	if added == 0 {
		return
	}
	sort.Slice(cg.Nodes, func(i, j int) bool { return cg.Nodes[i].ID < cg.Nodes[j].ID })
	sort.Slice(cg.Edges, func(i, j int) bool { return cg.Edges[i].ID < cg.Edges[j].ID })
	cg.Stats.NodeCount = len(cg.Nodes)
	cg.Stats.EdgeCount = len(cg.Edges)
}

func (a *Analyzer) convertCallGraph(out *model.CallGraph, graph *callgraph.Graph) *model.CallGraph {
	nodeIDs := map[*callgraph.Node]string{}
	nodeModels := map[*callgraph.Node]model.CallGraphNode{}
	for fn, node := range graph.Nodes {
		if fn == nil || node == nil {
			continue
		}
		n := a.callGraphNode(fn)
		nodeIDs[node] = n.ID
		nodeModels[node] = n
		out.Nodes = append(out.Nodes, n)
	}
	seenEdges := map[string]bool{}
	for _, node := range graph.Nodes {
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Caller == nil || edge.Callee == nil {
				continue
			}
			sourceID, ok1 := nodeIDs[edge.Caller]
			targetID, ok2 := nodeIDs[edge.Callee]
			if !ok1 || !ok2 {
				continue
			}
			pos := model.Position{}
			callType := "static"
			if edge.Site != nil {
				pos = a.position(edge.Site.Pos())
				if common := edge.Site.Common(); common != nil && common.StaticCallee() == nil {
					callType = classifyCallType(edge.Site, common)
				}
			} else {
				callType = "synthetic-root"
			}
			id := stableEdgeID(sourceID, targetID, pos, callType)
			if seenEdges[id] {
				continue
			}
			seenEdges[id] = true
			sourcePURL := nodeModels[edge.Caller].PURL
			sinkPURL := nodeModels[edge.Callee].PURL
			synthetic := edge.Site == nil
			out.Edges = append(out.Edges, model.CallGraphEdge{
				ID:         id,
				SourceID:   sourceID,
				TargetID:   targetID,
				SourceName: edge.Caller.Func.String(),
				TargetName: edge.Callee.Func.String(),
				SourcePURL: sourcePURL,
				SinkPURL:   sinkPURL,
				PURLs:      orderedUniqueStrings([]string{sourcePURL, sinkPURL}),
				CallType:   callType,
				Static:     callType == "static",
				Synthetic:  synthetic,
				Position:   pos,
			})
		}
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	sort.Slice(out.Edges, func(i, j int) bool { return out.Edges[i].ID < out.Edges[j].ID })
	out.Stats.NodeCount = len(out.Nodes)
	out.Stats.EdgeCount = len(out.Edges)
	return out
}

// classifyCallType returns a richer call-type label than the old static/dynamic
// binary. The full enum: static | interface | func-value | bound-method | defer |
// go | reflect | cgo | linkname | asm | synthetic-root.
func classifyCallType(instr ssa.Instruction, common *ssa.CallCommon) string {
	switch instr.(type) {
	case *ssa.Go:
		return "go"
	case *ssa.Defer:
		return "defer"
	}
	if common == nil {
		return "dynamic"
	}
	callee := common.StaticCallee()
	// Synthetic wrappers get their SSA string as the call type.
	if callee != nil && callee.Synthetic != "" {
		return string(callee.Synthetic)
	}
	// Reflect calls: reflect.Value.Call, etc.
	if callee != nil && callee.Pkg != nil && callee.Pkg.Pkg != nil {
		pkgPath := callee.Pkg.Pkg.Path()
		if pkgPath == "reflect" {
			return "reflect"
		}
	}
	// Cgo calls: _Cfunc_ prefix.
	if callee != nil && strings.Contains(callee.Name(), "_Cfunc_") {
		return "cgo"
	}
	if common.IsInvoke() {
		return "interface"
	}
	if callee == nil {
		return "func-value"
	}
	return "static"
}

func (a *Analyzer) callGraphNode(fn *ssa.Function) model.CallGraphNode {
	pkgPath := ""
	pkgName := ""
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkgPath = fn.Pkg.Pkg.Path()
		pkgName = fn.Pkg.Pkg.Name()
	}
	// Bound-method thunks, generic wrappers and interface adapters have
	// fn.Pkg == nil. Derive the owning package so the node is classifiable
	// rather than being lumped into an unfilterable "synthetic" bucket — the
	// standard library alone contributes thousands of these.
	syntheticKind := fn.Synthetic
	if pkgPath == "" {
		pkgPath = derivePkgPath(fn)
	}
	if pkgName == "" && pkgPath != "" {
		if idx := strings.LastIndexByte(pkgPath, '/'); idx >= 0 {
			pkgName = pkgPath[idx+1:]
		} else {
			pkgName = pkgPath
		}
	}
	mod := a.moduleForPackagePath(pkgPath)
	sig := ""
	if fn.Signature != nil {
		sig = types.TypeString(fn.Signature, qualifier(pkgPath))
	}
	receiver := ""
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		receiver = types.TypeString(fn.Signature.Recv().Type(), qualifier(pkgPath))
	}
	name := fn.Name()
	if fn.Object() != nil {
		name = fn.Object().Name()
	}
	return model.CallGraphNode{
		ID:            fn.String(),
		Name:          name,
		Label:         fn.String(),
		Kind:          "function",
		PackagePath:   pkgPath,
		PackageName:   pkgName,
		Module:        mod,
		PURL:          packagePURL(pkgPath, mod),
		Standard:      isStandardPackage(pkgPath, mod),
		Local:         isLocalModule(mod),
		External:      !isLocalModule(mod),
		Synthetic:     fn.Synthetic != "",
		SyntheticKind: syntheticKind,
		Visibility:    a.nodeVisibility(pkgPath, mod, a.position(fn.Pos())),
		Signature:     sig,
		Receiver:      receiver,
		Position:      a.position(fn.Pos()),
	}
}

// derivePkgPath finds the package a function belongs to when fn.Pkg is nil.
//
// Each fallback covers a shape the previous one misses: a generic instantiation
// has an origin, a wrapper has a receiver, a thunk has neither because its
// receiver is bound into the first parameter, and an anonymous function has a
// parent. Order matters, and the parameter case is the one that classifies the
// thunks the standard library produces in bulk.
func derivePkgPath(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	if origin := fn.Origin(); origin != nil && origin.Pkg != nil && origin.Pkg.Pkg != nil {
		return origin.Pkg.Pkg.Path()
	}
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		if path := packagePathFromType(fn.Signature.Recv().Type()); path != "" {
			return path
		}
	}
	if fn.Signature != nil && fn.Signature.Params() != nil && fn.Signature.Params().Len() > 0 {
		if path := packagePathFromType(fn.Signature.Params().At(0).Type()); path != "" {
			return path
		}
	}
	if parent := fn.Parent(); parent != nil {
		if parent.Pkg != nil && parent.Pkg.Pkg != nil {
			return parent.Pkg.Pkg.Path()
		}
		return derivePkgPath(parent)
	}
	return ""
}

// nodeVisibility classifies a node by where it lives. When no package could be
// derived, the source position still tells us whether the function came from the
// toolchain or from a module cache, which is enough to keep it out of the
// caller's view.
func (a *Analyzer) nodeVisibility(pkgPath string, mod *model.Module, position model.Position) string {
	if pkgPath != "" {
		switch {
		case isStandardPackage(pkgPath, mod):
			return "stdlib"
		case isLocalModule(mod):
			return "local"
		default:
			return "dependency"
		}
	}
	switch {
	case isGoRootPath(position.Filename):
		return "stdlib"
	case isGoModuleCachePath(position.Filename):
		return "dependency"
	default:
		return "synthetic"
	}
}

// isGoRootPath reports whether a file lives in the Go toolchain tree.
func isGoRootPath(path string) bool {
	root := strings.TrimSpace(build.Default.GOROOT)
	if root == "" || path == "" {
		return false
	}
	normalized := filepath.ToSlash(path)
	root = strings.TrimSuffix(filepath.ToSlash(root), "/")
	return strings.HasPrefix(normalized, root+"/")
}

func (a *Analyzer) includeGraphNode(node model.CallGraphNode) bool {
	// With visibility classification all nodes are kept; presentation filtering
	// moves to flow_filter.go as a post-reachability view concern.
	return true
}

// resolveRoots picks the SSA roots for RTA seeding. When the user passes
// explicit --roots flags those drive the selection; otherwise the legacy
// heuristic (main/init + synthetic registrations) applies.
func (a *Analyzer) resolveRoots(ctx *ssaContext) []*ssa.Function {
	if len(a.options.Roots) > 0 {
		return a.userRoots(ctx)
	}
	return legacyRtaRoots(ctx)
}

// userRoots resolves the --roots specifiers against the loaded SSA program.
func (a *Analyzer) userRoots(ctx *ssaContext) []*ssa.Function {
	seen := map[*ssa.Function]string{} // fn -> rootReason
	allFn := allSSAFunctions(ctx)

	for _, spec := range a.options.Roots {
		spec = strings.TrimSpace(spec)
		switch {
		case spec == "main":
			for _, fn := range allFn {
				if fn.Name() == "main" && fn.Parent() == nil {
					seen[fn] = "main"
				}
			}
		case spec == "init":
			for _, fn := range allFn {
				if fn.Name() == "init" && fn.Parent() == nil {
					seen[fn] = "init"
				}
			}
		case spec == "exported":
			for _, fn := range allFn {
				if a.isRootCandidate(fn) && isExportedAPI(fn) {
					seen[fn] = "exported"
				}
			}
		case spec == "tests":
			for _, fn := range allFn {
				if !a.isRootCandidate(fn) {
					continue
				}
				name := fn.Name()
				if strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Benchmark") || strings.HasPrefix(name, "Fuzz") || strings.HasPrefix(name, "Example") {
					seen[fn] = "test"
				}
			}
		case spec == "handlers":
			for _, fn := range allFn {
				if a.isRootCandidate(fn) && a.looksLikeHandler(fn) {
					seen[fn] = "handler"
				}
			}
		case spec == "all":
			for _, fn := range allFn {
				if a.isRootCandidate(fn) && fn.Parent() == nil && fn.Synthetic == "" {
					seen[fn] = "all"
				}
			}
			// Under --roots all, any function value that escapes into
			// a struct field or an unresolved call is a root candidate.
			for _, fn := range allFn {
				if fn.Parent() != nil || !a.isRootCandidate(fn) {
					continue
				}
				for _, block := range fn.Blocks {
					for _, instr := range block.Instrs {
						switch x := instr.(type) {
						case *ssa.Go:
							for _, target := range callbackFunctions(x.Common().Value) {
								if target != nil {
									seen[target] = "escaped-func-value"
								}
							}
						case *ssa.Defer:
							for _, target := range callbackFunctions(x.Common().Value) {
								if target != nil {
									seen[target] = "escaped-func-value"
								}
							}
						case *ssa.Store:
							if isEscapedFuncStore(x) {
								for _, target := range callbackFunctions(valueFromStore(x.Val)) {
									if target != nil {
										seen[target] = "escaped-func-value"
									}
								}
							}
						}
					}
				}
			}
		case strings.HasPrefix(spec, "symbol:"):
			pattern := strings.TrimPrefix(spec, "symbol:")
			for _, fn := range allFn {
				if fn.Blocks != nil && matchSymbolPattern(fn, pattern) {
					seen[fn] = "symbol:" + pattern
				}
			}
		}
	}

	var roots []*ssa.Function
	for fn, reason := range seen {
		roots = append(roots, fn)
		_ = reason // stored in callGraph.roots[]
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].String() < roots[j].String() })
	return roots
}

// callableFunctions drops roots RTA cannot start from. rta.Analyze puts every
// root straight on its worklist and reads root.Blocks without a nil check, so a
// nil root segfaults inside x/tools instead of yielding a smaller graph. A
// bodyless root is kept: it contributes no edges but is still a graph node, and
// dropping it would silently shrink the reported call graph.
func callableFunctions(fns []*ssa.Function) []*ssa.Function {
	out := make([]*ssa.Function, 0, len(fns))
	for _, fn := range fns {
		if fn == nil {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// legacyRtaRoots is the existing heuristic (main+init + synthetic registrations).
func legacyRtaRoots(ctx *ssaContext) []*ssa.Function {
	seen := map[*ssa.Function]bool{}
	var roots []*ssa.Function
	add := func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		roots = append(roots, fn)
	}
	for _, fn := range mainAndInitRoots(ctx.packages) {
		add(fn)
	}
	for _, fn := range syntheticRTARoots(ctx) {
		add(fn)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].String() < roots[j].String() })
	return roots
}

// allSSAFunctions returns every non-nil function in the SSA program.
// allSSAFunctions returns every function in the program, including methods.
//
// Package members hold only package-level functions, so selecting roots from
// them alone misses every method — which for a library is most of its API.
func allSSAFunctions(ctx *ssaContext) []*ssa.Function {
	if ctx == nil {
		return nil
	}
	return ctx.functions
}

// isRootCandidate limits root selection to the module under analysis. Without
// it, "exported" or "all" would make every exported function in the standard
// library and in every dependency a root, which is both meaningless and
// ruinously expensive.
func (a *Analyzer) isRootCandidate(fn *ssa.Function) bool {
	if fn == nil || fn.Blocks == nil {
		return false
	}
	pkgPath := ""
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkgPath = fn.Pkg.Pkg.Path()
	} else {
		pkgPath = derivePkgPath(fn)
	}
	if pkgPath == "" {
		return false
	}
	mod := a.moduleForPackagePath(pkgPath)
	if isStandardPackage(pkgPath, mod) {
		return false
	}
	return isLocalModule(mod)
}

// isExportedAPI reports whether a function is part of the package's exported
// surface: an exported package-level function, or an exported method on an
// exported named type.
func isExportedAPI(fn *ssa.Function) bool {
	obj := fn.Object()
	if obj == nil || !obj.Exported() {
		return false
	}
	if fn.Parent() != nil {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() == nil {
		return true
	}
	recv := fn.Signature.Recv().Type()
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	if !ok || named.Obj() == nil {
		return false
	}
	return named.Obj().Exported()
}

// matchSymbolPattern checks a function against a regex pattern on its
// fully-qualified symbol name or plain name.
func matchSymbolPattern(fn *ssa.Function, pattern string) bool {
	if fn == nil {
		return false
	}
	id := fn.String()
	name := fn.Name()
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		id = fn.Object().Pkg().Path() + "." + fn.Object().Name()
	}
	return strings.Contains(strings.ToLower(id), strings.ToLower(pattern)) ||
		strings.Contains(strings.ToLower(name), strings.ToLower(pattern))
}

// looksLikeHandler is a lightweight heuristic the "handlers" root set uses to
// recognise HTTP handler functions without repeating the registration
// substring heuristic in isSyntheticRegistration.
func (a *Analyzer) looksLikeHandler(fn *ssa.Function) bool {
	if fn == nil || fn.Signature == nil {
		return false
	}
	sig := fn.Signature
	// http.HandlerFunc: func(ResponseWriter, *Request)
	if sig.Params().Len() == 2 {
		p0 := sig.Params().At(0).Type().String()
		p1 := sig.Params().At(1).Type().String()
		if (strings.Contains(p0, "ResponseWriter") || strings.Contains(p0, "http.ResponseWriter")) &&
			(strings.Contains(p1, "*Request") || strings.Contains(p1, "*http.Request")) {
			return true
		}
	}
	return false
}

// rootReasonFor returns a human-readable label for why a function was chosen.
func (a *Analyzer) rootReasonFor(fn *ssa.Function) string {
	if fn.Name() == "main" && fn.Parent() == nil {
		return "main"
	}
	if fn.Name() == "init" && fn.Parent() == nil {
		return "init"
	}
	if fn.Object() != nil && fn.Object().Exported() {
		return "exported"
	}
	if a.looksLikeHandler(fn) {
		return "handler"
	}
	return "synthetic-registration"
}

// mainAndInitRoots returns main and init functions from the loaded packages.
func mainAndInitRoots(pkgs []*ssa.Package) []*ssa.Function {
	var roots []*ssa.Function
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		if pkg.Func("init") != nil {
			roots = append(roots, pkg.Func("init"))
		}
		if pkg.Func("main") != nil {
			roots = append(roots, pkg.Func("main"))
		}
	}
	return roots
}

// buildAutoCallGraph implements the --callgraph auto pipeline:
//
//	cha seed → rta from resolved roots → vta iterated twice over RTA result,
//	falling back vta → rta → cha → static on timeout.
func (a *Analyzer) buildAutoCallGraph(ctx *ssaContext) (*callgraph.Graph, string, []model.Diagnostic) {
	var diagnostics []model.Diagnostic

	// Every phase is guarded: this pipeline already falls back down the chain,
	// and a panic inside one algorithm is one more reason to fall back rather
	// than a reason to abandon the report.

	// Phase 1: CHA as seed.
	chaGraph, chaDiags := guardAlgorithm("cha", func() *callgraph.Graph { return cha.CallGraph(ctx.program) })
	diagnostics = append(diagnostics, chaDiags...)
	if chaGraph == nil {
		diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph-auto", Message: "cha produced no graph; no call graph is available"})
		return nil, "auto", diagnostics
	}
	diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph-auto", Message: "seed: cha (" + fmt.Sprintf("%d nodes", len(chaGraph.Nodes)) + ")"})

	// Phase 2: RTA from resolved roots.
	roots := callableFunctions(a.resolveRoots(ctx))
	rtaGraph, rtaDiags := guardAlgorithm("rta", func() *callgraph.Graph {
		result := rta.Analyze(roots, true)
		if result == nil {
			return nil
		}
		return result.CallGraph
	})
	diagnostics = append(diagnostics, rtaDiags...)
	if rtaGraph == nil {
		diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph-auto", Message: "rta returned no graph; falling back to cha"})
		return chaGraph, "cha", diagnostics
	}
	diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph-auto", Message: "rta: " + fmt.Sprintf("%d nodes", len(rtaGraph.Nodes)) + " from " + fmt.Sprintf("%d roots", len(roots))})

	// Phase 3: VTA twice over RTA result.
	vta2, vtaDiags := guardAlgorithm("vta", func() *callgraph.Graph {
		vta1 := vta.CallGraph(reachableFunctions(rtaGraph), rtaGraph)
		return vta.CallGraph(reachableFunctions(vta1), vta1)
	})
	diagnostics = append(diagnostics, vtaDiags...)
	if vta2 == nil {
		diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph-auto", Message: "vta returned no graph; falling back to rta"})
		return rtaGraph, "rta", diagnostics
	}
	diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph-auto", Message: fmt.Sprintf("vta×2: %d nodes", len(vta2.Nodes))})

	return vta2, "auto", diagnostics
}

func syntheticRTARoots(ctx *ssaContext) []*ssa.Function {
	if ctx == nil {
		return nil
	}
	reachable := reachableFromRoots(static.CallGraph(ctx.program), mainAndInitRoots(ctx.packages))
	seen := map[*ssa.Function]bool{}
	var roots []*ssa.Function
	add := func(fn *ssa.Function) {
		if fn == nil || seen[fn] {
			return
		}
		seen[fn] = true
		roots = append(roots, fn)
	}
	for _, fn := range ctx.functions {
		if fn == nil || !reachable[fn] {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				switch x := instr.(type) {
				case *ssa.Call:
					if isSyntheticRegistration(x.Common()) {
						for _, arg := range callArgs(x.Common()) {
							for _, target := range callbackFunctions(arg) {
								add(target)
							}
						}
					}
				case *ssa.Go:
					for _, target := range callbackFunctions(x.Common().Value) {
						add(target)
					}
					if callee := x.Common().StaticCallee(); callee != nil {
						add(callee)
					}
				case *ssa.Defer:
					if isSyntheticRegistration(x.Common()) {
						for _, target := range callbackFunctions(x.Common().Value) {
							add(target)
						}
					}
				case *ssa.Store:
					if isCallbackFieldStore(x) {
						for _, target := range callbackFunctions(valueFromStore(x.Val)) {
							add(target)
						}
					}
				}
			}
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].String() < roots[j].String() })
	return roots
}

func reachableFromRoots(graph *callgraph.Graph, roots []*ssa.Function) map[*ssa.Function]bool {
	reachable := map[*ssa.Function]bool{}
	if graph == nil {
		for _, root := range roots {
			if root != nil {
				reachable[root] = true
			}
		}
		return reachable
	}
	var visit func(*callgraph.Node)
	visit = func(node *callgraph.Node) {
		if node == nil || node.Func == nil || reachable[node.Func] {
			return
		}
		reachable[node.Func] = true
		for _, edge := range node.Out {
			if edge != nil {
				visit(edge.Callee)
			}
		}
	}
	for _, root := range roots {
		if root == nil {
			continue
		}
		if node := graph.Nodes[root]; node != nil {
			visit(node)
			continue
		}
		reachable[root] = true
	}
	return reachable
}

func isSyntheticRegistration(common *ssa.CallCommon) bool {
	if common == nil {
		return false
	}
	if len(callArgs(common)) == 0 {
		return false
	}
	// First pass: structural detection via the declarative framework model.
	if isFrameworkRegistration(common) {
		return true
	}
	// Second pass: narrow heuristic based on call symbol/name (kept for
	// non-framework registrations like cobra commands, testing.M, asynq
	// consumers, etc., which don't have a resolved receiver type).
	text := strings.ToLower(callName(common) + " " + callSymbol(common))
	for _, token := range []string{"handlefunc", "handle(", "handlerfunc", ".run(", ".rune(", ".prerun(", ".postrun(", ".persistentprerun(", ".persistentpostrun("} {
		if strings.Contains(text, token) {
			return true
		}
	}
	if common.Method != nil {
		// Method on a known receiver type is a potential registration.
		if sig, ok := common.Method.Type().(*types.Signature); ok && sig != nil && sig.Recv() != nil {
			recvType := sig.Recv().Type().String()
			for _, name := range []string{"mux", "router", "engine", "app", "group", "server", "command"} {
				if strings.Contains(strings.ToLower(recvType), name) {
					return true
				}
			}
		}
	}
	return false
}

// isFrameworkRegistration checks whether a call matches a known framework
// registration pattern by inspecting the resolved receiver type and method.
func isFrameworkRegistration(common *ssa.CallCommon) bool {
	symbol := callSymbol(common)
	name := callName(common)
	framework := endpointFramework(symbol, name)
	if framework == "" {
		return false
	}
	// Frameworks we recognize: any call on a recognised framework's type that
	// passes a function value as an argument is a potential registration.
	for _, arg := range callArgs(common) {
		if callbackFunctions(arg) != nil {
			return true
		}
	}
	// Also: calls that structurally match route registrations.
	classification, ok := classifyEndpointCall(symbol, name, framework, len(callArgs(common)))
	if !ok {
		return false
	}
	_ = classification
	return true
}

func isSyntheticHTTPVerbRegistration(name, symbol, receiverType string) bool {
	// Replaced by isFrameworkRegistration; kept as no-op for back-compat.
	return false
}

func syntheticRegistrationReceiverType(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if callee := common.StaticCallee(); callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil {
		return callee.Signature.Recv().Type().String()
	}
	if common.Method != nil {
		if sig, ok := common.Method.Type().(*types.Signature); ok && sig != nil && sig.Recv() != nil {
			return sig.Recv().Type().String()
		}
	}
	if sig := common.Signature(); sig != nil && sig.Recv() != nil {
		return sig.Recv().Type().String()
	}
	return ""
}

func callbackFunctions(v ssa.Value) []*ssa.Function {
	switch x := v.(type) {
	case *ssa.Function:
		return []*ssa.Function{x}
	case *ssa.MakeClosure:
		if fn, ok := x.Fn.(*ssa.Function); ok && fn != nil {
			return []*ssa.Function{fn}
		}
	case *ssa.ChangeType:
		return callbackFunctions(x.X)
	case *ssa.MakeInterface:
		return callbackFunctions(x.X)
	case *ssa.UnOp:
		return callbackFunctions(x.X)
	}
	return nil
}

func isCallbackFieldStore(store *ssa.Store) bool {
	if store == nil {
		return false
	}
	fieldAddr, ok := store.Addr.(*ssa.FieldAddr)
	if !ok {
		return false
	}
	fieldName := callbackFieldName(fieldAddr)
	if fieldName == "" {
		return false
	}
	return len(callbackFunctions(valueFromStore(store.Val))) > 0
}

// isEscapedFuncStore detects any store of a function value into a struct field.
// Broader than isCallbackFieldStore: doesn't filter on the field name. Used under
// --roots all to label escaped function values.
func isEscapedFuncStore(store *ssa.Store) bool {
	if store == nil {
		return false
	}
	if _, ok := store.Addr.(*ssa.FieldAddr); !ok {
		return false
	}
	return len(callbackFunctions(valueFromStore(store.Val))) > 0
}

func callbackFieldName(fieldAddr *ssa.FieldAddr) string {
	if fieldAddr == nil {
		return ""
	}
	ptr, ok := fieldAddr.X.Type().Underlying().(*types.Pointer)
	if !ok {
		return ""
	}
	strct, ok := ptr.Elem().Underlying().(*types.Struct)
	if !ok || fieldAddr.Field < 0 || fieldAddr.Field >= strct.NumFields() {
		return ""
	}
	name := strings.ToLower(strct.Field(fieldAddr.Field).Name())
	for _, token := range []string{"run", "rune", "prerun", "postrun", "persistentprerun", "persistentpostrun", "handler", "middleware", "interceptor", "callback", "consumer"} {
		if name == token {
			return name
		}
	}
	return ""
}

func valueFromStore(v ssa.Value) ssa.Value {
	switch x := v.(type) {
	case *ssa.MakeInterface:
		return x.X
	case *ssa.ChangeType:
		return x.X
	default:
		return v
	}
}

// computeReachability builds per-node reachability information using an explicit
// worklist (BFS) — no recursion, so large graphs don't overflow the stack.
func (a *Analyzer) computeReachability(cg *model.CallGraph) *model.ReachabilityInfo {
	if cg == nil || len(cg.Nodes) == 0 {
		return nil
	}
	// Build adjacency list from edges.
	adj := map[string][]string{}
	for _, edge := range cg.Edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edge.TargetID)
	}

	// Collect root IDs from the recorded roots.
	rootIDs := map[string]bool{}
	rootSet := map[string][]string{} // nodeID -> list of rootIDs that reach it
	for _, root := range cg.Roots {
		rootIDs[root.ID] = true
	}

	// BFS from each root to compute minDepth and root assignments.
	depth := map[string]int{}
	for _, root := range cg.Roots {
		if root.ID == "" {
			continue
		}
		queue := []string{root.ID}
		if _, seen := depth[root.ID]; !seen {
			depth[root.ID] = 0
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, next := range adj[cur] {
				if _, seen := depth[next]; seen {
					// Record this root as reaching the node.
					rootSet[next] = append(rootSet[next], root.ID)
					continue
				}
				depth[next] = depth[cur] + 1
				rootSet[next] = append(rootSet[next], root.ID)
				queue = append(queue, next)
			}
		}
	}

	// Build per-node reachability entries.
	info := &model.ReachabilityInfo{}
	for _, node := range cg.Nodes {
		d, reachable := depth[node.ID]
		if !reachable {
			info.Nodes = append(info.Nodes, model.ReachableNode{
				NodeID:             node.ID,
				ReachableFromRoots: false,
			})
			continue
		}
		rids := orderedUniqueStrings(rootSet[node.ID])
		info.Nodes = append(info.Nodes, model.ReachableNode{
			NodeID:             node.ID,
			ReachableFromRoots: true,
			MinDepth:           d,
			RootIDs:            rids,
		})
	}
	sort.Slice(info.Nodes, func(i, j int) bool { return info.Nodes[i].NodeID < info.Nodes[j].NodeID })
	return info
}

// computeWitnessPaths finds shortest paths from roots to each target symbol.
func (a *Analyzer) computeWitnessPaths(cg *model.CallGraph, targets []string, maxPaths int) []model.WitnessPath {
	if cg == nil || len(targets) == 0 {
		return nil
	}
	// Build adjacency with edge IDs.
	type edgeLink struct {
		target string
		edgeID string
	}
	adj := map[string][]edgeLink{}
	for _, edge := range cg.Edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edgeLink{target: edge.TargetID, edgeID: edge.ID})
	}

	// Collect node IDs matching each target symbol pattern.
	targetNodes := map[string][]string{}
	for _, node := range cg.Nodes {
		for _, target := range targets {
			if matchSymbolPatternStr(node.ID, target) || matchSymbolPatternStr(node.Label, target) {
				targetNodes[target] = append(targetNodes[target], node.ID)
			}
		}
	}

	// BFS from each root to find shortest paths to each target.
	var paths []model.WitnessPath
	for _, root := range cg.Roots {
		if root.ID == "" {
			continue
		}
		type bfsEntry struct {
			node  string
			nodes []string
			edges []string
		}
		seen := map[string]bool{root.ID: true}
		queue := []bfsEntry{{node: root.ID, nodes: []string{root.ID}}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, target := range targets {
				targetLimit := maxPaths
				if targetLimit <= 0 {
					targetLimit = 3
				}
				matched := 0
				for _, tn := range targetNodes[target] {
					if cur.node == tn {
						paths = append(paths, model.WitnessPath{
							Symbol:  target,
							NodeIDs: cur.nodes,
							EdgeIDs: cur.edges,
							Depth:   len(cur.nodes) - 1,
						})
						matched++
						if matched >= targetLimit {
							break
						}
					}
				}
			}
			for _, link := range adj[cur.node] {
				if seen[link.target] {
					continue
				}
				seen[link.target] = true
				newNodes := append(append([]string{}, cur.nodes...), link.target)
				newEdges := append(append([]string{}, cur.edges...), link.edgeID)
				queue = append(queue, bfsEntry{node: link.target, nodes: newNodes, edges: newEdges})
			}
		}
	}

	// Sort deterministically.
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Symbol == paths[j].Symbol {
			return paths[i].Depth < paths[j].Depth
		}
		return paths[i].Symbol < paths[j].Symbol
	})
	// Limit per symbol.
	if maxPaths <= 0 {
		maxPaths = 3
	}
	limited := make([]model.WitnessPath, 0, len(paths))
	countBySymbol := map[string]int{}
	for _, p := range paths {
		if countBySymbol[p.Symbol] >= maxPaths {
			continue
		}
		countBySymbol[p.Symbol]++
		limited = append(limited, p)
	}
	return limited
}

func matchSymbolPatternStr(id, pattern string) bool {
	return strings.Contains(strings.ToLower(id), strings.ToLower(pattern))
}

// readSymbolsFile reads a newline-separated list of symbol patterns from a file.
func readSymbolsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}
