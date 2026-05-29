package analyzer

import (
	"fmt"
	"go/types"
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
	if graph == nil {
		return cg
	}
	return a.convertCallGraph(cg, graph)
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
		graph = static.CallGraph(ctx.program)
	case "cha":
		graph = cha.CallGraph(ctx.program)
	case "rta":
		result := rta.Analyze(rtaRoots(ctx), true)
		if result != nil {
			graph = result.CallGraph
		} else {
			diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph", Message: "RTA requires at least one reachable root function"})
		}
	case "vta":
		initial := static.CallGraph(ctx.program)
		graph = vta.CallGraph(reachableFunctions(initial), initial)
	default:
		diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph", Message: fmt.Sprintf("unsupported callgraph mode %q", mode)})
	}
	return graph, algorithm, diagnostics
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

func (a *Analyzer) convertCallGraph(out *model.CallGraph, graph *callgraph.Graph) *model.CallGraph {
	nodeIDs := map[*callgraph.Node]string{}
	nodeModels := map[*callgraph.Node]model.CallGraphNode{}
	for fn, node := range graph.Nodes {
		if fn == nil || node == nil {
			continue
		}
		n := a.callGraphNode(fn)
		if !a.includeGraphNode(n) {
			continue
		}
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
			callType := "dynamic"
			if edge.Site != nil {
				pos = a.position(edge.Site.Pos())
				if common := edge.Site.Common(); common != nil && common.StaticCallee() != nil {
					callType = "static"
				}
			}
			id := stableEdgeID(sourceID, targetID, pos, callType)
			if seenEdges[id] {
				continue
			}
			seenEdges[id] = true
			sourcePURL := nodeModels[edge.Caller].PURL
			sinkPURL := nodeModels[edge.Callee].PURL
			out.Edges = append(out.Edges, model.CallGraphEdge{ID: id, SourceID: sourceID, TargetID: targetID, SourceName: edge.Caller.Func.String(), TargetName: edge.Callee.Func.String(), SourcePURL: sourcePURL, SinkPURL: sinkPURL, PURLs: orderedUniqueStrings([]string{sourcePURL, sinkPURL}), CallType: callType, Static: callType == "static", Position: pos})
		}
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	sort.Slice(out.Edges, func(i, j int) bool { return out.Edges[i].ID < out.Edges[j].ID })
	out.Stats.NodeCount = len(out.Nodes)
	out.Stats.EdgeCount = len(out.Edges)
	return out
}

func (a *Analyzer) callGraphNode(fn *ssa.Function) model.CallGraphNode {
	pkgPath := ""
	pkgName := ""
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkgPath = fn.Pkg.Pkg.Path()
		pkgName = fn.Pkg.Pkg.Name()
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
	return model.CallGraphNode{ID: fn.String(), Name: name, Label: fn.String(), Kind: "function", PackagePath: pkgPath, PackageName: pkgName, Module: mod, PURL: packagePURL(pkgPath, mod), Standard: isStandardPackage(pkgPath, mod), Local: isLocalModule(mod), External: !isLocalModule(mod), Synthetic: fn.Synthetic != "", Signature: sig, Receiver: receiver, Position: a.position(fn.Pos())}
}

func (a *Analyzer) includeGraphNode(node model.CallGraphNode) bool {
	if node.PackagePath == "" {
		return false
	}
	if node.Standard && !a.options.IncludeStdlib {
		return false
	}
	if node.Local && !a.options.IncludeLocal {
		return false
	}
	return true
}

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

func rtaRoots(ctx *ssaContext) []*ssa.Function {
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

func syntheticRTARoots(ctx *ssaContext) []*ssa.Function {
	if ctx == nil {
		return nil
	}
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
		if fn == nil {
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

func isSyntheticRegistration(common *ssa.CallCommon) bool {
	if common == nil {
		return false
	}
	if len(callArgs(common)) == 0 {
		return false
	}
	text := strings.ToLower(callName(common) + " " + callSymbol(common))
	for _, token := range []string{"handle", "handler", "route", "router", "register", "mount", "middleware", "interceptor", "command", "callback", "consumer", "subscribe", "use", "get", "post", "put", "patch", "delete", "any", "all"} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func callbackFunctions(v ssa.Value) []*ssa.Function {
	switch x := v.(type) {
	case *ssa.Function:
		return []*ssa.Function{x}
	case *ssa.MakeClosure:
		if x.Fn != nil {
			return []*ssa.Function{x.Fn}
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
	for _, token := range []string{"run", "handler", "middleware", "interceptor", "callback", "consumer"} {
		if strings.Contains(name, token) {
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
