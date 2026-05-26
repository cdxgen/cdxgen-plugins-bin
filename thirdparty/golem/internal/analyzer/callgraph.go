package analyzer

import (
	"fmt"
	"go/types"
	"io"
	"os"
	"sort"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/pointer"
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
		result := rta.Analyze(mainAndInitRoots(ctx.packages), true)
		if result != nil {
			graph = result.CallGraph
		} else {
			diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph", Message: "RTA requires at least one reachable root function"})
		}
	case "pointer":
		mains := mainPackages(ctx.packages)
		if len(mains) == 0 {
			diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph", Message: "pointer analysis requires at least one main package with main function"})
			return nil, algorithm, diagnostics
		}
		result, err := quietPointerAnalyze(&pointer.Config{Mains: mains, BuildCallGraph: true})
		if err != nil {
			diagnostics = append(diagnostics, model.Diagnostic{Kind: "callgraph", Message: err.Error()})
			algorithm = "pointer-rta-fallback"
			if fallback := rta.Analyze(mainAndInitRoots(ctx.packages), true); fallback != nil {
				graph = fallback.CallGraph
			}
		} else {
			graph = result.CallGraph
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
	for fn, node := range graph.Nodes {
		if fn == nil || node == nil {
			continue
		}
		n := a.callGraphNode(fn)
		if !a.includeGraphNode(n) {
			continue
		}
		nodeIDs[node] = n.ID
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
			out.Edges = append(out.Edges, model.CallGraphEdge{ID: id, SourceID: sourceID, TargetID: targetID, SourceName: edge.Caller.Func.String(), TargetName: edge.Callee.Func.String(), CallType: callType, Static: callType == "static", Position: pos})
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
	return model.CallGraphNode{ID: fn.String(), Name: name, Label: fn.String(), Kind: "function", PackagePath: pkgPath, PackageName: pkgName, Module: mod, PURL: modulePURL(mod), Standard: isStandardPackage(pkgPath, mod), Local: isLocalModule(mod), External: !isLocalModule(mod), Synthetic: fn.Synthetic != "", Signature: sig, Receiver: receiver, Position: a.position(fn.Pos())}
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

func mainPackages(pkgs []*ssa.Package) []*ssa.Package {
	var mains []*ssa.Package
	for _, pkg := range pkgs {
		if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Func("main") != nil {
			mains = append(mains, pkg)
		}
	}
	return mains
}

func quietPointerAnalyze(config *pointer.Config) (*pointer.Result, error) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		return pointer.Analyze(config)
	}
	os.Stderr = writer
	result, analyzeErr := pointer.Analyze(config)
	_ = writer.Close()
	os.Stderr = originalStderr
	_, _ = io.Copy(io.Discard, reader)
	_ = reader.Close()
	return result, analyzeErr
}
