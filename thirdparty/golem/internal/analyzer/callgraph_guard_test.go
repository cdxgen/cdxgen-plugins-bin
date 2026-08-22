package analyzer

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
)

func TestGuardAlgorithmConvertsAPanicIntoADiagnostic(t *testing.T) {
	graph, diags := guardAlgorithm("rta", func() *callgraph.Graph {
		var fn *struct{ Blocks []int }
		_ = fn.Blocks // the shape rta.visitFunc dies on: nil deref
		return nil
	})
	if graph != nil {
		t.Fatalf("want no graph after a panic, got %v", graph)
	}
	if len(diags) != 1 {
		t.Fatalf("want one diagnostic, got %d: %+v", len(diags), diags)
	}
	if diags[0].Kind != "callgraph" {
		t.Errorf("diagnostic kind = %q, want %q", diags[0].Kind, "callgraph")
	}
	// The panic value must survive into the message: a recovered panic reported
	// without its cause is indistinguishable from an empty result.
	for _, want := range []string{"rta", "panicked in x/tools", "nil pointer"} {
		if !strings.Contains(diags[0].Message, want) {
			t.Errorf("message does not mention %q: %s", want, diags[0].Message)
		}
	}
	if !panicked(diags) {
		t.Error("panicked() does not recognise its own diagnostic, so the cha fallback would never trigger")
	}
}

func TestGuardAlgorithmPassesTheGraphThroughWhenNothingPanics(t *testing.T) {
	sentinel := &callgraph.Graph{}
	graph, diags := guardAlgorithm("cha", func() *callgraph.Graph { return sentinel })
	if graph != sentinel {
		t.Errorf("graph = %v, want the sentinel back unchanged", graph)
	}
	if len(diags) != 0 {
		t.Errorf("want no diagnostics on the happy path, got %+v", diags)
	}
	if panicked(diags) {
		t.Error("panicked() reports a panic where none happened")
	}
}

func TestPanickedIgnoresUnrelatedDiagnostics(t *testing.T) {
	// "RTA requires at least one reachable root function" is a legitimate empty
	// result, not a breakage, and must not trigger the fallback.
	graph, _, diags := (&Analyzer{}).buildRawCallGraph(nil, "rta")
	if graph != nil {
		t.Fatalf("want no graph without an SSA context, got %v", graph)
	}
	if panicked(diags) {
		t.Errorf("panicked() true for a non-panic diagnostic set: %+v", diags)
	}
}

// TestCallGraphModesStillProduceGraphs is the guard against the guard: wrapping
// every algorithm in a recover is only safe if the wrapping did not stop the
// graphs being built at all.
func TestCallGraphModesStillProduceGraphs(t *testing.T) {
	skipIfShort(t, "loads and builds SSA once per call-graph mode")
	for _, mode := range []string{"static", "cha", "rta", "vta", "auto"} {
		t.Run(mode, func(t *testing.T) {
			report, err := Analyze(Options{
				Dir:           filepath.Join("..", "..", "testdata", "simple"),
				IncludeLocal:  true,
				CallGraphMode: mode,
				ToolVersion:   "test",
			})
			if err != nil {
				t.Fatalf("analyze with --callgraph %s: %v", mode, err)
			}
			if report.CallGraph == nil || len(report.CallGraph.Nodes) == 0 {
				t.Fatalf("--callgraph %s produced no nodes", mode)
			}
			for _, d := range report.CallGraph.Diagnostics {
				if strings.Contains(d.Message, "panicked in x/tools") {
					t.Errorf("--callgraph %s panicked on a clean fixture: %s", mode, d.Message)
				}
			}
		})
	}
}

// TestCallGraphModesOnGenericMethods runs every call-graph mode over a Go 1.27
// module whose concrete type carries an exported generic method and is boxed
// into an interface. That shape put a nil *ssa.Function on RTA's worklist
// (golang/go#80973): rta segfaulted, and auto silently descended to cha.
// With the vendored fix each mode must build its real graph — rta as rta,
// auto through its rta phase — with no recovered-panic diagnostic.
func TestCallGraphModesOnGenericMethods(t *testing.T) {
	skipIfShort(t, "loads and builds SSA once per call-graph mode")
	for _, mode := range []string{"static", "cha", "rta", "vta", "auto"} {
		t.Run(mode, func(t *testing.T) {
			report, err := Analyze(Options{
				Dir:           filepath.Join("..", "..", "testdata", "rta-generic-method"),
				IncludeLocal:  true,
				CallGraphMode: mode,
				ToolVersion:   "test",
			})
			if err != nil {
				t.Fatalf("analyze with --callgraph %s: %v", mode, err)
			}
			if report.CallGraph == nil || len(report.CallGraph.Nodes) == 0 {
				t.Fatalf("--callgraph %s produced no nodes on the generic-method fixture", mode)
			}
			for _, d := range report.CallGraph.Diagnostics {
				if strings.Contains(d.Message, "panicked in x/tools") {
					t.Errorf("--callgraph %s still panics on generic methods: %s", mode, d.Message)
				}
				if strings.Contains(d.Message, "fell back to") {
					t.Errorf("--callgraph %s fell back instead of completing: %s", mode, d.Message)
				}
			}
			// The requested algorithm must be the one that ran. Before the
			// fix, rta panicked and was reported as cha.
			if want := mode; report.CallGraph.Algorithm != want {
				t.Errorf("algorithm = %q, want %q", report.CallGraph.Algorithm, want)
			}
			// The fixture's real functions must be in the graph.
			var haveDescribe, haveMain bool
			for _, node := range report.CallGraph.Nodes {
				switch node.Name {
				case "Describe":
					haveDescribe = true
				case "main":
					haveMain = true
				}
			}
			if !haveMain {
				t.Error("main is missing from the graph")
			}
			if mode == "rta" && !haveDescribe {
				t.Error("Processor.Describe is missing from the rta graph; the invoke edge over Describer was lost")
			}
		})
	}
}
