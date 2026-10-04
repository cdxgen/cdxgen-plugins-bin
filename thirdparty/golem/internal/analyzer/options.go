package analyzer

import (
	"go/token"
	"io"
	"time"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/native"
)

const SchemaVersion = "https://cdxgen.github.io/cdxgen-plugins-bin/golem/schema/v6"

type Options struct {
	Dir                             string
	NoRecurse                       bool
	IncludeAllFlows                 bool
	Patterns                        []string
	BuildTags                       []string
	Tests                           bool
	IncludeStdlib                   bool
	IncludeLocal                    bool
	CallGraphMode                   string
	Roots                           []string
	CallGraphTimeout                time.Duration
	ReachableSymbols                string
	MaxPathsPerSymbol               int
	DataFlowMode                    string
	DataFlowPacks                   []string
	DataFlowConfig                  string
	DataFlowMax                     int
	DataFlowCallGraphMode           string
	DataFlowWorkers                 int
	DataFlowLargeRepoFunctions      int
	DataFlowMaxFunctionInstructions int
	DataFlowMaxTraceNodes           int
	DataFlowMaxTraceEdges           int
	DataFlowSkipGenerated           bool
	DataFlowSkipTests               bool
	DependencyDetail                string
	TaintEngine                     string // "seam" (default) or "legacy" (escape hatch)
	// Env carries extra KEY=VALUE pairs applied to the load configuration's
	// environment, on top of the process environment and winning over it.
	// Keys are allowlisted to the build shape by corpus.ValidateEnvPair —
	// GOEXPERIMENT, GOOS, GOARCH, GOAMD64, GOARM64 — because arbitrary keys
	// such as GOFLAGS would turn an analysis option into command execution in
	// the toolchain. See THREAT_MODEL.md.
	Env              []string
	MaxProcs         int
	MemoryLimit      int64
	Progress         bool
	ProgressInterval time.Duration
	ProgressWriter   io.Writer
	IncludeSSA       bool
	IncludeSources   bool
	ToolVersion      string
}

type Analyzer struct {
	fset          *token.FileSet
	options       Options
	packageByPath map[string]*packages.Package
	moduleByPath  map[string]*model.Module
	rootModules   map[string]*model.Module
	native        *native.Analyzer
	// goroot is the GOROOT of the go command the packages were loaded with,
	// and standardByPath the standard-library classification of every loaded
	// package. See isStandardPackage.
	goroot string
	// rawCallGraphs caches buildRawCallGraph results by requested mode. The
	// report call graph and the taint engines each ask for a graph from the
	// same program, and a static build is not cheap on a large one; the
	// contents depend only on (ctx, mode), so the second ask reuses the first.
	rawCallGraphs  map[string]rawCallGraphResult
	standardByPath map[string]bool
}

// rawCallGraphResult is the memoized outcome of one buildRawCallGraph call.
type rawCallGraphResult struct {
	graph       *callgraph.Graph
	algorithm   string
	diagnostics []model.Diagnostic
}
