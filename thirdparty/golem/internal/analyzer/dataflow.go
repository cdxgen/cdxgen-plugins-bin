package analyzer

import (
	"encoding/json"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/seam"
)

const (
	// seamCallGraphMode is the call graph SEAM is built on regardless of
	// --dataflow-callgraph. SEAM resolves dispatch through its own
	// implements-index, so the graph only has to be right about direct calls,
	// and RTA is sparse on a library-only module where there is no main to seed
	// it. The override is reported as a diagnostic rather than applied silently.
	seamCallGraphMode = "static"

	defaultDataFlowMaxTraceNodes           = 64
	defaultDataFlowMaxTraceEdges           = 128
	defaultDataFlowLargeRepoFunctions      = 1000
	defaultDataFlowMaxFunctionInstructions = 200
)

type dataFlowTrace struct {
	nodeIDs []string
	edgeIDs []string
	// tailID is the node the next hop extends from. Without it the tail is
	// whichever node happens to be last in nodeIDs, which stops being the end
	// of the path as soon as two traces merge or a node repeats — and the
	// slice then carries edges that do not join its nodes.
	tailID              string
	params              map[int]bool
	taintKinds          []string
	fieldPaths          []string
	sanitizedCategories []string
	sourceID            string
	sourceCategory      string
	sourcePURL          string
	sourcePatterns      []model.DataFlowPattern
	confidence          string
	generated           bool
}

type dataFlowState struct {
	values   map[ssa.Value]dataFlowTrace
	memory   map[string]dataFlowTrace
	chans    map[string]dataFlowTrace
	visiting map[ssa.Value]bool
	// spills names the memory locations that hold a by-value parameter,
	// which for a method includes the receiver. A field read from one of
	// these is a read of a field of that parameter: the whole-value trace
	// is visible to it (with the field recorded as a hop), while a field
	// read of an ordinary aggregate deliberately does not consult the
	// base location, or one tainted field would taint every other.
	spills map[string]bool
	// subKeys indexes the sub-locations of an aggregate: for a location's
	// key, the memory keys recorded beneath it (".field0", "[*]", and
	// their own sub-locations), kept sorted and deduplicated.
	//
	// Whole-aggregate reads and copies need every sub-location of one
	// address. Finding them by scanning memory costs a pass over every
	// location the function has recorded, per store and per load, which on
	// a large function is quadratic — and it yields them in map order, so
	// combineTraces would pick a different route between two runs on the
	// same input. The index answers in one lookup, in a fixed order.
	subKeys map[string][]string
}

type internalSummary struct {
	model         model.DataFlowMethodSummary
	paramReturn   map[int]bool
	paramSink     map[int]map[string]bool
	sourceReturns []model.DataFlowPattern
	fieldWrites   map[string]map[int]bool
	returnFields  map[string]bool
	// paramReturnFields records, per parameter, the field paths a
	// parameter-to-return flow travelled through inside the callee. A summary
	// is context-insensitive, so "parameter 0 flows to the return" is all it
	// can say at record time; the fields let the call site answer with only
	// the fields it actually tainted, which is what keeps field
	// discrimination (defect 34's negative half) intact across the call.
	paramReturnFields map[int]map[string]bool
}

type dataFlowBuilder struct {
	analyzer       *Analyzer
	out            *model.DataFlowEvidence
	patterns       *model.DataFlowPatternSet
	regexps        map[string]*regexp.Regexp
	summaries      map[*ssa.Function]*internalSummary
	endpoints      map[string][]model.APIEndpoint
	dynamicCallees map[ssa.CallInstruction][]*ssa.Function
	nodeSeen       map[string]bool
	edgeSeen       map[string]bool
	edgeByID       map[string]model.DataFlowEdge
	sliceSeen      map[string]bool
	diagnosticSeen map[string]bool
	sliceBudget    *dataFlowBudget
	maxSlices      int
	maxTraceNodes  int
	maxTraceEdges  int
	instructionCt  int
}

type dataFlowBudget struct {
	max  int64
	used atomic.Int64
}

func (a *Analyzer) buildDataFlow(pkgs []*packages.Package, ctx *ssaContext, progress *progressLogger) *model.DataFlowEvidence {
	started := time.Now()

	// SEAM is the default. On the corpus it reaches recall 0.957 against
	// legacy's 0.783 at equal precision, with a fifth of the open defects and
	// a shorter median run; on real repositories it now matches or beats
	// legacy on go-chi and stays within range elsewhere. Legacy remains
	// available behind --taint-engine=legacy.
	//
	// Neither engine is good on real code yet: on go-test-bench, whose nine
	// vulnerabilities are ground truth in
	// testdata/bench/annotations/go-test-bench.golem, legacy finds one and
	// SEAM none, because both lose taint at a function value held in a struct
	// field (defect 31). That is a shared limitation, not a reason to prefer
	// the older engine.
	engine := strings.ToLower(strings.TrimSpace(a.options.TaintEngine))
	if engine == "" {
		engine = "seam"
	}
	if engine == "seam" {
		return a.buildDataFlowSEAM(pkgs, ctx, progress, started)
	}

	patterns, diagnostics := loadDataFlowPatterns(a.options.DataFlowPacks, a.options.DataFlowConfig)
	regexps, regexDiagnostics := compileDataFlowRegexps(patterns)
	diagnostics = append(diagnostics, regexDiagnostics...)
	out := &model.DataFlowEvidence{Engine: "legacy", Mode: a.options.DataFlowMode, Patterns: patterns, Diagnostics: diagnostics}
	if ctx == nil || ctx.program == nil {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Kind: "dataflow", Message: "SSA context was not available"})
		return out
	}
	funcs := ctx.filteredFunctions(a.includeDataFlowFunction)
	sortDataFlowFunctions(funcs)
	analysisFuncs, skippedFuncs := a.dataFlowAnalysisFunctions(funcs)
	workers := dataFlowWorkerCount(a.options, len(analysisFuncs))
	progress.Memoryf("data-flow starting mode=%s functions=%d analyzedFunctions=%d skippedFunctions=%d workers=%d maxSlices=%d", a.options.DataFlowMode, len(funcs), len(analysisFuncs), skippedFuncs, workers, a.options.DataFlowMax)
	progress.Logf("data-flow scheduled first=%s largest=%s", describeDataFlowFunctions(analysisFuncs, 6, false), describeDataFlowFunctions(analysisFuncs, 6, true))
	dynamicCallees := a.dataFlowDynamicCallees(ctx, out)
	b := &dataFlowBuilder{analyzer: a, out: out, patterns: patterns, regexps: regexps, summaries: map[*ssa.Function]*internalSummary{}, endpoints: endpointHandlersForPackages(a, pkgs), dynamicCallees: dynamicCallees, nodeSeen: map[string]bool{}, edgeSeen: map[string]bool{}, edgeByID: map[string]model.DataFlowEdge{}, sliceSeen: map[string]bool{}, diagnosticSeen: map[string]bool{}, sliceBudget: newDataFlowBudget(a.options.DataFlowMax), maxSlices: a.options.DataFlowMax, maxTraceNodes: dataFlowMaxTraceNodes(a.options), maxTraceEdges: dataFlowMaxTraceEdges(a.options)}
	progress.Memoryf("data-flow inferring summaries")
	b.inferSummaries(ctx.filteredFunctions(a.includeDataFlowSummary))
	progress.Memoryf("data-flow summaries inferred")
	if skippedFuncs > 0 {
		b.addDiagnosticOnce("dataflow-budget", fmt.Sprintf("skipped %d very large functions above %d SSA instructions during slice materialization; summaries were still inferred", skippedFuncs, dataFlowMaxFunctionInstructions(a.options)))
	}
	b.analyzeFunctions(analysisFuncs, workers, progress)
	progress.Memoryf("data-flow function analysis complete")
	for _, summary := range b.summaries {
		if len(summary.model.ParamToReturn) > 0 || len(summary.model.ParamToSink) > 0 || len(summary.sourceReturns) > 0 || len(summary.fieldWrites) > 0 || summary.model.ReceiverToReturn || summary.model.Passthrough {
			if len(summary.sourceReturns) > 0 {
				if summary.model.Properties == nil {
					summary.model.Properties = map[string]string{}
				}
				cats := make([]string, 0, len(summary.sourceReturns))
				for _, p := range summary.sourceReturns {
					cats = append(cats, p.Category)
				}
				summary.model.Properties["sourceReturnCategories"] = strings.Join(uniqueStrings(cats), ",")
			}
			out.Summaries = append(out.Summaries, summary.model)
		}
	}
	enrichDataFlowSlices(out)
	sortDataFlowEvidence(out)
	out.Stats.NodeCount = len(out.Nodes)
	out.Stats.EdgeCount = len(out.Edges)
	out.Stats.SliceCount = len(out.Slices)
	out.Stats.SummaryCount = len(out.Summaries)
	out.Stats.CandidateFunctionCount = len(funcs)
	out.Stats.FunctionCount = len(analysisFuncs)
	out.Stats.SkippedFunctionCount = skippedFuncs
	out.Stats.InstructionCount = b.instructionCt
	out.Stats.WorkerCount = workers
	out.Stats.ElapsedMillis = int(time.Since(started).Milliseconds())
	out.Stats.TruncationReasons = dataFlowTruncationReasons(out.Diagnostics)
	out.Stats.Truncated = len(out.Stats.TruncationReasons) > 0
	for _, n := range out.Nodes {
		if n.Source {
			out.Stats.SourceCount++
		}
		if n.Sink {
			out.Stats.SinkCount++
		}
	}
	return out
}

func (a *Analyzer) dataFlowAnalysisFunctions(funcs []*ssa.Function) ([]*ssa.Function, int) {
	largeRepoFunctions := dataFlowLargeRepoFunctions(a.options)
	maxInstructions := dataFlowMaxFunctionInstructions(a.options)
	if largeRepoFunctions <= 0 || maxInstructions <= 0 || len(funcs) < largeRepoFunctions {
		return funcs, 0
	}
	out := make([]*ssa.Function, 0, len(funcs))
	skipped := 0
	for _, fn := range funcs {
		if a.skipDataFlowFunctionMaterialization(fn, maxInstructions) {
			skipped++
			continue
		}
		out = append(out, fn)
	}
	return out, skipped
}

func (a *Analyzer) skipDataFlowFunctionMaterialization(fn *ssa.Function, maxInstructions int) bool {
	if ssaFunctionInstructionCount(fn) > maxInstructions {
		return true
	}
	filename := a.position(fn.Pos()).Filename
	if a.options.DataFlowSkipTests && dataFlowTestLikeFunction(filename, fn) {
		return true
	}
	if a.options.DataFlowSkipGenerated && isGeneratedFile(filename) {
		return true
	}
	return false
}

func dataFlowTestLikeFunction(filename string, fn *ssa.Function) bool {
	if fileRole(filename) == "test" {
		return true
	}
	if fn == nil || fn.Signature == nil {
		return false
	}
	return testKindForFunc(fn.Name(), fn.Signature.String()) != ""
}

func dataFlowLargeRepoFunctions(options Options) int {
	if options.DataFlowLargeRepoFunctions > 0 {
		return options.DataFlowLargeRepoFunctions
	}
	return defaultDataFlowLargeRepoFunctions
}

func dataFlowMaxFunctionInstructions(options Options) int {
	if options.DataFlowMaxFunctionInstructions > 0 {
		return options.DataFlowMaxFunctionInstructions
	}
	return defaultDataFlowMaxFunctionInstructions
}

func dataFlowMaxTraceNodes(options Options) int {
	if options.DataFlowMaxTraceNodes > 0 {
		return options.DataFlowMaxTraceNodes
	}
	return defaultDataFlowMaxTraceNodes
}

func dataFlowMaxTraceEdges(options Options) int {
	if options.DataFlowMaxTraceEdges > 0 {
		return options.DataFlowMaxTraceEdges
	}
	return defaultDataFlowMaxTraceEdges
}

func sortDataFlowFunctions(funcs []*ssa.Function) {
	sort.SliceStable(funcs, func(i, j int) bool {
		ic, jc := ssaFunctionInstructionCount(funcs[i]), ssaFunctionInstructionCount(funcs[j])
		if ic != jc {
			return ic < jc
		}
		return funcs[i].String() < funcs[j].String()
	})
}

func ssaFunctionInstructionCount(fn *ssa.Function) int {
	if fn == nil {
		return 0
	}
	var count int
	for _, block := range fn.Blocks {
		if block != nil {
			count += len(block.Instrs)
		}
	}
	return count
}

func describeDataFlowFunctions(funcs []*ssa.Function, limit int, largest bool) string {
	if len(funcs) == 0 || limit <= 0 {
		return ""
	}
	start, end, step := 0, len(funcs), 1
	if largest {
		start, end, step = len(funcs)-1, -1, -1
	}
	var parts []string
	for i := start; i != end && len(parts) < limit; i += step {
		fn := funcs[i]
		if fn == nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%d)", fn.String(), ssaFunctionInstructionCount(fn)))
	}
	return strings.Join(parts, "; ")
}

func (a *Analyzer) dataFlowDynamicCallees(ctx *ssaContext, out *model.DataFlowEvidence) map[ssa.CallInstruction][]*ssa.Function {
	mode := a.options.DataFlowCallGraphMode
	if mode == "" || mode == "none" {
		return nil
	}
	graph, algorithm, diagnostics := a.buildRawCallGraph(ctx, mode)
	for _, diag := range diagnostics {
		diag.Kind = "dataflow-callgraph"
		out.Diagnostics = append(out.Diagnostics, diag)
	}
	if graph == nil {
		return nil
	}
	if out.Patterns != nil {
		if out.Patterns.Packs == nil {
			out.Patterns.Packs = []string{}
		}
	}
	out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Kind: "dataflow-callgraph", Message: "using " + algorithm + " call graph for dynamic summary replay"})
	return callGraphCalleeIndex(graph)
}

func callGraphCalleeIndex(graph *callgraph.Graph) map[ssa.CallInstruction][]*ssa.Function {
	out := map[ssa.CallInstruction][]*ssa.Function{}
	seen := map[ssa.CallInstruction]map[*ssa.Function]bool{}
	if graph == nil {
		return out
	}
	for _, node := range graph.Nodes {
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Site == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			if seen[edge.Site] == nil {
				seen[edge.Site] = map[*ssa.Function]bool{}
			}
			if seen[edge.Site][edge.Callee.Func] {
				continue
			}
			seen[edge.Site][edge.Callee.Func] = true
			out[edge.Site] = append(out[edge.Site], edge.Callee.Func)
		}
	}
	for site := range out {
		sort.Slice(out[site], func(i, j int) bool { return out[site][i].String() < out[site][j].String() })
	}
	return out
}

func (a *Analyzer) includeDataFlowFunction(fn *ssa.Function) bool {
	if fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	pkgPath := fn.Pkg.Pkg.Path()
	mod := a.moduleForPackagePath(pkgPath)
	standard := isStandardPackage(pkgPath, mod)
	local := isLocalModule(mod)
	if standard && !a.options.IncludeStdlib {
		return false
	}
	if !local && !standard && a.options.DataFlowMode != "all" {
		return false
	}
	if local && !a.options.IncludeLocal {
		return false
	}
	return true
}

// includeDataFlowSummary is the wider function set summaries are computed
// over: the analysis set plus generic instantiations.
//
// An instantiation carries no package of its own (fn.Pkg is nil), so it is
// excluded from the analysis set — and with it, in a Go 1.27 generic method,
// from every set, because a generic method has no uninstantiated SSA body at
// all: the instantiation is the only form with instructions. Nothing static
// names the callee either; the call site references the instantiation
// directly, so a summary keyed on it is the only way taint crosses the call.
// Materialisation stays in the analysis set, so an instantiation never
// reports a finding under its own name.
func (a *Analyzer) includeDataFlowSummary(fn *ssa.Function) bool {
	if a.includeDataFlowFunction(fn) {
		return true
	}
	if origin := fn.Origin(); origin != nil {
		return a.includeDataFlowFunction(origin)
	}
	return false
}

func loadDataFlowPatterns(packs []string, path string) (*model.DataFlowPatternSet, []model.Diagnostic) {
	set := builtinDataFlowPatterns(packs)
	var diagnostics []model.Diagnostic
	if strings.TrimSpace(path) == "" {
		return set, diagnostics
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return set, []model.Diagnostic{{Kind: "dataflow-patterns", Message: err.Error()}}
	}
	var user model.DataFlowPatternSet
	if err := json.Unmarshal(data, &user); err != nil {
		return set, []model.Diagnostic{{Kind: "dataflow-patterns", Message: err.Error()}}
	}
	set.Sources = append(set.Sources, normalizePatterns("source", user.Sources)...)
	set.Sinks = append(set.Sinks, normalizePatterns("sink", user.Sinks)...)
	set.Passthroughs = append(set.Passthroughs, normalizePatterns("passthrough", user.Passthroughs)...)
	set.Sanitizers = append(set.Sanitizers, normalizePatterns("sanitizer", user.Sanitizers)...)
	return set, diagnostics
}

func compileDataFlowRegexps(set *model.DataFlowPatternSet) (map[string]*regexp.Regexp, []model.Diagnostic) {
	compiled := map[string]*regexp.Regexp{}
	if set == nil {
		return compiled, nil
	}
	var diagnostics []model.Diagnostic
	for _, p := range allDataFlowPatterns(set) {
		if strings.ToLower(p.Match) != "regex" || p.Pattern == "" {
			continue
		}
		key := dataFlowPatternKey(p)
		if _, ok := compiled[key]; ok {
			continue
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			diagnostics = append(diagnostics, model.Diagnostic{Kind: "dataflow-patterns", Message: fmt.Sprintf("invalid regex pattern %q for %s %s: %v", p.Pattern, p.Target, p.Kind, err)})
			continue
		}
		compiled[key] = re
	}
	return compiled, diagnostics
}

func allDataFlowPatterns(set *model.DataFlowPatternSet) []model.DataFlowPattern {
	if set == nil {
		return nil
	}
	out := make([]model.DataFlowPattern, 0, len(set.Sources)+len(set.Sinks)+len(set.Passthroughs)+len(set.Sanitizers))
	out = append(out, set.Sources...)
	out = append(out, set.Sinks...)
	out = append(out, set.Passthroughs...)
	out = append(out, set.Sanitizers...)
	return out
}

func dataFlowPatternKey(p model.DataFlowPattern) string {
	return strings.Join([]string{p.Target, p.Kind, strings.ToLower(p.Match), p.Pattern}, "\x00")
}

func builtinDataFlowPatterns(packs []string) *model.DataFlowPatternSet {
	selected := map[string]bool{}
	if len(packs) == 0 {
		for _, p := range []string{"base", "http", "data", "filesystem", "process", "crypto", "native", "frameworks", "config", "cloud", "queue"} {
			selected[p] = true
		}
	} else {
		for _, p := range packs {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "all" {
				for _, name := range []string{"base", "http", "data", "filesystem", "process", "crypto", "native", "frameworks", "config", "cloud", "queue"} {
					selected[name] = true
				}
			} else if p != "" {
				selected[p] = true
			}
		}
	}
	set := &model.DataFlowPatternSet{Packs: sortedMapKeys(selected)}
	addSource := func(kind, pattern, category string, taints ...string) {
		set.Sources = append(set.Sources, dfPattern("source", kind, pattern, category, taints...))
	}
	addSink := func(kind, pattern, category string, taints ...string) {
		set.Sinks = append(set.Sinks, dfPattern("sink", kind, pattern, category, taints...))
	}
	// addSinkExact is for symbols that are complete on their own, where a
	// substring match would also catch every longer symbol they happen to be
	// a prefix of.
	addSinkExact := func(kind, pattern, category string, taints ...string) {
		p := dfPattern("sink", kind, pattern, category, taints...)
		p.Match = "exact"
		set.Sinks = append(set.Sinks, p)
	}
	addSinkArgs := func(kind, pattern, category string, args []int, taints ...string) {
		p := dfPattern("sink", kind, pattern, category, taints...)
		p.RelevantArguments = args
		set.Sinks = append(set.Sinks, p)
	}
	addWriter := func(kind, pattern, category string, writes []int) {
		p := dfPattern("passthrough", kind, pattern, category)
		p.WritesToArguments = writes
		set.Passthroughs = append(set.Passthroughs, p)
	}
	addPass := func(kind, pattern, category string) {
		set.Passthroughs = append(set.Passthroughs, dfPattern("passthrough", kind, pattern, category))
	}
	addSan := func(kind, pattern, category string, removes ...string) {
		p := dfPattern("sanitizer", kind, pattern, category)
		p.RemovesTaintKinds = removes
		set.Sanitizers = append(set.Sanitizers, p)
	}
	addCategorySan := func(kind, pattern, category string, sanitizes []string, removes ...string) {
		p := dfPattern("sanitizer", kind, pattern, category)
		p.RemovesTaintKinds = removes
		p.SanitizesCategories = sanitizes
		set.Sanitizers = append(set.Sanitizers, p)
	}
	if selected["base"] {
		addSource("symbol", "os.Args", "cli", "user-input")
		addSource("function", "os.Getenv", "environment", "environment", "secret")
		addSource("function", "os.LookupEnv", "environment", "environment", "secret")
		addSource("function", "flag.Arg", "cli", "user-input")
		addSource("function", "flag.Args", "cli", "user-input")
		paramPattern := dfPattern("source", "parameter", "^(input|query|command|cmd|path|file|filename|url|uri|token|key|secret|password)$", "parameter", "user-input")
		paramPattern.Match = "regex"
		set.Sources = append(set.Sources, paramPattern)
		addSource("type", "*net/http.Request", "http-input", "user-input")
		addSource("type", "http.Request", "http-input", "user-input")
		for _, name := range []string{"fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln", "strings.Join", "strings.Trim", "strings.TrimSpace", "strings.Replace", "strings.ReplaceAll", "bytes.(*Buffer).String", "strconv.Itoa", "strconv.Format", "net/url.QueryEscape", "net/url.PathEscape", "net/url.JoinPath", "regexp.(*Regexp).ReplaceAllString", "regexp.(*Regexp).ReplaceAllLiteralString", "regexp.(*Regexp).ReplaceAllStringFunc", "regexp.(*Regexp).FindString", "regexp.(*Regexp).FindStringSubmatch", "regexp.(*Regexp).FindAllString", "regexp.(*Regexp).FindAllStringSubmatch", "regexp.(*Regexp).Split", "reflect.ValueOf", "reflect.Value.Interface", "reflect.Value).Interface", "reflect.Value.String", "reflect.Value).String", "reflect.Value.Bytes", "reflect.Value).Bytes", "reflect.Value.Convert", "reflect.Value).Convert"} {
			addPass("function", name, "conversion")
		}
		for _, name := range []string{"log.Print", "log.Printf", "log.Println", "log.Fatal", "log.Fatalf", "log.Fatalln", "log.Panic", "log.Panicf", "log.Panicln", "log/slog.Debug", "log/slog.Info", "log/slog.Warn", "log/slog.Error", "go.uber.org/zap.(*Logger).Info", "go.uber.org/zap.(*Logger).Warn", "go.uber.org/zap.(*Logger).Error", "go.uber.org/zap.(*SugaredLogger).Info", "go.uber.org/zap.(*SugaredLogger).Infof", "go.uber.org/zap.(*SugaredLogger).Error", "fmt.Print", "fmt.Printf", "fmt.Println"} {
			addSink("function", name, "logging", "user-input", "secret")
		}
		// Values that pass through the standard library unchanged. Without these
		// taint stops at the first io, bufio, context or errors call, which in Go
		// is usually the first call of any consequence.
		for _, name := range []string{
			"strings.NewReader", "bytes.NewReader", "bytes.NewBufferString", "bufio.NewScanner", "bufio.NewReader",
			"io.ReadAll", "io.NopCloser", "errors.New", "errors.Unwrap", "errors.Join",
			"context.WithValue", "context.Value",
			"(*bufio.Scanner).Text", "(*bufio.Scanner).Bytes", "(*bufio.Reader).ReadString", "(*bufio.Reader).ReadBytes",
			"(*strings.Builder).String", "(*bytes.Buffer).String", "(*bytes.Buffer).Bytes",
			"(*strings.Reader).ReadString", "(*net/url.URL).String",
		} {
			addPass("function", name, "conversion")
		}
		// uuid joined the standard library in Go 1.27. Its generators are
		// crypto/rand-backed and are deliberately not insecure-random sources;
		// parsing and rendering are taint carriers, the same shape as the
		// json round-trip models. The methods are written in the notation
		// the SSA printer uses, receiver and all: normalizeSSASymbolNotation
		// rewrites source notation only for pointer receivers, so a value
		// receiver spelled "uuid.UUID.String" would match nothing.
		for _, name := range []string{
			"uuid.Parse", "uuid.MustParse",
			"(uuid.UUID).String",
			"(uuid.UUID).AppendText",
			"(uuid.UUID).MarshalText",
			"(*uuid.UUID).UnmarshalText",
		} {
			addPass("function", name, "conversion")
		}
		// An error's message carries whatever was wrapped into it. The symbol for
		// the interface method is bare, so match it exactly rather than loosely.
		errorMessage := dfPattern("passthrough", "function", "Error", "conversion")
		errorMessage.Match = "exact"
		set.Passthroughs = append(set.Passthroughs, errorMessage)

		// Calls that fill memory reached through an argument rather than
		// returning a value.
		addWriter("function", "io.Copy", "conversion", []int{0})
		addWriter("function", "io.CopyN", "conversion", []int{0})
		addWriter("function", "io.ReadFull", "conversion", []int{1})
		addWriter("function", "encoding/json.Unmarshal", "conversion", []int{1})
		addWriter("function", "encoding/json.NewDecoder", "conversion", []int{})
		addWriter("function", "(*encoding/json.Decoder).Decode", "conversion", []int{1})
		// encoding/json/v2 is the default JSON implementation from Go 1.27 on.
		addWriter("function", "encoding/json/v2.Unmarshal", "conversion", []int{1})
		addWriter("function", "encoding/json/v2.UnmarshalRead", "conversion", []int{1})
		addWriter("function", "encoding/json/v2.UnmarshalDecode", "conversion", []int{1})
		addWriter("function", "encoding/json/jsontext.NewDecoder", "conversion", []int{})
		addWriter("function", "gopkg.in/yaml.v3.Unmarshal", "conversion", []int{1})
		addWriter("function", "(*strings.Builder).WriteString", "conversion", []int{0})
		addWriter("function", "(*strings.Builder).Write", "conversion", []int{0})
		addWriter("function", "(*bytes.Buffer).WriteString", "conversion", []int{0})
		addWriter("function", "(*bytes.Buffer).Write", "conversion", []int{0})

		customPass := dfPattern("passthrough", "name", `(?i)(identity|passthrough|forward|wrap|unwrap)$`, "custom-helper")
		customPass.Match = "regex"
		set.Passthroughs = append(set.Passthroughs, customPass)
		customSan := dfPattern("sanitizer", "name", `(?i)(sanitize|escape|clean|normalize|canonicalize|redact|validate)([A-Z_].*)?$`, "custom-sanitizer")
		customSan.Match = "regex"
		customSan.SanitizesCategories = []string{"http-response", "formatted-output", "filesystem", "redirect", "data"}
		set.Sanitizers = append(set.Sanitizers, customSan)
	}
	if selected["http"] {
		for _, name := range []string{
			"FormValue", "PostFormValue", "Cookie", "Header.Get", "Header).Get", "Values.Get", "(*net/url.URL).Query", "ParseForm", "MultipartReader", "FormFile",
			"github.com/gin-gonic/gin.(*Context).Param", "github.com/gin-gonic/gin.(*Context).Query", "github.com/gin-gonic/gin.(*Context).DefaultQuery", "github.com/gin-gonic/gin.(*Context).PostForm", "github.com/gin-gonic/gin.(*Context).GetHeader", "github.com/gin-gonic/gin.(*Context).Cookie", "github.com/gin-gonic/gin.(*Context).Bind", "github.com/gin-gonic/gin.(*Context).BindJSON", "github.com/gin-gonic/gin.(*Context).ShouldBind", "github.com/gin-gonic/gin.(*Context).ShouldBindJSON", "github.com/gin-gonic/gin.(*Context).ShouldBindQuery",
			"github.com/labstack/echo/v4.Context.QueryParam", "github.com/labstack/echo/v4.Context.Param", "github.com/labstack/echo/v4.Context.FormValue", "github.com/labstack/echo/v4.Context.QueryParams", "github.com/labstack/echo/v4.Context.FormParams", "github.com/labstack/echo/v4.Context.Cookie", "github.com/labstack/echo/v4.Context.Bind",
			"github.com/gofiber/fiber/v2.(*Ctx).Params", "github.com/gofiber/fiber/v2.(*Ctx).Query", "github.com/gofiber/fiber/v2.(*Ctx).Get", "github.com/gofiber/fiber/v2.(*Ctx).FormValue", "github.com/gofiber/fiber/v2.(*Ctx).Body", "github.com/gofiber/fiber/v2.(*Ctx).BodyRaw", "github.com/gofiber/fiber/v2.(*Ctx).BodyParser", "github.com/gofiber/fiber/v2.(*Ctx).Cookies",
			"github.com/valyala/fasthttp.(*RequestCtx).FormValue", "github.com/valyala/fasthttp.(*RequestCtx).UserValue", "github.com/valyala/fasthttp.Args.Peek", "github.com/valyala/fasthttp.Args.Get", "github.com/valyala/fasthttp.RequestHeader.Peek", "github.com/valyala/fasthttp.RequestHeader.Cookie",
			"github.com/kataras/iris/v12.Context.URLParam", "github.com/kataras/iris/v12.Context.FormValue", "github.com/kataras/iris/v12.Context.GetHeader", "github.com/kataras/iris/v12.Context.ReadJSON", "github.com/kataras/iris/v12.Context.ReadBody",
			"github.com/beego/beego/v2/server/web.(*Controller).GetString", "github.com/beego/beego/v2/server/web.(*Controller).GetStrings", "github.com/beego/beego/v2/server/web.(*Controller).GetInt", "github.com/beego/beego/v2/server/web.(*Controller).GetBool", "github.com/beego/beego/v2/server/web.(*Controller).GetFloat", "github.com/beego/beego/v2/server/web.(*Controller).GetBody", "github.com/beego/beego/v2/server/web/context.(*Input).Param", "github.com/beego/beego/v2/server/web/context.(*Input).Header",
			"github.com/gobuffalo/buffalo.Context.Param", "github.com/gobuffalo/buffalo.Context.Params", "github.com/gobuffalo/buffalo.Context.Bind",
			"github.com/grpc-ecosystem/grpc-gateway/v2/runtime.AnnotateIncomingContext", "github.com/grpc-ecosystem/grpc-gateway/v2/runtime.HTTPPathPattern", "connectrpc.com/connect.(*Request).Header", "connectrpc.com/connect.AnyRequest.Header", "connectrpc.com/connect.AnyRequest.Spec", "connectrpc.com/connect.AnyRequest.Peer",
			"github.com/gorilla/mux.Vars", "github.com/go-chi/chi.URLParam", "github.com/go-chi/chi.URLParamFromCtx", "google.golang.org/grpc/metadata.FromIncomingContext", "google.golang.org/grpc.(*ServerStream).RecvMsg",
		} {
			addSource("function", name, "http-input", "user-input")
		}
		addSink("function", "net/http.ResponseWriter.Write", "http-response", "user-input")
		for _, name := range []string{"fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln"} {
			addSink("function", name, "formatted-output", "user-input")
		}
		addSinkArgs("function", "http.Error", "http-response", []int{1}, "user-input")
		addSink("function", "encoding/json.(*Encoder).Encode", "http-response", "user-input")
		addSinkArgs("function", "encoding/json/v2.MarshalWrite", "http-response", []int{1}, "user-input")
		addSinkArgs("function", "encoding/json/v2.MarshalEncode", "http-response", []int{1}, "user-input")
		addSink("function", "encoding/json/jsontext.(*Encoder).WriteValue", "http-response", "user-input")
		addSinkArgs("function", "http.Redirect", "redirect", []int{2}, "url")
		addSinkArgs("function", "net/http.RedirectHandler", "redirect", []int{0}, "url")
		addCategorySan("function", "net/url.QueryEscape", "url-encoding", []string{"redirect"}, "url")
		addCategorySan("function", "net/url.PathEscape", "url-encoding", []string{"redirect"}, "url")
		addCategorySan("function", "html/template.HTMLEscapeString", "html-escaping", []string{"http-response", "formatted-output"})
		addCategorySan("function", "html/template.HTMLEscaper", "html-escaping", []string{"http-response", "formatted-output"})
	}
	if selected["frameworks"] {
		for _, sourceType := range []string{"chi.Context", "mux.RouteMatch", "connectrpc.com/connect.AnyRequest", "*connectrpc.com/connect.Request"} {
			addSource("type", sourceType, "framework-context", "user-input")
		}
		for _, name := range []string{"github.com/99designs/gqlgen/graphql.GetOperationContext", "github.com/99designs/gqlgen/graphql.GetFieldContext"} {
			addSource("function", name, "framework-context", "user-input")
		}
		for _, name := range []string{"gin.Context.JSON", "gin.Context).JSON", "gin.Context.String", "gin.Context).String", "gin.Context.HTML", "gin.Context).HTML", "echo.Context.JSON", "echo.Context.String", "github.com/gofiber/fiber/v2.(*Ctx).JSON", "github.com/gofiber/fiber/v2.(*Ctx).Send", "github.com/gofiber/fiber/v2.(*Ctx).SendString", "github.com/valyala/fasthttp.RequestCtx.SetBody", "github.com/kataras/iris/v12.Context.JSON", "github.com/kataras/iris/v12.Context.HTML", "github.com/gobuffalo/buffalo.Context.Render"} {
			addSink("function", name, "http-response", "user-input")
		}
		for _, name := range []string{"gin.Context.Redirect", "gin.Context).Redirect", "echo.Context.Redirect", "github.com/gofiber/fiber/v2.(*Ctx).Redirect", "github.com/kataras/iris/v12.Context.Redirect", "github.com/beego/beego/v2/server/web.(*Controller).Redirect", "github.com/gobuffalo/buffalo.Context.Redirect"} {
			addSink("function", name, "redirect", "url")
		}
		for _, passthrough := range []string{"github.com/gin-gonic/gin.Context", "github.com/labstack/echo/v4", "github.com/gofiber/fiber/v2", "github.com/go-chi/chi", "github.com/gorilla/mux", "github.com/grpc-ecosystem/grpc-gateway/v2/runtime", "connectrpc.com/connect", "github.com/valyala/fasthttp", "github.com/kataras/iris/v12", "github.com/beego/beego/v2/server/web", "github.com/gobuffalo/buffalo", "github.com/99designs/gqlgen/graphql"} {
			addPass("function", passthrough, "framework")
		}
	}
	if selected["process"] {
		addSink("function", "os/exec.Command", "command-execution", "user-input")
		addSink("function", "os/exec.CommandContext", "command-execution", "user-input")
		addSink("function", "plugin.Open", "dynamic-loading", "user-input", "path")
		addPass("function", "plugin.Lookup", "dynamic-loading")
	}
	if selected["data"] {
		// Only the query string is a SQL-injection sink. The values that follow
		// it are bound parameters, which the driver sends out of band and which
		// are therefore safe by construction; treating them as sink arguments
		// reports every correctly parameterised query as an injection.
		//
		// Indices are SSA argument positions, and for a method call SSA passes
		// the receiver as argument zero — so the query string is at index one,
		// and at index two for the variants that take a context first.
		for _, name := range []string{"database/sql.(*DB).Query", "database/sql.(*DB).Exec", "database/sql.(*Tx).Query", "database/sql.(*Tx).Exec", "database/sql.(*Conn).Query", "database/sql.(*Conn).Exec"} {
			addSinkArgs("function", name, "data", []int{1}, "user-input")
		}
		// The Context variants take the context first, so the query is second.
		for _, name := range []string{"database/sql.(*DB).QueryContext", "database/sql.(*DB).ExecContext", "database/sql.(*Tx).QueryContext", "database/sql.(*Tx).ExecContext", "database/sql.(*Conn).QueryContext", "database/sql.(*Conn).ExecContext"} {
			addSinkArgs("function", name, "data", []int{2}, "user-input")
		}
		for _, name := range []string{"github.com/jmoiron/sqlx", "github.com/jmoiron/sqlx.Queryx", "github.com/jmoiron/sqlx.Select", "github.com/jmoiron/sqlx.Get", "github.com/jackc/pgx", "github.com/jackc/pgx.Query", "github.com/jackc/pgx.Exec", "gorm.io/gorm.(*DB).Raw", "gorm.io/gorm.(*DB).Exec", "gorm.io/gorm.(*DB).Where", "go.mongodb.org/mongo-driver/mongo", "github.com/redis/go-redis", "github.com/redis/go-redis/v9", "github.com/segmentio/kafka-go", "github.com/nats-io/nats.go", "encoding/gob.(*Decoder).Decode", "encoding/json.Unmarshal", "encoding/json/v2.Unmarshal", "encoding/json/v2.UnmarshalRead", "yaml.Unmarshal"} {
			addSink("function", name, "data", "user-input")
		}
		addCategorySan("function", "database/sql.(*Stmt).Exec", "sql-parameterization", []string{"data"}, "sql")
	}
	if selected["filesystem"] {
		for _, name := range []string{"os.Open", "os.OpenFile", "os.WriteFile", "os.ReadFile", "os.Create", "os.Mkdir", "os.MkdirAll", "os.Remove", "os.RemoveAll", "archive/zip", "archive/tar", "http.ServeFile"} {
			addSink("function", name, "filesystem", "path")
		}
		addPass("function", "path/filepath.Join", "path")
		addPass("function", "path.Join", "path")
		addCategorySan("function", "path/filepath.Base", "path-validation", []string{"filesystem"}, "path")
	}
	if selected["crypto"] {
		for _, name := range []string{"crypto/aes.NewCipher", "crypto/des.NewCipher", "crypto/hmac.New", "crypto/x509.ParsePKCS1PrivateKey", "crypto/x509.ParsePKCS8PrivateKey", "crypto/x509.ParseCertificate", "crypto/tls.LoadX509KeyPair", "golang.org/x/crypto/pbkdf2.Key", "golang.org/x/crypto/bcrypt.GenerateFromPassword", "golang.org/x/crypto/scrypt.Key", "github.com/golang-jwt/jwt", "github.com/golang-jwt/jwt/v4", "github.com/golang-jwt/jwt/v5", "github.com/dgrijalva/jwt-go", "golang.org/x/oauth2"} {
			addSink("function", name, "crypto", "secret", "crypto-key")
		}
		addSource("name", "(?i)(private.*key|secret|password|token|nonce|iv|salt)", "crypto-material", "secret", "crypto-key")
		addSan("function", "crypto/rand.Read", "secure-random", "insecure-random")
		// math/rand and math/rand/v2 draw from predictable sources. Both are
		// sources of the "insecure-random" taint kind the crypto/rand.Read
		// sanitizer above removes, so a token that passes through a secure
		// re-read is cleaned while a math/rand draw stays flagged.
		// Every drawing function of each package, and no others: Shuffle and
		// Seed return nothing, so a source model on them could never taint
		// anything. The two lists are the ones models/stdlib.json carries,
		// entry for entry — the vocabulary test compares them.
		randV1 := []string{"Int", "Int31", "Int31n", "Int63", "Int63n", "Intn", "Uint32", "Uint64", "Float32", "Float64", "NormFloat64", "ExpFloat64", "Perm", "Read"}
		randV2 := []string{"Int", "IntN", "Int32", "Int32N", "Int64", "Int64N", "Uint", "UintN", "Uint32", "Uint32N", "Uint64", "Uint64N", "N", "Float32", "Float64", "NormFloat64", "ExpFloat64", "Perm"}
		for _, fn := range randV1 {
			addSource("function", "math/rand."+fn, "insecure-random", "insecure-random")
			addSource("function", "math/rand.(*Rand)."+fn, "insecure-random", "insecure-random")
		}
		for _, fn := range randV2 {
			addSource("function", "math/rand/v2."+fn, "insecure-random", "insecure-random")
			addSource("function", "math/rand/v2.(*Rand)."+fn, "insecure-random", "insecure-random")
		}
	}
	if selected["native"] {
		addSink("function", "_Cfunc_", "native-interop", "native")
		addPass("function", "_Cfunc_CString", "native-conversion")
		addPass("function", "_Cfunc_GoString", "native-conversion")
		addPass("function", "_Cfunc_GoStringN", "native-conversion")
		addPass("function", "_Cfunc_GoBytes", "native-conversion")
		addSource("function", "_Cfunc_GoString", "native-conversion", "native")
		addSource("function", "_Cfunc_GoStringN", "native-conversion", "native")
		addSource("function", "_Cfunc_GoBytes", "native-conversion", "native")
		addPass("function", "_Cfunc_CBytes", "native-conversion")
		addPass("function", "_Cgo_ptr", "native-conversion")
		addSink("package", "unsafe", "unsafe", "native")
		for _, name := range []string{"unsafe.String", "unsafe.Slice", "reflect.Value.Call", "reflect.Value).Call", "reflect.Value.CallSlice", "reflect.Value).CallSlice"} {
			addSink("function", name, "unsafe", "native")
		}
		df := dfPattern("sink", "function", "syscall.", "syscall", "native")
		set.Sinks = append(set.Sinks, df)
	}
	if selected["config"] {
		for _, name := range []string{"github.com/spf13/cobra.Command", "github.com/spf13/cobra.(*Command).Flag", "github.com/spf13/cobra.(*Command).Flags", "github.com/spf13/pflag", "github.com/spf13/viper.Get", "github.com/spf13/viper.GetString", "github.com/spf13/viper.GetStringMap", "github.com/spf13/viper.GetStringSlice", "github.com/spf13/viper.GetBool", "github.com/spf13/viper.GetInt", "github.com/spf13/viper.GetDuration"} {
			addSource("function", name, "configuration", "user-input")
		}
	}
	if selected["cloud"] {
		for _, name := range []string{"github.com/aws/aws-sdk-go", "github.com/aws/aws-sdk-go-v2", "cloud.google.com/go", "google.golang.org/api", "github.com/Azure/azure-sdk-for-go"} {
			addSink("package", name, "external-service", "user-input", "secret")
		}
		// The standard library's client calls are matched exactly. Under a
		// substring match "net/http.Head" is a prefix of the symbol
		// "(net/http.Header).Get", so reading a request header counted as a
		// call out to an external service — a false positive on any handler
		// that reads a header.
		for _, name := range []string{"net/http.(*Client).Do", "net/http.(*Client).Get", "net/http.Get", "net/http.Head", "net/http.Post", "net/http.PostForm", "net/http.NewRequest", "net/http.NewRequestWithContext"} {
			addSinkExact("function", name, "external-service", "user-input", "secret")
		}
		for _, name := range []string{"google.golang.org/grpc.(*ClientConn).Invoke", "google.golang.org/grpc.(*ClientConn).NewStream", "google.golang.org/grpc.ClientStream.SendMsg", "google.golang.org/grpc.ClientStream.RecvMsg", "connectrpc.com/connect.Client.CallUnary", "cloud.google.com/go/storage.(*Client).Bucket", "cloud.google.com/go/pubsub.(*Topic).Publish", "github.com/aws/aws-sdk-go-v2/service/sqs.(*Client).SendMessage"} {
			addSink("function", name, "external-service", "user-input", "secret")
		}
	}
	if selected["queue"] {
		for _, name := range []string{"cloud.google.com/go/pubsub.(*Message).Data", "github.com/aws/aws-sdk-go-v2/service/sqs/types.Message.Body", "github.com/segmentio/kafka-go.Message.Value", "github.com/nats-io/nats.go.Msg.Data", "github.com/hibiken/asynq.Task.Payload"} {
			addSource("field", name, "queue-message", "user-input")
		}
		for _, name := range []string{"cloud.google.com/go/pubsub.(*Topic).Publish", "github.com/aws/aws-sdk-go-v2/service/sqs.(*Client).SendMessage", "github.com/segmentio/kafka-go.(*Writer).WriteMessages", "github.com/nats-io/nats.go.(*Conn).Publish", "github.com/hibiken/asynq.Client.Enqueue"} {
			addSink("function", name, "queue-send", "user-input", "secret")
		}
	}
	set.Sources = normalizePatterns("source", set.Sources)
	set.Sinks = normalizePatterns("sink", set.Sinks)
	set.Passthroughs = normalizePatterns("passthrough", set.Passthroughs)
	set.Sanitizers = normalizePatterns("sanitizer", set.Sanitizers)
	return set
}

func dfPattern(target, kind, pattern, category string, taints ...string) model.DataFlowPattern {
	return model.DataFlowPattern{Target: target, Kind: kind, Match: "contains", Pattern: pattern, Category: category, TaintKinds: taints, Confidence: "medium"}
}

// ssaReceiverNotation rewrites a pattern written in source notation into the
// notation the SSA printer uses for a method on a pointer receiver.
//
// A pattern reading "database/sql.(*DB).Query" can never match, because the
// symbol it is compared against reads "(*database/sql.DB).Query". The two
// notations differ in where the package qualifier sits, and because matching is
// a substring test the mismatch is silent: the entire database/sql sink family,
// and every third-party pattern written the same way, matches nothing at all.
var ssaReceiverNotation = regexp.MustCompile(`^(.*)\.\(\*([A-Za-z_][A-Za-z0-9_]*)\)\.(.+)$`)

// normalizeSSASymbolNotation converts source notation to SSA notation, leaving
// anything that does not look like a pointer-receiver method untouched.
func normalizeSSASymbolNotation(pattern string) string {
	groups := ssaReceiverNotation.FindStringSubmatch(pattern)
	if groups == nil {
		return pattern
	}
	pkg, typeName, method := groups[1], groups[2], groups[3]
	if pkg == "" {
		return pattern
	}
	return "(*" + pkg + "." + typeName + ")." + method
}

func normalizePatterns(target string, in []model.DataFlowPattern) []model.DataFlowPattern {
	out := make([]model.DataFlowPattern, 0, len(in))
	for _, p := range in {
		if p.Target == "" {
			p.Target = target
		}
		p.Target = strings.ToLower(p.Target)
		if p.Kind == "" {
			p.Kind = "function"
		}
		p.Kind = strings.ToLower(p.Kind)
		if p.Match == "" {
			p.Match = "contains"
		}
		p.Match = strings.ToLower(p.Match)
		if p.Confidence == "" {
			p.Confidence = "medium"
		}
		// Exact patterns need the rewrite as much as substring ones: an
		// unrewritten "net/http.(*Client).Get" matches no symbol at all.
		if (p.Match == "contains" || p.Match == "exact") && (p.Kind == "function" || p.Kind == "method" || p.Kind == "symbol") {
			p.Pattern = normalizeSSASymbolNotation(p.Pattern)
		}
		p = enrichDataFlowPatternDefaults(p)
		if p.Pattern != "" {
			out = append(out, p)
		}
	}
	return out
}

func enrichDataFlowPatternDefaults(p model.DataFlowPattern) model.DataFlowPattern {
	if p.Target == "sink" {
		if len(p.RelevantArguments) == 0 {
			switch p.Category {
			case "redirect":
				if strings.Contains(p.Pattern, "http.Redirect") {
					p.RelevantArguments = []int{2}
				}
			case "http-response":
				if strings.Contains(p.Pattern, "http.Error") {
					p.RelevantArguments = []int{1}
				}
			}
		}
		if p.RuleID == "" || p.RuleName == "" || p.Severity == "" || p.RiskScore == 0 {
			ruleID, ruleName, severity, score := dataFlowRuleForCategory(p.Category)
			p.RuleID = firstNonEmpty(p.RuleID, ruleID)
			p.RuleName = firstNonEmpty(p.RuleName, ruleName)
			p.Severity = firstNonEmpty(p.Severity, severity)
			if p.RiskScore == 0 {
				p.RiskScore = score
			}
		}
	}
	return p
}

func dataFlowRuleForCategory(category string) (id, name, severity string, score int) {
	switch strings.ToLower(category) {
	case "command-execution":
		return "GOLEM-DATAFLOW-COMMAND-INJECTION", "User input reaches process execution", "critical", 95
	case "data":
		return "GOLEM-DATAFLOW-DATA-QUERY", "User input reaches data query or deserialization API", "high", 80
	case "filesystem":
		return "GOLEM-DATAFLOW-PATH-TRAVERSAL", "User input reaches filesystem operation", "high", 80
	case "redirect":
		return "GOLEM-DATAFLOW-OPEN-REDIRECT", "User input reaches redirect target", "medium", 60
	case "http-response", "formatted-output":
		return "GOLEM-DATAFLOW-REFLECTED-OUTPUT", "User input reaches response/output", "medium", 55
	case "logging":
		return "GOLEM-DATAFLOW-LOG-INJECTION-OR-SECRET-LEAK", "User input or secret reaches logs", "medium", 55
	case "crypto":
		return "GOLEM-DATAFLOW-CRYPTO-MATERIAL", "Sensitive material reaches cryptographic API", "high", 75
	case "native-interop", "unsafe", "syscall":
		return "GOLEM-DATAFLOW-UNSAFE-NATIVE", "User input reaches unsafe/native boundary", "high", 85
	case "dynamic-loading":
		return "GOLEM-DATAFLOW-DYNAMIC-LOADING", "User input reaches dynamic loading", "high", 85
	case "panic":
		return "GOLEM-DATAFLOW-PANIC", "User input reaches panic", "medium", 50
	case "external-service":
		return "GOLEM-DATAFLOW-EXTERNAL-SERVICE", "User input or secret reaches external service SDK", "medium", 55
	default:
		return "GOLEM-DATAFLOW-GENERIC", "Source reaches sink", "medium", 50
	}
}

func (b *dataFlowBuilder) inferSummaries(funcs []*ssa.Function) {
	for _, fn := range funcs {
		b.summaries[fn] = &internalSummary{model: b.newSummary(fn), paramReturn: map[int]bool{}, paramSink: map[int]map[string]bool{}, fieldWrites: map[string]map[int]bool{}, returnFields: map[string]bool{}, paramReturnFields: map[int]map[string]bool{}}
	}
	for i := 0; i < 4; i++ {
		changed := false
		for _, fn := range funcs {
			if b.summarizeFunction(fn) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

func (b *dataFlowBuilder) newSummary(fn *ssa.Function) model.DataFlowMethodSummary {
	pkgPath := ""
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkgPath = fn.Pkg.Pkg.Path()
	}
	return model.DataFlowMethodSummary{FunctionID: fn.String(), Function: fn.String(), PackagePath: pkgPath, Confidence: "medium"}
}

func (b *dataFlowBuilder) summarizeFunction(fn *ssa.Function) bool {
	state := newDataFlowState()
	for i, p := range fn.Params {
		state.values[p] = dataFlowTrace{params: map[int]bool{i: true}}
	}
	var changed bool
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			switch x := instr.(type) {
			case *ssa.Store:
				if tr, ok := b.summaryTaintOf(state, x.Val); ok {
					state.setMemory(addrKey(x.Addr), x.Addr, tr)
					b.rememberAggregateStore(state, x.Addr, tr)
					changed = b.recordSummaryFieldWrite(fn, state, x.Addr, tr) || changed
				}
				if isParameterSpill(x) {
					state.spills[addrKey(x.Addr)] = true
				}
				b.copyAggregateTaint(state, x.Addr, x.Val)
			case *ssa.MapUpdate:
				if tr, ok := b.summaryTaintOf(state, x.Value); ok {
					state.setMemory(addrKey(x.Map)+"[*]", x.Map, tr)
				}
			case *ssa.Send:
				if tr, ok := b.summaryTaintOf(state, x.X); ok {
					state.chans[addrKey(x.Chan)] = tr
				}
			case *ssa.Select:
				b.processSummarySelect(state, x)
			case *ssa.Call:
				if tr, ok := b.summaryCallTaint(state, x.Common()); ok {
					state.values[x] = tr
				}
				changed = b.recordSummarySink(fn, x.Common(), state) || changed
			case *ssa.Panic:
				if tr, ok := b.summaryTaintOf(state, x.X); ok {
					for p := range tr.params {
						changed = b.addParamSink(fn, p, "panic") || changed
					}
				}
			case *ssa.Defer:
				changed = b.recordSummarySink(fn, x.Common(), state) || changed
			case *ssa.Go:
				changed = b.recordSummarySink(fn, x.Common(), state) || changed
			case *ssa.Return:
				for _, result := range x.Results {
					if tr, ok := b.summaryTaintOf(state, result); ok {
						if field, ok := summaryReceiverField(result); ok {
							changed = b.addReturnField(fn, field) || changed
						}
						for _, field := range tr.fieldPaths {
							if strings.HasPrefix(field, "field") {
								changed = b.addReturnField(fn, field) || changed
							}
						}
						for idx := range tr.params {
							changed = b.addParamReturn(fn, idx) || changed
							for _, field := range tr.fieldPaths {
								if strings.HasPrefix(field, "field") {
									changed = b.addParamReturnField(fn, idx, field) || changed
								}
							}
						}
						if tr.generated {
							for _, p := range tr.sourcePatterns {
								changed = b.addSourceReturn(fn, p) || changed
							}
						}
					}
				}
			default:
				if v, ok := instr.(ssa.Value); ok {
					if tr, ok := b.summaryValueTaint(state, v); ok {
						state.values[v] = tr
					}
				}
			}
		}
	}
	return changed
}

func newDataFlowState() dataFlowState {
	return dataFlowState{values: map[ssa.Value]dataFlowTrace{}, memory: map[string]dataFlowTrace{}, chans: map[string]dataFlowTrace{}, visiting: map[ssa.Value]bool{}, spills: map[string]bool{}, subKeys: map[string][]string{}}
}

// setMemory records tr at key, replacing whatever was there, and indexes key
// as a sub-location of base if it is one. base is the location the key was
// derived from — the address of the aggregate, not of the field — and may be
// nil for a key that names a whole location.
func (s dataFlowState) setMemory(key string, base ssa.Value, tr dataFlowTrace) {
	s.memory[key] = tr
	s.indexSubKey(key, base)
}

// mergeMemory combines tr into whatever key already holds. Same indexing as
// setMemory.
func (s dataFlowState) mergeMemory(key string, base ssa.Value, tr dataFlowTrace) {
	s.memory[key] = combineTraces(s.memory[key], tr)
	s.indexSubKey(key, base)
}

// indexSubKey records key under every location it is a sub-location of.
//
// It walks up from base through the field and index selections that produced
// it, because a key is a sub-location of each of its ancestors, not just its
// immediate parent: a whole-struct read of `a` has to see `a.field0.field1`
// as readily as `a.field0`.
func (s dataFlowState) indexSubKey(key string, base ssa.Value) {
	for v := base; v != nil; {
		if prefix := addrKey(v); isSubLocationKey(key, prefix) {
			s.addSubKey(prefix, key)
		}
		switch x := v.(type) {
		case *ssa.FieldAddr:
			v = x.X
		case *ssa.IndexAddr:
			v = x.X
		default:
			v = nil
		}
	}
}

func (s dataFlowState) addSubKey(base, key string) {
	keys := s.subKeys[base]
	at := sort.SearchStrings(keys, key)
	if at < len(keys) && keys[at] == key {
		return
	}
	keys = append(keys, "")
	copy(keys[at+1:], keys[at:])
	keys[at] = key
	s.subKeys[base] = keys
}

// isSubLocationKey reports whether key names a field or element of the
// location named by base, at any depth. A bare prefix match is not enough:
// two unrelated locations can share a prefix, so the character that follows
// has to be a selection.
func isSubLocationKey(key, base string) bool {
	if base == "" || len(key) <= len(base) || !strings.HasPrefix(key, base) {
		return false
	}
	switch key[len(base)] {
	case '.', '[':
		return true
	}
	return false
}

func newDataFlowBudget(max int) *dataFlowBudget {
	if max <= 0 {
		return &dataFlowBudget{}
	}
	return &dataFlowBudget{max: int64(max)}
}

func (b *dataFlowBudget) reserve() bool {
	if b == nil || b.max <= 0 {
		return true
	}
	for {
		used := b.used.Load()
		if used >= b.max {
			return false
		}
		if b.used.CompareAndSwap(used, used+1) {
			return true
		}
	}
}

func (b *dataFlowBudget) release() {
	if b == nil || b.max <= 0 {
		return
	}
	for {
		used := b.used.Load()
		if used <= 0 {
			return
		}
		if b.used.CompareAndSwap(used, used-1) {
			return
		}
	}
}

func (b *dataFlowBudget) exhausted() bool {
	return b != nil && b.max > 0 && b.used.Load() >= b.max
}

func (b *dataFlowBuilder) rememberAggregateStore(state dataFlowState, addr ssa.Value, tr dataFlowTrace) {
	switch a := addr.(type) {
	case *ssa.IndexAddr:
		state.setMemory(addrKey(a.X)+"[*]", a.X, tr.withFieldPath("[*]"))
	case *ssa.FieldAddr:
		state.setMemory(fieldMemoryKey(a.X, a.Field), a.X, tr.withFieldPath(fmt.Sprintf("field%d", a.Field)))
	}
}

// isAggregateType reports whether a value of this type is copied field by
// field, so field-qualified sub-locations have to be carried across a
// whole-value load or store.
func isAggregateType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Struct, *types.Array:
		return true
	}
	return false
}

// isParameterSpill reports whether a store is the copy SSA emits to give a
// by-value parameter an address: `*t0 = c`. Reading a field of a spilled
// parameter is the only context in which a whole-value trace may be widened to
// the aggregate's fields, because it is the parameter itself being read
// field by field, and the field name is recorded as a hop.
func isParameterSpill(store *ssa.Store) bool {
	if store == nil {
		return false
	}
	if _, ok := store.Addr.(*ssa.Alloc); !ok {
		return false
	}
	switch store.Val.(type) {
	case *ssa.Parameter, *ssa.FreeVar:
		return true
	}
	return false
}

// aggregateSourcePrefix names the key space a whole aggregate value's
// field-qualified sub-locations live under. A value loaded out of memory is a
// fresh SSA register whose own key holds nothing; its fields were recorded
// under the address it was loaded from.
func aggregateSourcePrefix(v ssa.Value) string {
	if op, ok := v.(*ssa.UnOp); ok && op.Op == token.MUL {
		return addrKey(op.X)
	}
	return addrKey(v)
}

// copyAggregateTaint moves the field-qualified sub-locations under srcPrefix
// to dstPrefix, keeping the field paths intact across a by-value aggregate
// copy (defect 34).
//
// `w := Wrapper{Cmd: taint}` compiles to a store into a scratch allocation, a
// load of the entire struct, and a store of that value into w. The whole-value
// trace alone does not survive the round trip, because a field read consults
// the field's own key first and the copy never wrote it. Moving the
// sub-locations makes a value-typed literal behave like the pointer-typed one.
func (b *dataFlowBuilder) copyAggregateTaint(state dataFlowState, dst, src ssa.Value) bool {
	// dst is the address receiving the copy, so only the stored value has to
	// be an aggregate; the destination's own type is a pointer to one.
	if src == nil || dst == nil || !isAggregateType(src.Type()) {
		return false
	}
	dstPrefix, srcPrefix := addrKey(dst), aggregateSourcePrefix(src)
	if dstPrefix == "" || srcPrefix == "" || dstPrefix == srcPrefix {
		return false
	}
	type move struct {
		key   string
		trace dataFlowTrace
	}
	var moves []move
	for _, key := range state.subKeys[srcPrefix] {
		if tr := state.memory[key]; !tr.empty() {
			moves = append(moves, move{dstPrefix + key[len(srcPrefix):], tr})
		}
	}
	for _, m := range moves {
		state.mergeMemory(m.key, dst, m.trace)
	}
	return len(moves) > 0
}

// aggregateLoadTaint gathers the field-qualified sub-locations recorded under
// base, for a load of the whole aggregate. Without it a whole-struct load
// returns only what the base key holds and drops every field-qualified store
// made through the address (defect 34).
func (b *dataFlowBuilder) aggregateLoadTaint(state dataFlowState, base ssa.Value) (dataFlowTrace, bool) {
	baseKey := addrKey(base)
	if baseKey == "" {
		return dataFlowTrace{}, false
	}
	var traces []dataFlowTrace
	for _, key := range state.subKeys[baseKey] {
		if tr := state.memory[key]; !tr.empty() {
			traces = append(traces, tr)
		}
	}
	return combineTraceList(traces)
}

type dataFlowFunctionResult struct {
	index        int
	functionName string
	evidence     *model.DataFlowEvidence
	instructions int
}

func (b *dataFlowBuilder) analyzeFunctions(funcs []*ssa.Function, workers int, progress *progressLogger) {
	if len(funcs) == 0 {
		return
	}
	if workers <= 1 {
		for i, fn := range funcs {
			b.analyzeFunction(fn)
			progress.MaybeLogf("data-flow analyzed %d/%d functions nodes=%d edges=%d slices=%d", i+1, len(funcs), len(b.out.Nodes), len(b.out.Edges), len(b.out.Slices))
		}
		return
	}
	jobs := make(chan int)
	results := make(chan dataFlowFunctionResult, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				fn := funcs[idx]
				localOut := &model.DataFlowEvidence{Mode: b.out.Mode, Patterns: b.patterns}
				local := &dataFlowBuilder{analyzer: b.analyzer, out: localOut, patterns: b.patterns, regexps: b.regexps, summaries: b.summaries, endpoints: b.endpoints, dynamicCallees: b.dynamicCallees, nodeSeen: map[string]bool{}, edgeSeen: map[string]bool{}, edgeByID: map[string]model.DataFlowEdge{}, sliceSeen: map[string]bool{}, diagnosticSeen: map[string]bool{}, sliceBudget: b.sliceBudget, maxSlices: b.maxSlices, maxTraceNodes: b.maxTraceNodes, maxTraceEdges: b.maxTraceEdges}
				local.analyzeFunction(fn)
				results <- dataFlowFunctionResult{index: idx, functionName: fn.String(), evidence: localOut, instructions: local.instructionCt}
			}
		}()
	}
	go func() {
		for i := range funcs {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	completed := 0
	nextMerge := 0
	pending := map[int]dataFlowFunctionResult{}
	for result := range results {
		completed++
		pending[result.index] = result
		for {
			ready, ok := pending[nextMerge]
			if !ok {
				break
			}
			delete(pending, nextMerge)
			b.instructionCt += ready.instructions
			b.mergeFunctionEvidence(ready.evidence)
			nextMerge++
		}
		progress.MaybeLogf("data-flow analyzed %d/%d functions latest=%s merged=%d nodes=%d edges=%d slices=%d", completed, len(funcs), result.functionName, nextMerge, len(b.out.Nodes), len(b.out.Edges), len(b.out.Slices))
	}
}

func (b *dataFlowBuilder) mergeFunctionEvidence(df *model.DataFlowEvidence) {
	if df == nil {
		return
	}
	for _, diag := range df.Diagnostics {
		b.addDiagnosticOnce(diag.Kind, diag.Message)
	}
	for _, node := range df.Nodes {
		if b.nodeSeen[node.ID] {
			continue
		}
		b.nodeSeen[node.ID] = true
		b.out.Nodes = append(b.out.Nodes, node)
	}
	for _, edge := range df.Edges {
		if b.edgeSeen[edge.ID] {
			continue
		}
		b.edgeSeen[edge.ID] = true
		b.edgeByID[edge.ID] = edge
		b.out.Edges = append(b.out.Edges, edge)
	}
	for _, slice := range df.Slices {
		if b.maxSlices > 0 && len(b.out.Slices) >= b.maxSlices {
			b.addDiagnosticOnce("dataflow-budget", fmt.Sprintf("data-flow slice limit reached at %d slices; additional slices were omitted", b.maxSlices))
			return
		}
		if b.sliceSeen[slice.ID] {
			continue
		}
		b.sliceSeen[slice.ID] = true
		b.out.Slices = append(b.out.Slices, slice)
	}
}

func (b *dataFlowBuilder) analyzeFunction(fn *ssa.Function) {
	state := newDataFlowState()
	for i, p := range fn.Params {
		for _, pat := range b.matchParameterSource(fn, i, p) {
			n := b.addNode("source", p.Name(), p.String(), p.Type().String(), fn, p.Pos(), true, false, pat.Category, pat.TaintKinds, "", pat.Confidence, nil)
			state.values[p] = combineTraces(state.values[p], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{pat}, taintKinds: taintsForPattern(pat), confidence: pat.Confidence})
		}
		for _, endpoint := range b.matchEndpointHandlerParam(fn, p) {
			pat := model.DataFlowPattern{Target: "source", Kind: "parameter", Match: "exact", Pattern: fn.String(), Category: "http-endpoint", TaintKinds: []string{"user-input"}, Confidence: "high"}
			n := b.addNode("source", p.Name(), p.String(), p.Type().String(), fn, p.Pos(), true, false, pat.Category, pat.TaintKinds, "", pat.Confidence, map[string]string{"endpointId": endpoint.ID, "endpointPath": endpoint.Path, "endpointMethod": endpoint.Method})
			state.values[p] = combineTraces(state.values[p], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{pat}, taintKinds: taintsForPattern(pat), confidence: pat.Confidence})
		}
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if b.sliceBudget.exhausted() {
				b.addDiagnosticOnce("dataflow-budget", fmt.Sprintf("data-flow slice limit reached at %d slices; additional slices were omitted", b.maxSlices))
				return
			}
			b.instructionCt++
			switch x := instr.(type) {
			case *ssa.Store:
				if tr, ok := b.taintOf(state, x.Val); ok {
					n := b.addNode("store", valueName(x.Addr), valueSymbol(x.Addr), valueType(x.Val), fn, x.Pos(), false, false, "", tr.taintKinds, strings.Join(tr.fieldPaths, "."), tr.confidence, nil)
					tr = b.connectTrace(tr, n, "store", x.Pos(), valueName(x.Addr))
					state.setMemory(addrKey(x.Addr), x.Addr, tr)
					b.rememberAggregateStore(state, x.Addr, tr)
				}
				if isParameterSpill(x) {
					state.spills[addrKey(x.Addr)] = true
				}
				b.copyAggregateTaint(state, x.Addr, x.Val)
			case *ssa.MapUpdate:
				if tr, ok := b.taintOf(state, x.Value); ok {
					n := b.addNode("map-store", valueName(x.Map), valueSymbol(x.Map), valueType(x.Value), fn, x.Pos(), false, false, "", tr.taintKinds, "[*]", tr.confidence, nil)
					tr = b.connectTrace(tr, n, "map-store", x.Pos(), valueName(x.Map))
					state.setMemory(addrKey(x.Map)+"[*]", x.Map, tr.withFieldPath("[*]"))
				}
			case *ssa.Send:
				if tr, ok := b.taintOf(state, x.X); ok {
					n := b.addNode("channel-send", valueName(x.Chan), valueSymbol(x.Chan), valueType(x.X), fn, x.Pos(), false, false, "", tr.taintKinds, "chan", tr.confidence, nil)
					state.chans[addrKey(x.Chan)] = b.connectTrace(tr, n, "channel-send", x.Pos(), valueName(x.Chan))
				}
			case *ssa.Select:
				if tr, ok := b.processSelect(fn, state, x); ok {
					state.values[x] = tr
				}
			case *ssa.Call:
				b.processCall(fn, state, x, x.Common())
			case *ssa.Panic:
				b.emitPanicSink(fn, state, x)
			case *ssa.Defer:
				b.processAsyncCall(fn, state, x.Common(), x.Pos(), "defer")
			case *ssa.Go:
				b.processAsyncCall(fn, state, x.Common(), x.Pos(), "go")
			default:
				if v, ok := instr.(ssa.Value); ok {
					for _, source := range b.matchFieldSource(v) {
						n := b.addNode("source", source.name, source.symbol, source.typ, fn, v.Pos(), true, false, source.pattern.Category, source.pattern.TaintKinds, source.fieldPath, source.pattern.Confidence, map[string]string{"pattern": source.pattern.Pattern})
						state.values[v] = combineTraces(state.values[v], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{source.pattern}, taintKinds: taintsForPattern(source.pattern), confidence: source.pattern.Confidence, fieldPaths: uniqueStrings([]string{source.fieldPath}), generated: true})
					}
					if tr, ok := b.valueTaint(state, v); ok {
						state.values[v] = combineTraces(state.values[v], tr)
					}
				}
			}
		}
	}
}

func (b *dataFlowBuilder) processCall(fn *ssa.Function, state dataFlowState, call ssa.Value, common *ssa.CallCommon) {
	for _, pat := range b.matchCall(common, b.patterns.Sinks) {
		b.emitSink(fn, state, call, common, pat)
	}
	// Propagation runs before source matching so that a value arriving already
	// tainted keeps the identity of where it actually came from.
	//
	// Some calls are modelled as both: C.GoString introduces taint when it
	// returns a buffer the C side produced, and carries taint when that buffer
	// began life as a Go string handed across by C.CString. Only one of the two
	// can be true of any given call, and attaching a fresh source to a value
	// that is already carrying one leaves an orphan node in the report — cited
	// by a slice, reachable by no edge.
	propagated := false
	if b.shouldPropagate(common) {
		if tr, ok := b.combineCallArgTaints(state, common); ok {
			n := b.addNode("call", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), false, false, "", tr.taintKinds, "", tr.confidence, nil)
			state.values[call] = combineTraces(state.values[call], b.connectTrace(tr, n, "call-return", call.Pos(), callName(common)))
			propagated = true
		}
	}
	for _, pat := range b.matchCall(common, b.patterns.Sources) {
		if propagated {
			continue
		}
		n := b.addNode("source", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), true, false, pat.Category, pat.TaintKinds, "", pat.Confidence, map[string]string{"pattern": pat.Pattern})
		state.values[call] = combineTraces(state.values[call], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{pat}, taintKinds: taintsForPattern(pat), confidence: pat.Confidence, generated: true})
	}
	if sanitized, ok := b.sanitizedCallTrace(fn, state, call, common); ok {
		if !sanitized.empty() {
			state.values[call] = combineTraces(state.values[call], sanitized)
		}
		return
	}
	if callee := common.StaticCallee(); callee != nil {
		b.replaySummary(fn, state, call, common, callee, "interprocedural")
	}
	if site, ok := call.(ssa.CallInstruction); ok {
		for _, callee := range b.dynamicCallees[site] {
			if common.StaticCallee() == callee {
				continue
			}
			b.replaySummary(fn, state, call, common, callee, "dynamic-summary")
		}
	}
	if common.Method != nil {
		for _, callee := range b.interfaceSummaryCallees(common) {
			b.replaySummary(fn, state, call, common, callee, "interface-summary")
		}
	}
	b.rememberResultFields(state, call)
	b.applyArgumentWrites(fn, state, common, call.Pos())
}

// rememberResultFields deposits an aggregate call result's taint at the fields
// it travelled through, so a caller that stores the result and reads one field
// (`out := b.Map(f); use(out.Value)`) still finds the flow. The result is
// returned by value and copied into a local, so whole-value taint alone does
// not survive to a field read; depositing at the named fields keeps the path
// precise instead of widening the result to every field.
func (b *dataFlowBuilder) rememberResultFields(state dataFlowState, call ssa.Value) {
	if call == nil || !isAggregateType(call.Type()) {
		return
	}
	tr, ok := state.values[call]
	if !ok || tr.empty() || len(tr.fieldPaths) == 0 {
		return
	}
	baseKey := addrKey(call)
	if baseKey == "" {
		return
	}
	for _, field := range tr.fieldPaths {
		if !strings.HasPrefix(field, "field") {
			continue
		}
		key := baseKey + "." + field
		state.mergeMemory(key, call, tr)
	}
}

// unwrapWriteTarget looks through the conversions a destination argument passes
// through on its way to an interface parameter.
//
// io.Copy takes an io.Writer and json.Unmarshal takes an any, so the pointer the
// caller supplied arrives wrapped in a MakeInterface. Keying memory off the
// wrapper rather than the allocation it wraps means the later read of that
// allocation never sees what was written into it.
func unwrapWriteTarget(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		case *ssa.Convert:
			v = x.X
		default:
			return v
		}
	}
}

// applyArgumentWrites records taint that a call deposits into memory reached
// through one of its arguments.
//
// Go's standard library moves a great deal of data this way rather than by
// returning it: io.Copy fills its destination, json.Unmarshal fills the value
// behind a pointer, and a strings.Builder accumulates into its receiver. A model
// that only understands return values loses the taint at each of these calls,
// and with it every flow that passes through one.
func (b *dataFlowBuilder) applyArgumentWrites(fn *ssa.Function, state dataFlowState, common *ssa.CallCommon, pos token.Pos) {
	patterns := b.matchCall(common, b.patterns.Passthroughs)
	if len(patterns) == 0 {
		return
	}
	args := callArgs(common)
	for _, pat := range patterns {
		if len(pat.WritesToArguments) == 0 {
			continue
		}
		incoming, ok := b.combineCallArgTaints(state, common)
		if !ok {
			continue
		}
		for _, idx := range pat.WritesToArguments {
			if idx < 0 || idx >= len(args) {
				continue
			}
			target := unwrapWriteTarget(args[idx])
			n := b.addNode("argument-write", valueName(target), callSymbol(common), valueType(target), fn, pos, false, false, "", incoming.taintKinds, "", incoming.confidence, map[string]string{"writesArgument": fmt.Sprint(idx)})
			written := b.connectTrace(incoming, n, "argument-write", pos, valueName(target))
			key := addrKey(target)
			state.mergeMemory(key, target, written)
			// A destination is usually a pointer to an aggregate, so record the
			// element and field views a later read will look through.
			state.mergeMemory(key+"[*]", target, written)
			if load, isLoad := target.(*ssa.UnOp); isLoad && load.Op == token.MUL {
				inner := addrKey(load.X)
				state.mergeMemory(inner, load.X, written)
			}
		}
	}
}

func (b *dataFlowBuilder) processSummarySelect(state dataFlowState, sel *ssa.Select) {
	if sel == nil {
		return
	}
	var receives []dataFlowTrace
	for _, st := range sel.States {
		if st.Chan == nil {
			continue
		}
		if st.Send != nil {
			if tr, ok := b.summaryTaintOf(state, st.Send); ok {
				state.chans[addrKey(st.Chan)] = tr
			}
			continue
		}
		if tr, ok := state.chans[addrKey(st.Chan)]; ok {
			receives = append(receives, tr)
		}
	}
	if tr, ok := combineTraceList(receives); ok {
		state.values[sel] = tr
	}
}

func (b *dataFlowBuilder) processSelect(fn *ssa.Function, state dataFlowState, sel *ssa.Select) (dataFlowTrace, bool) {
	if sel == nil {
		return dataFlowTrace{}, false
	}
	var receives []dataFlowTrace
	for _, st := range sel.States {
		if st.Chan == nil {
			continue
		}
		if st.Send != nil {
			if tr, ok := b.taintOf(state, st.Send); ok {
				n := b.addNode("select-send", valueName(st.Chan), valueSymbol(st.Chan), valueType(st.Send), fn, st.Pos, false, false, "", tr.taintKinds, "chan", tr.confidence, nil)
				state.chans[addrKey(st.Chan)] = b.connectTrace(tr, n, "select-send", st.Pos, valueName(st.Chan))
			}
			continue
		}
		if tr, ok := state.chans[addrKey(st.Chan)]; ok {
			n := b.addNode("select-receive", valueName(st.Chan), valueSymbol(st.Chan), valueType(st.Chan), fn, st.Pos, false, false, "", tr.taintKinds, "chan", tr.confidence, nil)
			receives = append(receives, b.connectTrace(tr, n, "select-receive", st.Pos, valueName(st.Chan)))
		}
	}
	return combineTraceList(receives)
}

func (b *dataFlowBuilder) emitPanicSink(fn *ssa.Function, state dataFlowState, p *ssa.Panic) {
	if p == nil || p.X == nil {
		return
	}
	if tr, ok := b.taintOf(state, p.X); ok && traceAllowsSink(tr, "panic") {
		pat := enrichDataFlowPatternDefaults(model.DataFlowPattern{Target: "sink", Kind: "builtin", Match: "exact", Pattern: "panic", Category: "panic", TaintKinds: []string{"user-input", "secret"}, Confidence: "medium"})
		b.emitSliceSink(fn, tr, p.Pos(), "panic", "panic", valueType(p.X), pat, 0, "Taint reaches panic")
	}
}

func (b *dataFlowBuilder) sanitizedCallTrace(fn *ssa.Function, state dataFlowState, call ssa.Value, common *ssa.CallCommon) (dataFlowTrace, bool) {
	patterns := b.matchCall(common, b.patterns.Sanitizers)
	if len(patterns) == 0 {
		return dataFlowTrace{}, false
	}
	tr, ok := b.combineCallArgTaints(state, common)
	if !ok {
		return dataFlowTrace{}, true
	}
	removed := map[string]bool{}
	fullStop := false
	for _, pat := range patterns {
		if len(pat.RemovesTaintKinds) == 0 && len(pat.SanitizesCategories) == 0 {
			fullStop = true
		}
		for _, kind := range pat.RemovesTaintKinds {
			removed[strings.ToLower(kind)] = true
		}
	}
	if fullStop {
		return dataFlowTrace{}, true
	}
	tr.sanitizedCategories = uniqueStrings(append(tr.sanitizedCategories, sanitizerCategories(patterns)...))
	var kept []string
	for _, kind := range tr.taintKinds {
		if !removed[strings.ToLower(kind)] {
			kept = append(kept, kind)
		}
	}
	if len(kept) == 0 {
		return dataFlowTrace{}, true
	}
	n := b.addNode("sanitizer", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), false, false, firstNonEmpty(patterns[0].Category, "sanitizer"), kept, "", tr.confidence, map[string]string{"removedTaintKinds": strings.Join(sortedMapKeys(removed), ","), "sanitizesCategories": strings.Join(tr.sanitizedCategories, ",")})
	tr.taintKinds = uniqueStrings(kept)
	return b.connectTrace(tr, n, "sanitizer", call.Pos(), callName(common)), true
}

func (b *dataFlowBuilder) interfaceSummaryCallees(common *ssa.CallCommon) []*ssa.Function {
	if common == nil || common.Method == nil {
		return nil
	}
	var out []*ssa.Function
	seen := map[*ssa.Function]bool{}
	for callee, summary := range b.summaries {
		if callee == nil || seen[callee] || callee.Name() != common.Method.Name() || !interfaceSummaryCompatible(common, callee) {
			continue
		}
		if len(summary.paramReturn) == 0 && len(summary.paramSink) == 0 && len(summary.sourceReturns) == 0 {
			continue
		}
		out = append(out, callee)
		seen[callee] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (b *dataFlowBuilder) replaySummary(fn *ssa.Function, state dataFlowState, call ssa.Value, common *ssa.CallCommon, callee *ssa.Function, edgeKind string) {
	summary := b.summaries[callee]
	if summary == nil {
		return
	}
	for _, pat := range summary.sourceReturns {
		n := b.addNode("source", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), true, false, pat.Category, pat.TaintKinds, "", pat.Confidence, map[string]string{"summaryFunction": callee.String(), "summaryKind": edgeKind})
		state.values[call] = combineTraces(state.values[call], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{pat}, taintKinds: taintsForPattern(pat), confidence: pat.Confidence, generated: true})
	}
	for idx := range summary.paramReturn {
		if arg, ok := summaryCallArgument(common, callee, idx); ok {
			tr, ok := b.summaryReturnTrace(state, arg, idx, summary)
			if ok {
				n := b.addNode("call-summary", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), false, false, "", tr.taintKinds, "", tr.confidence, map[string]string{"summaryFunction": callee.String(), "parameterIndex": fmt.Sprint(idx), "summaryKind": edgeKind})
				state.values[call] = combineTraces(state.values[call], b.connectTrace(tr, n, edgeKind+"-return", call.Pos(), fmt.Sprint(idx)))
			}
		}
	}
	for idx, cats := range summary.paramSink {
		if arg, ok := summaryCallArgument(common, callee, idx); ok {
			if tr, ok := b.taintOf(state, arg); ok {
				for cat := range cats {
					if !traceAllowsSink(tr, cat) {
						continue
					}
					pat := enrichDataFlowPatternDefaults(model.DataFlowPattern{Target: "sink", Kind: "function", Match: "exact", Pattern: callee.String(), Category: cat, Confidence: "medium"})
					b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, idx, fmt.Sprintf("Taint reaches %s sink in %s", edgeKind, callee.String()))
				}
			}
		}
	}
	recv, hasRecv := summaryCallArgument(common, callee, 0)
	for field, params := range summary.fieldWrites {
		if !hasRecv {
			continue
		}
		var traces []dataFlowTrace
		for idx := range params {
			arg, ok := summaryCallArgument(common, callee, idx)
			if !ok {
				continue
			}
			if tr, ok := b.taintOf(state, arg); ok {
				traces = append(traces, tr)
			}
		}
		if tr, ok := combineTraceList(traces); ok {
			n := b.addNode("call-summary", callName(common), callSymbol(common), valueType(recv), fn, call.Pos(), false, false, "", tr.taintKinds, field, tr.confidence, map[string]string{"summaryFunction": callee.String(), "summaryKind": edgeKind, "receiverField": field})
			fieldTrace := b.connectTrace(tr, n, edgeKind+"-field", call.Pos(), field).withFieldPath(field)
			state.setMemory(addrKey(recv)+"."+field, recv, fieldTrace)
		}
	}
}

func interfaceSummaryCompatible(common *ssa.CallCommon, callee *ssa.Function) bool {
	if common == nil || common.Signature() == nil || callee == nil || callee.Signature == nil {
		return false
	}
	callSig := common.Signature()
	calleeSig := callee.Signature
	callParams := callSig.Params()
	calleeParams := calleeSig.Params()
	calleeOffset := 0
	if calleeSig.Recv() != nil {
		calleeOffset = 1
	}
	if callParams.Len() != calleeParams.Len()-calleeOffset || callSig.Results().Len() != calleeSig.Results().Len() {
		return false
	}
	for i := 0; i < callParams.Len(); i++ {
		if callParams.At(i).Type().String() != calleeParams.At(i+calleeOffset).Type().String() {
			return false
		}
	}
	for i := 0; i < callSig.Results().Len(); i++ {
		if callSig.Results().At(i).Type().String() != calleeSig.Results().At(i).Type().String() {
			return false
		}
	}
	return true
}

func summaryCallArgument(common *ssa.CallCommon, callee *ssa.Function, paramIndex int) (ssa.Value, bool) {
	if common == nil || callee == nil || paramIndex < 0 {
		return nil, false
	}
	args := callArgs(common)
	hasReceiver := callee.Signature != nil && callee.Signature.Recv() != nil
	if hasReceiver {
		if paramIndex == 0 {
			if recv := receiverValue(common); recv != nil {
				return recv, true
			}
			if !common.IsInvoke() && len(args) > 0 {
				return args[0], true
			}
			if common.Value != nil && !common.IsInvoke() {
				return common.Value, true
			}
			return nil, false
		}
		argIndex := paramIndex - 1
		if !common.IsInvoke() {
			argIndex = paramIndex
		}
		if argIndex >= 0 && argIndex < len(args) {
			return args[argIndex], true
		}
		return nil, false
	}
	if paramIndex < len(args) {
		return args[paramIndex], true
	}
	return nil, false
}

func (b *dataFlowBuilder) processAsyncCall(fn *ssa.Function, state dataFlowState, common *ssa.CallCommon, pos token.Pos, kind string) {
	for _, pat := range b.matchCall(common, b.patterns.Sinks) {
		args := callArgs(common)
		for idx, arg := range args {
			if !sinkArgumentRelevant(common, pat, idx) {
				continue
			}
			if tr, ok := b.taintOf(state, arg); ok && traceAllowsSink(tr, firstNonEmpty(pat.Category, "sink")) {
				b.emitSliceSink(fn, tr, pos, callName(common), callSymbol(common), "", pat, idx, "Taint reaches asynchronous "+kind+" sink")
			}
		}
	}
}

func (b *dataFlowBuilder) emitSink(fn *ssa.Function, state dataFlowState, call ssa.Value, common *ssa.CallCommon, pat model.DataFlowPattern) {
	args := callArgs(common)
	for idx, arg := range args {
		if !sinkArgumentRelevant(common, pat, idx) {
			continue
		}
		if tr, ok := b.taintOf(state, arg); ok && traceAllowsSink(tr, firstNonEmpty(pat.Category, "sink")) {
			b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, idx, "Taint reaches "+firstNonEmpty(pat.Category, "sink"))
		}
	}
	if recv := receiverValue(common); recv != nil {
		if sinkReceiverRelevant(pat) {
			if tr, ok := b.taintOf(state, recv); ok && traceAllowsSink(tr, firstNonEmpty(pat.Category, "sink")) {
				b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, -1, "Taint reaches sink receiver")
			}
		}
	}
}

func sinkArgumentRelevant(common *ssa.CallCommon, pat model.DataFlowPattern, idx int) bool {
	if len(pat.RelevantArguments) > 0 {
		for _, relevant := range pat.RelevantArguments {
			if relevant == idx {
				return true
			}
		}
		return false
	}
	category := strings.ToLower(firstNonEmpty(pat.Category, "sink"))
	symbol := callSymbol(common)
	switch category {
	case "redirect":
		if strings.Contains(symbol, "net/http.Redirect") || strings.Contains(symbol, "http.Redirect") {
			return idx == 2
		}
	case "http-response":
		if strings.Contains(symbol, "http.Error") {
			return idx == 1
		}
	}
	return true
}

func sinkReceiverRelevant(pat model.DataFlowPattern) bool {
	if pat.ReceiverRelevant {
		return true
	}
	return len(pat.RelevantArguments) == 0
}

func (b *dataFlowBuilder) emitSliceSink(fn *ssa.Function, tr dataFlowTrace, pos token.Pos, name, symbol, typ string, pat model.DataFlowPattern, argIndex int, summary string) {
	idx := argIndex
	sourceID := firstNonEmpty(tr.sourceID, firstString(tr.nodeIDs))
	if sourceID == "" {
		return
	}
	if !b.sliceBudget.reserve() {
		b.addDiagnosticOnce("dataflow-budget", fmt.Sprintf("data-flow slice limit reached at %d slices; additional slices were omitted", b.maxSlices))
		return
	}
	props := map[string]string{"pattern": pat.Pattern}
	if pat.RuleID != "" {
		props["ruleId"] = pat.RuleID
	}
	if pat.Severity != "" {
		props["severity"] = pat.Severity
	}
	sink := b.addNode("sink", name, symbol, typ, fn, pos, false, true, pat.Category, mergeStrings(tr.taintKinds, taintsForPattern(pat)), "", firstNonEmpty(pat.Confidence, tr.confidence), props)
	tr = b.connectTrace(tr, sink, "sink", pos, fmt.Sprint(argIndex))
	id := stableID("df-slice", sourceID, sink.ID, strings.Join(tr.edgeIDs, ":"), fmt.Sprint(argIndex))
	if b.sliceSeen[id] {
		b.sliceBudget.release()
		return
	}
	b.sliceSeen[id] = true
	sinkPURL := firstNonEmpty(pat.PURL, sink.PURL)
	// A slice must be able to stand on its own: a consumer walks its edges to
	// draw the path, so every node an edge touches has to be listed, whatever
	// the trace happened to record.
	nodeIDs := append(append([]string{}, tr.nodeIDs...), sink.ID)
	for _, edgeID := range tr.edgeIDs {
		if edge, ok := b.edgeByID[edgeID]; ok {
			nodeIDs = append(nodeIDs, edge.SourceID, edge.TargetID)
		}
	}
	b.out.Slices = append(b.out.Slices, model.DataFlowSlice{ID: id, SourceID: sourceID, SinkID: sink.ID, NodeIDs: orderedUniqueStrings(nodeIDs), EdgeIDs: orderedUniqueStrings(tr.edgeIDs), SourceCategory: tr.sourceCategory, SinkCategory: pat.Category, SourcePURL: tr.sourcePURL, SinkPURL: sinkPURL, PURLs: orderedUniqueStrings([]string{tr.sourcePURL, sinkPURL}), SinkArgumentIndex: &idx, TaintKinds: uniqueStrings(mergeStrings(tr.taintKinds, taintsForPattern(pat))), FieldPaths: uniqueStrings(tr.fieldPaths), RuleID: pat.RuleID, RuleName: pat.RuleName, Severity: pat.Severity, RiskScore: pat.RiskScore, Confidence: firstNonEmpty(pat.Confidence, tr.confidence, "medium"), Description: summary})
}

func (b *dataFlowBuilder) addNode(kind, name, symbol, typ string, fn *ssa.Function, pos token.Pos, source, sink bool, category string, taints []string, fieldPath, confidence string, props map[string]string) model.DataFlowNode {
	position := b.analyzer.position(pos)
	fnID := ""
	fnName := ""
	pkgPath := ""
	var mod *model.Module
	purl := ""
	if fn != nil {
		fnID = fn.String()
		fnName = fn.String()
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			pkgPath = fn.Pkg.Pkg.Path()
			mod = b.analyzer.moduleForPackagePath(pkgPath)
			purl = packagePURL(pkgPath, mod)
		}
	}
	id := stableID("df-node", kind, fnID, symbol, name, position.Filename, fmt.Sprint(position.Line), fmt.Sprint(position.Column), category)
	node := model.DataFlowNode{ID: id, Kind: kind, Name: name, Symbol: symbol, Type: typ, PackagePath: pkgPath, Module: mod, PURL: purl, FunctionID: fnID, Function: fnName, Position: position, Source: source, Sink: sink, Category: category, TaintKinds: uniqueStrings(taints), FieldPath: fieldPath, Confidence: firstNonEmpty(confidence, "medium"), Properties: props}
	if !b.nodeSeen[id] {
		b.nodeSeen[id] = true
		b.out.Nodes = append(b.out.Nodes, node)
	}
	return node
}

func (b *dataFlowBuilder) connectTrace(tr dataFlowTrace, node model.DataFlowNode, kind string, pos token.Pos, label string) dataFlowTrace {
	if len(tr.nodeIDs) == 0 {
		tr.nodeIDs = append(tr.nodeIDs, node.ID)
		tr.tailID = node.ID
		return tr
	}
	previousID := tr.tailID
	if previousID == "" {
		previousID = tr.nodeIDs[len(tr.nodeIDs)-1]
	}
	id := stableID("df-edge", previousID, node.ID, kind, label, fmt.Sprint(b.analyzer.position(pos).Line))
	if !b.edgeSeen[id] {
		b.edgeSeen[id] = true
		edge := model.DataFlowEdge{ID: id, SourceID: previousID, TargetID: node.ID, Kind: kind, Label: label, Position: b.analyzer.position(pos)}
		b.edgeByID[id] = edge
		b.out.Edges = append(b.out.Edges, edge)
	}
	tr.edgeIDs = appendLimitedUnique(tr.edgeIDs, id, b.maxTraceEdges)
	tr.nodeIDs = appendLimitedUnique(tr.nodeIDs, node.ID, b.maxTraceNodes)
	tr.tailID = node.ID
	return tr
}

func (b *dataFlowBuilder) taintOf(state dataFlowState, v ssa.Value) (dataFlowTrace, bool) {
	if v == nil {
		return dataFlowTrace{}, false
	}
	if state.visiting[v] {
		return dataFlowTrace{}, false
	}
	if tr, ok := state.values[v]; ok && !tr.empty() {
		return tr, true
	}
	if tr, ok := state.memory[addrKey(v)]; ok && !tr.empty() {
		return tr, true
	}
	state.visiting[v] = true
	defer delete(state.visiting, v)
	return b.valueTaint(state, v)
}

func (b *dataFlowBuilder) valueTaint(state dataFlowState, v ssa.Value) (dataFlowTrace, bool) {
	switch x := v.(type) {
	case *ssa.UnOp:
		if x.Op == token.MUL {
			if tr, ok := state.memory[addrKey(x.X)]; ok {
				return tr, true
			}
			// Loading a whole aggregate out of memory: the field-qualified
			// taint lives under sub-locations of the address, not on the
			// base key, and has to be gathered explicitly for the store
			// that follows to find it (defect 34).
			if isAggregateType(x.Type()) {
				if tr, ok := b.aggregateLoadTaint(state, x.X); ok {
					return tr, true
				}
			}
		}
		if x.Op == token.ARROW {
			if tr, ok := state.chans[addrKey(x.X)]; ok {
				return tr, true
			}
		}
		return b.taintOf(state, x.X)
	case *ssa.FieldAddr:
		fieldPath := fmt.Sprintf("field%d", x.Field)
		if tr, ok := state.memory[addrKey(x)]; ok {
			return tr.withFieldPath(fieldPath), true
		}
		if tr, ok := state.memory[fieldMemoryKey(x.X, x.Field)]; ok {
			return tr.withFieldPath(fieldPath), true
		}
		// The element view a whole-destination write sets (io.Copy, the
		// json.Unmarshal family): a field of a struct that was filled
		// through a pointer must pick up that write, or every flow crossing
		// one of those calls dies between the write and the field read.
		if tr, ok := state.memory[addrKey(x.X)+"[*]"]; ok {
			return tr.withFieldPath(fieldPath), true
		}
		// A field of a spilled by-value parameter (which for a method
		// includes the receiver). The parameter's trace is whole-value, so
		// the field name is recorded as a hop: that is what lets this
		// function's summary say "parameter N flows out through field F"
		// and the call site answer with only that field.
		if state.spills[addrKey(x.X)] {
			if tr, ok := state.memory[addrKey(x.X)]; ok {
				return tr.withFieldPath(fieldPath), true
			}
		}
		// A field read on a value that itself carries taint — a parameter
		// with a source label (r.URL on the *http.Request parameter), a
		// call result. The base *location's* whole-value trace is
		// deliberately not consulted: widening every field read to the
		// aggregate's taint is how a tainted field leaks onto its clean
		// siblings (defect 34's negative half).
		if tr, ok := state.values[x.X]; ok && !tr.empty() {
			return tr.withFieldPath(fieldPath), true
		}
		return dataFlowTrace{}, false
	case *ssa.IndexAddr:
		if tr, ok := state.memory[addrKey(x)]; ok {
			return tr.withFieldPath("[*]"), true
		}
		return b.taintOf(state, x.X)
	case *ssa.Lookup:
		if tr, ok := state.memory[addrKey(x.X)+"[*]"]; ok {
			return tr.withFieldPath("[*]"), true
		}
	case *ssa.Field:
		if tr, ok := state.memory[fieldMemoryKey(x.X, x.Field)]; ok {
			return tr.withFieldPath(fmt.Sprintf("field%d", x.Field)), true
		}
		if tr, ok := b.taintOf(state, x.X); ok {
			return tr.withFieldPath(fmt.Sprintf("field%d", x.Field)), true
		}
		return dataFlowTrace{}, false
	case *ssa.Index:
		if tr, ok := state.memory[addrKey(x.X)+"[*]"]; ok {
			return tr.withFieldPath("[*]"), true
		}
		return b.taintOf(state, x.X)
	case *ssa.Extract:
		return b.taintOf(state, x.Tuple)
	case *ssa.Phi:
		var traces []dataFlowTrace
		for _, e := range x.Edges {
			if tr, ok := b.taintOf(state, e); ok {
				traces = append(traces, tr)
			}
		}
		return combineTraceList(traces)
	case *ssa.BinOp:
		left, lok := b.taintOf(state, x.X)
		right, rok := b.taintOf(state, x.Y)
		if lok && rok {
			return combineTraces(left, right), true
		}
		if lok {
			return left, true
		}
		return right, rok
	case *ssa.Convert:
		return b.taintOf(state, x.X)
	case *ssa.ChangeType:
		return b.taintOf(state, x.X)
	case *ssa.ChangeInterface:
		return b.taintOf(state, x.X)
	case *ssa.MakeInterface:
		return b.taintOf(state, x.X)
	case *ssa.TypeAssert:
		return b.taintOf(state, x.X)
	case *ssa.Slice:
		if tr, ok := state.memory[addrKey(x.X)+"[*]"]; ok {
			return tr.withFieldPath("[*]"), true
		}
		return b.taintOf(state, x.X)
	case *ssa.MakeClosure:
		var traces []dataFlowTrace
		for _, binding := range x.Bindings {
			if tr, ok := b.taintOf(state, binding); ok {
				traces = append(traces, tr)
			}
		}
		return combineTraceList(traces)
	case *ssa.Const:
		if x.Value != nil && x.Value.Kind() == constant.String {
			for _, pat := range b.matchValueSource(x) {
				return dataFlowTrace{generated: true, taintKinds: taintsForPattern(pat), confidence: pat.Confidence}, true
			}
		}
	}
	return dataFlowTrace{}, false
}

func (b *dataFlowBuilder) summaryTaintOf(state dataFlowState, v ssa.Value) (dataFlowTrace, bool) {
	return b.taintOf(state, v)
}
func (b *dataFlowBuilder) summaryValueTaint(state dataFlowState, v ssa.Value) (dataFlowTrace, bool) {
	return b.valueTaint(state, v)
}

func (b *dataFlowBuilder) summaryCallTaint(state dataFlowState, common *ssa.CallCommon) (dataFlowTrace, bool) {
	if len(b.matchCall(common, b.patterns.Sanitizers)) > 0 {
		return dataFlowTrace{}, false
	}
	if len(b.matchCall(common, b.patterns.Sources)) > 0 {
		return dataFlowTrace{generated: true, sourcePatterns: b.matchCall(common, b.patterns.Sources)}, true
	}
	if callee := common.StaticCallee(); callee != nil {
		if summary := b.summaries[callee]; summary != nil {
			var traces []dataFlowTrace
			for idx := range summary.paramReturn {
				if arg, ok := summaryCallArgument(common, callee, idx); ok {
					if tr, ok := b.taintOf(state, arg); ok {
						traces = append(traces, tr)
					}
				}
			}
			if len(summary.sourceReturns) > 0 {
				traces = append(traces, dataFlowTrace{generated: true, sourcePatterns: summary.sourceReturns})
			}
			return combineTraceList(traces)
		}
	}
	if b.shouldPropagate(common) {
		return b.combineCallArgTaints(state, common)
	}
	return dataFlowTrace{}, false
}

func (b *dataFlowBuilder) recordSummarySink(fn *ssa.Function, common *ssa.CallCommon, state dataFlowState) bool {
	changed := false
	for _, pat := range b.matchCall(common, b.patterns.Sinks) {
		for idx, arg := range callArgs(common) {
			if tr, ok := b.taintOf(state, arg); ok && traceAllowsSink(tr, firstNonEmpty(pat.Category, "sink")) {
				for p := range tr.params {
					changed = b.addParamSink(fn, p, firstNonEmpty(pat.Category, "sink")) || changed
				}
			}
			_ = idx
		}
	}
	if callee := common.StaticCallee(); callee != nil {
		if summary := b.summaries[callee]; summary != nil {
			for paramIdx, cats := range summary.paramSink {
				if arg, ok := summaryCallArgument(common, callee, paramIdx); ok {
					if tr, ok := b.taintOf(state, arg); ok {
						for callerParam := range tr.params {
							for cat := range cats {
								if !traceAllowsSink(tr, cat) {
									continue
								}
								changed = b.addParamSink(fn, callerParam, cat) || changed
							}
						}
					}
				}
			}
		}
	}
	return changed
}

func (b *dataFlowBuilder) addParamReturn(fn *ssa.Function, idx int) bool {
	s := b.summaries[fn]
	if s.paramReturn[idx] {
		return false
	}
	s.paramReturn[idx] = true
	if fn != nil && fn.Signature != nil && fn.Signature.Recv() != nil && idx == 0 {
		s.model.ReceiverToReturn = true
	}
	s.model.ParamToReturn = append(s.model.ParamToReturn, model.DataFlowSummaryFlow{ParameterIndex: idx})
	sort.Slice(s.model.ParamToReturn, func(i, j int) bool {
		return s.model.ParamToReturn[i].ParameterIndex < s.model.ParamToReturn[j].ParameterIndex
	})
	return true
}

func (b *dataFlowBuilder) addParamReturnField(fn *ssa.Function, idx int, field string) bool {
	s := b.summaries[fn]
	if s == nil {
		return false
	}
	if s.paramReturnFields[idx] == nil {
		s.paramReturnFields[idx] = map[string]bool{}
	}
	if s.paramReturnFields[idx][field] {
		return false
	}
	s.paramReturnFields[idx][field] = true
	return true
}

func (b *dataFlowBuilder) addParamSink(fn *ssa.Function, idx int, cat string) bool {
	s := b.summaries[fn]
	if s.paramSink[idx] == nil {
		s.paramSink[idx] = map[string]bool{}
	}
	if s.paramSink[idx][cat] {
		return false
	}
	s.paramSink[idx][cat] = true
	s.model.ParamToSink = append(s.model.ParamToSink, model.DataFlowSummaryFlow{ParameterIndex: idx, Categories: []string{cat}})
	sort.Slice(s.model.ParamToSink, func(i, j int) bool {
		return s.model.ParamToSink[i].ParameterIndex < s.model.ParamToSink[j].ParameterIndex
	})
	return true
}

func (b *dataFlowBuilder) addSourceReturn(fn *ssa.Function, pat model.DataFlowPattern) bool {
	s := b.summaries[fn]
	for _, existing := range s.sourceReturns {
		if existing.Pattern == pat.Pattern && existing.Category == pat.Category {
			return false
		}
	}
	s.sourceReturns = append(s.sourceReturns, pat)
	return true
}

func (b *dataFlowBuilder) addReturnField(fn *ssa.Function, field string) bool {
	s := b.summaries[fn]
	if s == nil || s.returnFields[field] {
		return false
	}
	s.returnFields[field] = true
	return true
}

func (b *dataFlowBuilder) recordSummaryFieldWrite(fn *ssa.Function, state dataFlowState, addr ssa.Value, tr dataFlowTrace) bool {
	if fn == nil || fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	field, ok := summaryReceiverField(addr)
	if !ok {
		return false
	}
	summary := b.summaries[fn]
	if summary == nil {
		return false
	}
	changed := false
	if summary.fieldWrites[field] == nil {
		summary.fieldWrites[field] = map[int]bool{}
	}
	for idx := range tr.params {
		if summary.fieldWrites[field][idx] {
			continue
		}
		summary.fieldWrites[field][idx] = true
		changed = true
	}
	if changed {
		fields := make([]string, 0, len(summary.fieldWrites))
		for name := range summary.fieldWrites {
			fields = append(fields, name)
		}
		sort.Strings(fields)
		if summary.model.Properties == nil {
			summary.model.Properties = map[string]string{}
		}
		summary.model.Properties["receiverFieldWrites"] = strings.Join(fields, ",")
	}
	_ = state
	return changed
}

func summaryReceiverField(addr ssa.Value) (string, bool) {
	switch field := addr.(type) {
	case *ssa.FieldAddr:
		if param, ok := field.X.(*ssa.Parameter); ok && param.Parent() != nil && param.Parent().Signature != nil && param.Parent().Signature.Recv() != nil && len(param.Parent().Params) > 0 && param == param.Parent().Params[0] {
			return fmt.Sprintf("field%d", field.Field), true
		}
	case *ssa.Field:
		if param, ok := field.X.(*ssa.Parameter); ok && param.Parent() != nil && param.Parent().Signature != nil && param.Parent().Signature.Recv() != nil && len(param.Parent().Params) > 0 && param == param.Parent().Params[0] {
			return fmt.Sprintf("field%d", field.Field), true
		}
	}
	return "", false
}

func (b *dataFlowBuilder) summaryReturnTrace(state dataFlowState, arg ssa.Value, idx int, summary *internalSummary) (dataFlowTrace, bool) {
	// When the summary names the fields a parameter-to-return flow travelled
	// through and this call site knows the argument field by field, answer
	// with only those fields. Applying an unqualified "parameter N flows to
	// the return" with the whole argument's taint makes every field of a
	// struct with any tainted field tainted in turn, which is how
	// pair{tainted: input, clean: "static"}.Clean() produced a finding. A
	// call site with no field-level record falls back to the whole-value
	// taint, so restricting can only ever remove a false positive.
	if summary != nil {
		if fields := summary.paramReturnFields[idx]; len(fields) > 0 {
			if tr, ok, applicable := b.argFieldTaint(state, arg, fields); applicable {
				return tr, ok
			}
		}
	}
	var traces []dataFlowTrace
	if tr, ok := b.taintOf(state, arg); ok {
		traces = append(traces, tr)
	}
	if idx == 0 && summary != nil {
		for field := range summary.returnFields {
			if tr, ok := state.memory[addrKey(arg)+"."+field]; ok {
				traces = append(traces, tr)
			}
		}
	}
	return combineTraceList(traces)
}

// argFieldTaint answers what an aggregate argument carries at the specific
// fields a callee's summary says it reads. applicable reports whether the
// restriction is meaningful: the argument is an aggregate and this call site
// holds at least one field-level record for it. When it does not — the common
// case, and every case where the struct was filled somewhere else — the caller
// must fall back to the whole-value taint rather than answer "nothing".
func (b *dataFlowBuilder) argFieldTaint(state dataFlowState, arg ssa.Value, fields map[string]bool) (dataFlowTrace, bool, bool) {
	if arg == nil || len(fields) == 0 || !isAggregateType(arg.Type()) {
		return dataFlowTrace{}, false, false
	}
	base := aggregateSourcePrefix(arg)
	if base == "" {
		return dataFlowTrace{}, false, false
	}
	knowsFields := false
	for _, key := range state.subKeys[base] {
		if strings.HasPrefix(key, base+".") {
			knowsFields = true
			break
		}
	}
	if !knowsFields {
		return dataFlowTrace{}, false, false
	}
	var traces []dataFlowTrace
	// Sorted, because combineTraces keeps one route out of several and a map
	// iteration would pick a different one between runs on the same input.
	for _, field := range sortedMapKeys(fields) {
		if tr, ok := state.memory[base+"."+field]; ok {
			traces = append(traces, tr)
		}
	}
	tr, ok := combineTraceList(traces)
	return tr, ok, true
}

func (b *dataFlowBuilder) combineCallArgTaints(state dataFlowState, common *ssa.CallCommon) (dataFlowTrace, bool) {
	var traces []dataFlowTrace
	for _, arg := range callArgs(common) {
		if tr, ok := b.taintOf(state, arg); ok {
			traces = append(traces, tr)
		}
	}
	if common != nil && common.Value != nil {
		if tr, ok := b.taintOf(state, common.Value); ok {
			traces = append(traces, tr)
		}
	}
	if recv := receiverValue(common); recv != nil {
		if tr, ok := b.taintOf(state, recv); ok {
			traces = append(traces, tr)
		}
	}
	return combineTraceList(traces)
}

func (b *dataFlowBuilder) shouldPropagate(common *ssa.CallCommon) bool {
	if len(b.matchCall(common, b.patterns.Passthroughs)) > 0 {
		return true
	}
	if common != nil && common.StaticCallee() == nil && common.Value != nil {
		return true
	}
	if common != nil {
		if _, ok := common.Value.(*ssa.MakeClosure); ok {
			return true
		}
	}
	callee := common.StaticCallee()
	if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil {
		return false
	}
	// The carrier list is the one the SEAM engine uses
	// (seam.IsStdlibCarrierPackage); sharing it is what keeps the two engines
	// from disagreeing about which standard library calls preserve taint.
	return seam.IsStdlibCarrierPackage(callee.Pkg.Pkg.Path())
}

func (b *dataFlowBuilder) matchCall(common *ssa.CallCommon, patterns []model.DataFlowPattern) []model.DataFlowPattern {
	symbol := callSymbol(common)
	name := callName(common)
	pkgPath := callPackage(common)
	typ := callType(common)
	return b.matchDataFlowPatterns(patterns, symbol, name, pkgPath, typ, "")
}

func (b *dataFlowBuilder) matchValueSource(v ssa.Value) []model.DataFlowPattern {
	return b.matchDataFlowPatterns(b.patterns.Sources, valueSymbol(v), valueName(v), valuePackage(v), valueType(v), valueConstString(v))
}

type fieldSourceMatch struct {
	name      string
	symbol    string
	typ       string
	fieldPath string
	pattern   model.DataFlowPattern
}

func (b *dataFlowBuilder) matchFieldSource(v ssa.Value) []fieldSourceMatch {
	target, ok := fieldPatternTargetForValue(v)
	if !ok {
		return nil
	}
	var out []fieldSourceMatch
	for _, p := range b.patterns.Sources {
		if !fieldPatternMatches(target, p, b.regexps) {
			continue
		}
		out = append(out, fieldSourceMatch{name: target.name, symbol: target.primarySymbol(), typ: target.typ, fieldPath: target.fieldPath, pattern: p})
	}
	return out
}

func (b *dataFlowBuilder) matchParameterSource(fn *ssa.Function, idx int, p *ssa.Parameter) []model.DataFlowPattern {
	text := p.Name() + " " + p.Type().String()
	matches := b.matchDataFlowPatterns(b.patterns.Sources, fn.String()+"."+p.Name(), p.Name(), callPackageForFunction(fn), p.Type().String(), text)
	out := matches[:0]
	for _, m := range matches {
		if m.Kind == "parameter" || m.Kind == "name" || m.Kind == "type" || m.Kind == "symbol" {
			out = append(out, m)
		}
	}
	_ = idx
	return out
}

func endpointHandlersForPackages(a *Analyzer, pkgs []*packages.Package) map[string][]model.APIEndpoint {
	out := map[string][]model.APIEndpoint{}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		facts := a.endpointFactsForPackage(pkg)
		for _, endpoint := range facts.endpoints {
			handler := strings.TrimSpace(endpoint.Handler)
			if handler == "" || handler == "func literal" {
				continue
			}
			out[handler] = append(out[handler], endpoint)
			if pkg.PkgPath != "" {
				out[pkg.PkgPath+"."+handler] = append(out[pkg.PkgPath+"."+handler], endpoint)
			}
		}
	}
	return out
}

func (b *dataFlowBuilder) matchEndpointHandlerParam(fn *ssa.Function, p *ssa.Parameter) []model.APIEndpoint {
	if fn == nil || p == nil || len(b.endpoints) == 0 {
		return nil
	}
	endpoints := append([]model.APIEndpoint{}, b.endpoints[fn.Name()]...)
	endpoints = append(endpoints, b.endpoints[fn.String()]...)
	if len(endpoints) == 0 {
		return nil
	}
	if isEndpointRequestParameter(fn.Signature, fn.Params, p) {
		return endpoints
	}
	return nil
}

func isEndpointRequestParameter(sig *types.Signature, params []*ssa.Parameter, p *ssa.Parameter) bool {
	idx := parameterIndex(params, p)
	if idx < 0 || sig == nil || sig.Params() == nil || idx >= sig.Params().Len() {
		return false
	}
	typeText := sig.Params().At(idx).Type().String()
	if strings.Contains(typeText, "net/http.Request") {
		return true
	}
	if isHTTPResponseWriterType(typeText) {
		return false
	}
	if sig.Params().Len() == 1 {
		return true
	}
	if idx == 1 {
		return true
	}
	return idx == 0 && sig.Params().Len() == 2 && isHTTPResponseWriterType(sig.Params().At(1).Type().String())
}

func parameterIndex(params []*ssa.Parameter, target *ssa.Parameter) int {
	for idx, param := range params {
		if param == target {
			return idx
		}
	}
	return -1
}

func isHTTPResponseWriterType(typeText string) bool {
	return strings.Contains(typeText, "net/http.ResponseWriter")
}

func (b *dataFlowBuilder) matchDataFlowPatterns(patterns []model.DataFlowPattern, symbol, name, pkgPath, typ, code string) []model.DataFlowPattern {
	var out []model.DataFlowPattern
	for _, p := range patterns {
		value := symbol
		switch p.Kind {
		case "function", "method", "symbol":
			value = symbol
		case "package", "namespace":
			value = pkgPath
		case "type":
			value = typ
		case "name", "parameter", "field", "receiver":
			value = name
		case "code":
			value = code
		}
		if patternMatches(value, p, b.regexps) {
			out = append(out, p)
		}
	}
	return out
}

type fieldPatternTarget struct {
	symbols   []string
	name      string
	pkgPath   string
	typ       string
	fieldPath string
}

func (t fieldPatternTarget) primarySymbol() string {
	if len(t.symbols) > 0 {
		return t.symbols[0]
	}
	return t.name
}

func fieldPatternMatches(target fieldPatternTarget, p model.DataFlowPattern, regexps map[string]*regexp.Regexp) bool {
	switch p.Kind {
	case "field":
		if patternMatches(target.name, p, regexps) {
			return true
		}
		for _, symbol := range target.symbols {
			if patternMatches(symbol, p, regexps) {
				return true
			}
		}
		return false
	case "symbol":
		for _, symbol := range target.symbols {
			if patternMatches(symbol, p, regexps) {
				return true
			}
		}
		return false
	case "package", "namespace":
		return patternMatches(target.pkgPath, p, regexps)
	case "type":
		return patternMatches(target.typ, p, regexps)
	case "name":
		return patternMatches(target.name, p, regexps)
	default:
		return false
	}
}

func fieldPatternTargetForValue(v ssa.Value) (fieldPatternTarget, bool) {
	switch x := v.(type) {
	case *ssa.FieldAddr:
		return fieldPatternTargetForType(x.X.Type(), x.Field)
	case *ssa.Field:
		return fieldPatternTargetForType(x.X.Type(), x.Field)
	default:
		return fieldPatternTarget{}, false
	}
}

func fieldPatternTargetForType(base types.Type, fieldIndex int) (fieldPatternTarget, bool) {
	named, structType, ok := namedStructType(base)
	if !ok || fieldIndex < 0 || fieldIndex >= structType.NumFields() {
		return fieldPatternTarget{}, false
	}
	field := structType.Field(fieldIndex)
	if field == nil {
		return fieldPatternTarget{}, false
	}
	pkgPath := ""
	if named.Obj() != nil && named.Obj().Pkg() != nil {
		pkgPath = named.Obj().Pkg().Path()
	}
	if pkgPath == "" && field.Pkg() != nil {
		pkgPath = field.Pkg().Path()
	}
	typeName := ""
	if named.Obj() != nil {
		typeName = named.Obj().Name()
	}
	symbols := []string{}
	if pkgPath != "" && typeName != "" {
		symbols = append(symbols, pkgPath+"."+typeName+"."+field.Name(), pkgPath+".(*"+typeName+")."+field.Name())
	}
	return fieldPatternTarget{
		symbols:   uniqueStrings(symbols),
		name:      field.Name(),
		pkgPath:   pkgPath,
		typ:       field.Type().String(),
		fieldPath: fmt.Sprintf("field%d", fieldIndex),
	}, true
}

func namedStructType(base types.Type) (*types.Named, *types.Struct, bool) {
	original := types.Unalias(base)
	if ptr, ok := original.(*types.Pointer); ok {
		original = types.Unalias(ptr.Elem())
	}
	named, ok := original.(*types.Named)
	if !ok {
		return nil, nil, false
	}
	structType, ok := named.Underlying().(*types.Struct)
	if !ok {
		return nil, nil, false
	}
	return named, structType, true
}

func patternMatches(value string, p model.DataFlowPattern, regexps map[string]*regexp.Regexp) bool {
	if value == "" || p.Pattern == "" {
		return false
	}
	switch strings.ToLower(p.Match) {
	case "exact":
		return strings.EqualFold(value, p.Pattern)
	case "prefix":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(p.Pattern))
	case "suffix":
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(p.Pattern))
	case "regex":
		re := regexps[dataFlowPatternKey(p)]
		return re != nil && re.MatchString(value)
	default:
		return strings.Contains(strings.ToLower(value), strings.ToLower(p.Pattern))
	}
}

func callArgs(common *ssa.CallCommon) []ssa.Value {
	if common == nil {
		return nil
	}
	args := append([]ssa.Value{}, common.Args...)
	return args
}

func receiverValue(common *ssa.CallCommon) ssa.Value {
	if common == nil || common.Value == nil {
		return nil
	}
	if common.IsInvoke() {
		return common.Value
	}
	return nil
}

func callSymbol(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if callee := common.StaticCallee(); callee != nil {
		return callee.String()
	}
	if name := unsafeBuiltinName(common); name != "" {
		return "unsafe." + name
	}
	if common.Method != nil {
		return objectSymbol(common.Method)
	}
	return common.String()
}

func callName(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if callee := common.StaticCallee(); callee != nil {
		return callee.Name()
	}
	if name := unsafeBuiltinName(common); name != "" {
		return name
	}
	if common.Method != nil {
		return common.Method.Name()
	}
	return common.String()
}

func callType(common *ssa.CallCommon) string {
	if common == nil || common.Signature() == nil {
		return ""
	}
	return common.Signature().String()
}

func callPackage(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if callee := common.StaticCallee(); callee != nil {
		return callPackageForFunction(callee)
	}
	if unsafeBuiltinName(common) != "" {
		return "unsafe"
	}
	if common.Method != nil && common.Method.Pkg() != nil {
		return common.Method.Pkg().Path()
	}
	return ""
}

func unsafeBuiltinName(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	builtin, ok := common.Value.(*ssa.Builtin)
	if !ok || builtin == nil {
		return ""
	}
	switch builtin.Name() {
	case "String", "Slice", "StringData", "SliceData", "Add":
		return builtin.Name()
	default:
		return ""
	}
}

func callPackageForFunction(fn *ssa.Function) string {
	if fn != nil && fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	return ""
}

func objectSymbol(obj types.Object) string {
	if obj == nil {
		return ""
	}
	if obj.Pkg() != nil {
		return obj.Pkg().Path() + "." + obj.Name()
	}
	return obj.Name()
}

func addrKey(v ssa.Value) string {
	switch x := v.(type) {
	case nil:
		return ""
	case *ssa.Alloc:
		return "alloc:" + x.String() + ":" + fmt.Sprint(x.Pos())
	case *ssa.Global:
		return "global:" + x.String()
	case *ssa.Const:
		if s := valueConstString(x); s != "" {
			if len(s) > 80 {
				s = s[:80]
			}
			return "const:" + s
		}
		return "const"
	case *ssa.FieldAddr:
		return addrKey(x.X) + fmt.Sprintf(".field%d", x.Field)
	case *ssa.IndexAddr:
		return addrKey(x.X) + "[*]"
	case *ssa.Parameter:
		return "param:" + x.Parent().String() + ":" + x.Name()
	default:
		return "value:" + x.String()
	}
}

func fieldMemoryKey(base ssa.Value, field int) string {
	return addrKey(base) + fmt.Sprintf(".field%d", field)
}

func valueName(v ssa.Value) string {
	if v == nil {
		return ""
	}
	if n := v.Name(); n != "" {
		return n
	}
	return v.String()
}

func valueSymbol(v ssa.Value) string {
	if v == nil {
		return ""
	}
	if m, ok := v.(interface{ Object() types.Object }); ok && m.Object() != nil {
		return objectSymbol(m.Object())
	}
	return v.String()
}

func valuePackage(v ssa.Value) string {
	if v == nil {
		return ""
	}
	if m, ok := v.(interface{ Object() types.Object }); ok && m.Object() != nil && m.Object().Pkg() != nil {
		return m.Object().Pkg().Path()
	}
	return ""
}

func valueType(v ssa.Value) string {
	if v == nil || v.Type() == nil {
		return ""
	}
	return v.Type().String()
}

func valueConstString(v ssa.Value) string {
	if c, ok := v.(*ssa.Const); ok && c.Value != nil && c.Value.Kind() == constant.String {
		return constant.StringVal(c.Value)
	}
	return ""
}

func (t dataFlowTrace) empty() bool { return len(t.nodeIDs) == 0 && len(t.params) == 0 && !t.generated }

func (t dataFlowTrace) withFieldPath(path string) dataFlowTrace {
	if path != "" {
		t.fieldPaths = uniqueStrings(append(t.fieldPaths, path))
	}
	return t
}

func combineTraceList(traces []dataFlowTrace) (dataFlowTrace, bool) {
	if len(traces) == 0 {
		return dataFlowTrace{}, false
	}
	out := traces[0]
	for _, tr := range traces[1:] {
		out = combineTraces(out, tr)
	}
	return out, !out.empty()
}

func combineTraces(a, b dataFlowTrace) dataFlowTrace {
	if a.empty() {
		return b
	}
	if b.empty() {
		return a
	}
	// Keep one coherent route rather than the union of two.
	//
	// A trace is a path, and connectTrace extends it from whichever node is
	// last. Unioning the nodes and edges of two routes leaves no single tail,
	// so the next hop attaches to an arbitrary node of the merged set and the
	// slice stops describing a path at all — its nodes and its edges disagree
	// about how the taint travelled. The union was never faithful in any case:
	// only one sourceID survives a merge, so the other route's nodes were
	// already orphans in the report.
	//
	// Everything that is a property of the taint rather than of the route is
	// still merged, and the shorter route wins because a shorter path is both
	// likelier to be the one a reader wants and cheaper to render.
	route := a
	other := b
	if len(b.nodeIDs) < len(a.nodeIDs) && (a.sourceID == "" || b.sourceID != "") {
		route, other = b, a
	}
	out := dataFlowTrace{
		nodeIDs:             orderedUniqueLimit(route.nodeIDs, defaultDataFlowMaxTraceNodes),
		tailID:              route.tailID,
		edgeIDs:             orderedUniqueLimit(route.edgeIDs, defaultDataFlowMaxTraceEdges),
		params:              map[int]bool{},
		taintKinds:          uniqueStrings(append(a.taintKinds, b.taintKinds...)),
		fieldPaths:          uniqueStrings(append(a.fieldPaths, b.fieldPaths...)),
		sanitizedCategories: uniqueStrings(append(a.sanitizedCategories, b.sanitizedCategories...)),
		sourceID:            firstNonEmpty(route.sourceID, other.sourceID),
		sourceCategory:      firstNonEmpty(route.sourceCategory, other.sourceCategory),
		sourcePURL:          firstNonEmpty(route.sourcePURL, other.sourcePURL),
		sourcePatterns:      append(append([]model.DataFlowPattern{}, a.sourcePatterns...), b.sourcePatterns...),
		confidence:          firstNonEmpty(a.confidence, b.confidence, "medium"),
		generated:           a.generated || b.generated,
	}
	for k := range a.params {
		out.params[k] = true
	}
	for k := range b.params {
		out.params[k] = true
	}
	return out
}

func sanitizerCategories(patterns []model.DataFlowPattern) []string {
	var out []string
	for _, pat := range patterns {
		out = append(out, pat.SanitizesCategories...)
	}
	return uniqueStrings(out)
}

func traceAllowsSink(tr dataFlowTrace, category string) bool {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		return true
	}
	for _, sanitized := range tr.sanitizedCategories {
		if strings.EqualFold(sanitized, category) {
			return false
		}
	}
	return true
}

func (b *dataFlowBuilder) addDiagnosticOnce(kind, message string) {
	if b == nil || b.out == nil || message == "" {
		return
	}
	key := kind + "\x00" + message
	if b.diagnosticSeen == nil {
		b.diagnosticSeen = map[string]bool{}
	}
	if b.diagnosticSeen[key] {
		return
	}
	b.diagnosticSeen[key] = true
	b.out.Diagnostics = append(b.out.Diagnostics, model.Diagnostic{Kind: kind, Message: message})
}

func dataFlowTruncationReasons(diagnostics []model.Diagnostic) []string {
	seen := map[string]bool{}
	var out []string
	for _, diag := range diagnostics {
		if diag.Kind != "dataflow-budget" || diag.Message == "" || seen[diag.Message] {
			continue
		}
		seen[diag.Message] = true
		out = append(out, diag.Message)
	}
	sort.Strings(out)
	return out
}

func enrichDataFlowSlices(df *model.DataFlowEvidence) {
	if df == nil || len(df.Slices) == 0 {
		return
	}
	nodes := map[string]model.DataFlowNode{}
	for _, node := range df.Nodes {
		nodes[node.ID] = node
	}
	edges := map[string]model.DataFlowEdge{}
	for _, edge := range df.Edges {
		edges[edge.ID] = edge
	}
	firstByFlow := map[string]string{}
	countByFlow := map[string]int{}
	duplicateGroups := map[string]bool{}
	totalPathLength := 0
	for i := range df.Slices {
		s := &df.Slices[i]
		if source, ok := nodes[s.SourceID]; ok {
			s.SourceName = source.Name
			s.SourceSymbol = source.Symbol
			s.SourceFunction = source.Function
			s.SourcePackagePath = source.PackagePath
			s.SourceScope = fileRole(source.Position.Filename)
			s.SourceCriticality = sourceCriticality(s.SourceCategory)
			s.SourcePURL = firstNonEmpty(s.SourcePURL, source.PURL)
			if s.SourceCategory == "" {
				s.SourceCategory = source.Category
			}
		}
		if sink, ok := nodes[s.SinkID]; ok {
			s.SinkName = sink.Name
			s.SinkSymbol = sink.Symbol
			s.SinkFunction = sink.Function
			s.SinkPackagePath = sink.PackagePath
			s.SinkScope = fileRole(sink.Position.Filename)
			s.SinkCriticality = sinkCriticality(s.SinkCategory)
			s.SinkPURL = firstNonEmpty(s.SinkPURL, sink.PURL)
			if s.SinkCategory == "" {
				s.SinkCategory = sink.Category
			}
		}
		purls := []string{s.SourcePURL, s.SinkPURL}
		for _, nodeID := range s.NodeIDs {
			if node, ok := nodes[nodeID]; ok {
				purls = append(purls, node.PURL)
			}
		}
		s.PURLs = orderedUniqueStrings(append(s.PURLs, purls...))
		var edgeKinds []string
		for _, edgeID := range s.EdgeIDs {
			if edge, ok := edges[edgeID]; ok {
				edgeKinds = append(edgeKinds, edge.Kind)
			}
		}
		s.EdgeKinds = uniqueStrings(edgeKinds)
		var sanitizerIDs []string
		for _, nodeID := range s.NodeIDs {
			if node, ok := nodes[nodeID]; ok && node.Kind == "sanitizer" {
				sanitizerIDs = append(sanitizerIDs, nodeID)
			}
		}
		s.SanitizerNodeIDs = uniqueStrings(sanitizerIDs)
		// Rule metadata is part of the published slice schema, and a consumer
		// filtering on severity or riskScore has to get the same answer from
		// either engine. Legacy fills these in while compiling its pattern
		// pack, so only entries whose model omits them arrive here empty;
		// deriving from the sink category is the same rule legacy applies.
		if s.RuleID == "" || s.RuleName == "" || s.Severity == "" || s.RiskScore == 0 {
			ruleID, ruleName, severity, score := dataFlowRuleForCategory(s.SinkCategory)
			s.RuleID = firstNonEmpty(s.RuleID, ruleID)
			s.RuleName = firstNonEmpty(s.RuleName, ruleName)
			s.Severity = firstNonEmpty(s.Severity, severity)
			if s.RiskScore == 0 {
				s.RiskScore = score
			}
		}
		if s.Confidence == "" {
			s.Confidence = "medium"
		}
		s.PathLength = len(s.EdgeIDs)
		totalPathLength += s.PathLength
		if s.PathLength > df.Stats.MaxPathLength {
			df.Stats.MaxPathLength = s.PathLength
		}
		if len(s.SanitizerNodeIDs) > 0 {
			df.Stats.SanitizedSliceCount++
		}
		arg := ""
		if s.SinkArgumentIndex != nil {
			arg = fmt.Sprint(*s.SinkArgumentIndex)
		}
		s.FlowKey = stableID("df-flow", s.SourceCategory, s.SinkCategory, s.SourceFunction, s.SinkFunction, s.SinkSymbol, arg, strings.Join(s.TaintKinds, ","), strings.Join(s.FieldPaths, ","))
		countByFlow[s.FlowKey]++
		if first := firstByFlow[s.FlowKey]; first != "" {
			s.DuplicateOf = first
			s.DuplicateIndex = countByFlow[s.FlowKey]
			duplicateGroups[s.FlowKey] = true
		} else {
			firstByFlow[s.FlowKey] = s.ID
		}
	}
	df.Stats.UniqueFlowCount = len(firstByFlow)
	for _, count := range countByFlow {
		if count > 1 {
			df.Stats.DuplicateSliceCount += count - 1
		}
	}
	df.Stats.DuplicateGroupCount = len(duplicateGroups)
	if len(df.Slices) > 0 {
		df.Stats.AveragePathLength = float64(totalPathLength) / float64(len(df.Slices))
	}
}

func sourceCriticality(category string) string {
	switch strings.ToLower(category) {
	case "http-input", "http-endpoint", "cli", "environment", "crypto-material":
		return "high"
	case "framework-context", "configuration":
		return "medium"
	case "parameter":
		return "low"
	default:
		return "medium"
	}
}

func sinkCriticality(category string) string {
	switch strings.ToLower(category) {
	case "command-execution", "native-interop", "unsafe", "syscall", "dynamic-loading":
		return "critical"
	case "filesystem", "data", "crypto":
		return "high"
	case "redirect", "http-response", "formatted-output", "logging", "external-service":
		return "medium"
	default:
		return "medium"
	}
}

func taintsForPattern(p model.DataFlowPattern) []string {
	if len(p.TaintKinds) > 0 {
		return p.TaintKinds
	}
	if p.Category != "" {
		return []string{p.Category}
	}
	return nil
}

func mergeStrings(a, b []string) []string {
	return uniqueStrings(append(append([]string{}, a...), b...))
}

func appendLimitedUnique(values []string, value string, limit int) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	if limit > 0 && len(values) >= limit {
		copy(values, values[1:])
		values[len(values)-1] = value
		return values
	}
	return append(values, value)
}

func orderedUniqueStrings(in []string) []string {
	return orderedUniqueLimit(in, 0)
}

func orderedUniqueLimit(in []string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		if limit > 0 && len(out) >= limit {
			break
		}
		out = append(out, value)
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sortedMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortDataFlowEvidence(df *model.DataFlowEvidence) {
	if df == nil {
		return
	}
	sort.Slice(df.Nodes, func(i, j int) bool { return df.Nodes[i].ID < df.Nodes[j].ID })
	sort.Slice(df.Edges, func(i, j int) bool { return df.Edges[i].ID < df.Edges[j].ID })
	sort.Slice(df.Slices, func(i, j int) bool { return df.Slices[i].ID < df.Slices[j].ID })
	sort.Slice(df.Summaries, func(i, j int) bool { return df.Summaries[i].FunctionID < df.Summaries[j].FunctionID })
}

// buildDataFlowSEAM runs the SEAM taint engine and adapts its output.
func (a *Analyzer) buildDataFlowSEAM(pkgs []*packages.Package, ctx *ssaContext, progress *progressLogger, started time.Time) *model.DataFlowEvidence {
	mode := a.options.DataFlowMode
	if mode == "" || mode == "none" {
		return &model.DataFlowEvidence{Engine: "seam", Mode: mode}
	}

	// Build the call graph for summary SCC ordering and reachability. SEAM uses
	// its own implements-index for dispatch resolution, so the call graph only
	// needs to be correct for direct calls — which the static call graph is.
	// RTA can be sparse for library-only modules (no main → few roots), which
	// would miss functions that are obviously reachable.
	graph, _, cgDiags := a.buildRawCallGraph(ctx, seamCallGraphMode)
	if requested := a.options.DataFlowCallGraphMode; requested != "" && requested != seamCallGraphMode {
		cgDiags = append(cgDiags, model.Diagnostic{
			Kind:    "dataflow",
			Message: fmt.Sprintf("SEAM built its call graph with %q rather than the requested %q: it resolves dispatch through its own implements-index, and RTA is sparse on a module with no main package", seamCallGraphMode, requested),
		})
	}
	dynamicCallees := callGraphCalleeIndex(graph)

	// Module and package attribution for the whole loaded graph, not just the
	// roots. Taint that reaches a dependency has to be attributable to that
	// dependency: without the transitive walk every dependency package looks
	// module-less, which reads downstream as "part of the module under
	// analysis" and makes dependencyCrossingSliceCount zero by construction.
	moduleByPath := make(map[string]*model.Module)
	packageByPath := make(map[string]*packages.Package)
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if pkg == nil || pkg.PkgPath == "" {
			return
		}
		packageByPath[pkg.PkgPath] = pkg
		if mod := moduleForPackage(pkg); mod != nil {
			moduleByPath[pkg.PkgPath] = mod
		}
	})

	// The scope controls what gets materialised (reported), not what gets
	// summarised. Summaries are always computed for the whole reachable
	// program (including dependencies and stdlib) so taint can cross those
	// boundaries. Materialisation is always local: a slice is reported for
	// code in the module under analysis, not for stdlib internals. This is the
	// two-tier policy from §4.2: summary scope = whole program, materialisation
	// scope = local.
	// --dataflow all widens materialisation to the dependency tree, which is
	// what it has always meant in practice. It stops short of the standard
	// library: a finding reported inside net/http names a function the reader
	// did not write, and on this corpus that alone produced ten such findings
	// per fixture.
	scope := "local"
	if mode == "all" {
		scope = "dependencies"
	}

	// Create and run SEAM engine.
	seamOpts := seam.Options{
		Mode:      mode,
		Scope:     scope,
		MaxSlices: a.options.DataFlowMax,
	}
	if seamOpts.MaxSlices <= 0 {
		seamOpts.MaxSlices = 1000
	}
	engine := seam.NewEngine(seamOpts)

	// //go:linkname is invisible to SSA, so a call to a body-less declaration
	// leads into nothing. The call graph already draws the alias edge; give
	// the taint engine the same mapping so a flow can cross it too.
	if a.native != nil {
		aliases := map[*ssa.Function]*ssa.Function{}
		for _, directive := range a.native.Linknames() {
			local := a.native.ResolveTarget(directive.PackagePath + "." + directive.Local)
			target := a.native.ResolveTarget(directive.Target)
			if local != nil && target != nil && local != target {
				aliases[local] = target
			}
		}
		if len(aliases) > 0 {
			engine.SetLinknameAliases(aliases)
		}
	}

	progress.Memoryf("data-flow starting engine=seam mode=%s scope=%s functions=%d maxSlices=%d",
		mode, scope, len(ctx.program.AllPackages()), seamOpts.MaxSlices)
	out := engine.Analyze(ctx.program, pkgs, graph, dynamicCallees, moduleByPath, packageByPath, a.fset)

	// SEAM's diagnostics are emitted with Kind="seam". A subset of them —
	// the slice-limit message — is the same condition legacy reports as
	// Kind="dataflow-budget", and downstream stats (Truncated,
	// TruncationReasons) key off that Kind. Reclassify them so the budget
	// signal is visible to consumers of either engine's report.
	for i, diag := range out.Diagnostics {
		if diag.Kind == "seam" && strings.Contains(diag.Message, "slice limit reached") {
			out.Diagnostics[i].Kind = "dataflow-budget"
		}
	}

	// Attach diagnostics.
	for _, diag := range cgDiags {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Kind: diag.Kind, Message: diag.Message})
	}

	// Enrich slices with source/sink info (like legacy does).
	enrichDataFlowSlices(out)
	sortDataFlowEvidence(out)

	// Compute stats.
	out.Stats.NodeCount = len(out.Nodes)
	out.Stats.EdgeCount = len(out.Edges)
	out.Stats.SliceCount = len(out.Slices)
	out.Stats.SummaryCount = len(out.Summaries)
	out.Stats.FunctionCount = engine.AllFuncs()
	out.Stats.ElapsedMillis = int(time.Since(started).Milliseconds())
	out.Stats.TruncationReasons = dataFlowTruncationReasons(out.Diagnostics)
	out.Stats.Truncated = len(out.Stats.TruncationReasons) > 0

	for _, n := range out.Nodes {
		if n.Source {
			out.Stats.SourceCount++
		}
		if n.Sink {
			out.Stats.SinkCount++
		}
	}

	progress.Memoryf("data-flow SEAM engine complete slices=%d nodes=%d edges=%d elapsed=%dms",
		out.Stats.SliceCount, out.Stats.NodeCount, out.Stats.EdgeCount, out.Stats.ElapsedMillis)

	return out
}
