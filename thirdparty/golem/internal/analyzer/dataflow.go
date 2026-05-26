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
)

const (
	maxTraceNodeIDs                  = 64
	maxTraceEdgeIDs                  = 128
	largeRepoFunctionCount           = 1000
	largeRepoMaxFunctionInstructions = 200
)

type dataFlowTrace struct {
	nodeIDs             []string
	edgeIDs             []string
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
}

type internalSummary struct {
	model         model.DataFlowMethodSummary
	paramReturn   map[int]bool
	paramSink     map[int]map[string]bool
	sourceReturns []model.DataFlowPattern
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
	sliceSeen      map[string]bool
	diagnosticSeen map[string]bool
	sliceBudget    *dataFlowBudget
	maxSlices      int
	instructionCt  int
}

type dataFlowBudget struct {
	max  int64
	used atomic.Int64
}

func (a *Analyzer) buildDataFlow(pkgs []*packages.Package, ctx *ssaContext, progress *progressLogger) *model.DataFlowEvidence {
	started := time.Now()
	patterns, diagnostics := loadDataFlowPatterns(a.options.DataFlowMode, a.options.DataFlowPacks, a.options.DataFlowConfig)
	regexps, regexDiagnostics := compileDataFlowRegexps(patterns)
	diagnostics = append(diagnostics, regexDiagnostics...)
	out := &model.DataFlowEvidence{Mode: a.options.DataFlowMode, Patterns: patterns, Diagnostics: diagnostics}
	if ctx == nil || ctx.program == nil {
		out.Diagnostics = append(out.Diagnostics, model.Diagnostic{Kind: "dataflow", Message: "SSA context was not available"})
		return out
	}
	funcs := ctx.filteredFunctions(a.includeDataFlowFunction)
	sortDataFlowFunctions(funcs)
	analysisFuncs, skippedFuncs := dataFlowAnalysisFunctions(funcs)
	workers := dataFlowWorkerCount(a.options, len(analysisFuncs))
	progress.Memoryf("data-flow starting mode=%s functions=%d analyzedFunctions=%d skippedFunctions=%d workers=%d maxSlices=%d", a.options.DataFlowMode, len(funcs), len(analysisFuncs), skippedFuncs, workers, a.options.DataFlowMax)
	progress.Logf("data-flow scheduled first=%s largest=%s", describeDataFlowFunctions(analysisFuncs, 6, false), describeDataFlowFunctions(analysisFuncs, 6, true))
	dynamicCallees := a.dataFlowDynamicCallees(ctx, out)
	b := &dataFlowBuilder{analyzer: a, out: out, patterns: patterns, regexps: regexps, summaries: map[*ssa.Function]*internalSummary{}, endpoints: endpointHandlersForPackages(a, pkgs), dynamicCallees: dynamicCallees, nodeSeen: map[string]bool{}, edgeSeen: map[string]bool{}, sliceSeen: map[string]bool{}, diagnosticSeen: map[string]bool{}, sliceBudget: newDataFlowBudget(a.options.DataFlowMax), maxSlices: a.options.DataFlowMax}
	progress.Memoryf("data-flow inferring summaries")
	b.inferSummaries(funcs)
	progress.Memoryf("data-flow summaries inferred")
	if skippedFuncs > 0 {
		b.addDiagnosticOnce("dataflow-budget", fmt.Sprintf("skipped %d very large functions above %d SSA instructions during slice materialization; summaries were still inferred", skippedFuncs, largeRepoMaxFunctionInstructions))
	}
	b.analyzeFunctions(analysisFuncs, workers, progress)
	progress.Memoryf("data-flow function analysis complete")
	for _, summary := range b.summaries {
		if len(summary.model.ParamToReturn) > 0 || len(summary.model.ParamToSink) > 0 || len(summary.sourceReturns) > 0 || summary.model.ReceiverToReturn || summary.model.Passthrough {
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

func dataFlowAnalysisFunctions(funcs []*ssa.Function) ([]*ssa.Function, int) {
	if len(funcs) < largeRepoFunctionCount {
		return funcs, 0
	}
	out := make([]*ssa.Function, 0, len(funcs))
	skipped := 0
	for _, fn := range funcs {
		if ssaFunctionInstructionCount(fn) > largeRepoMaxFunctionInstructions {
			skipped++
			continue
		}
		out = append(out, fn)
	}
	return out, skipped
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

func loadDataFlowPatterns(mode string, packs []string, path string) (*model.DataFlowPatternSet, []model.Diagnostic) {
	set := builtinDataFlowPatterns(mode, packs)
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

func builtinDataFlowPatterns(mode string, packs []string) *model.DataFlowPatternSet {
	selected := map[string]bool{}
	if len(packs) == 0 {
		for _, p := range []string{"base", "http", "data", "filesystem", "process", "crypto", "native", "frameworks"} {
			selected[p] = true
		}
	} else {
		for _, p := range packs {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "all" {
				for _, name := range []string{"base", "http", "data", "filesystem", "process", "crypto", "native", "frameworks"} {
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
	if selected["base"] || mode == "all" || mode == "security" {
		addSource("symbol", "os.Args", "cli", "user-input")
		addSource("function", "os.Getenv", "environment", "environment", "secret")
		addSource("function", "os.LookupEnv", "environment", "environment", "secret")
		addSource("function", "flag.Arg", "cli", "user-input")
		addSource("function", "flag.Args", "cli", "user-input")
		paramPattern := dfPattern("source", "parameter", "^(input|query|command|cmd|path|file|filename|url|uri|token|key|secret|password)$", "parameter", "user-input")
		paramPattern.Match = "regex"
		set.Sources = append(set.Sources, paramPattern)
		addSource("type", "*net/http.Request", "http-request", "user-input")
		addSource("type", "http.Request", "http-request", "user-input")
		for _, name := range []string{"fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln", "strings.Join", "strings.Trim", "strings.TrimSpace", "strings.Replace", "strings.ReplaceAll", "bytes.(*Buffer).String", "strconv.Itoa", "strconv.Format", "net/url.QueryEscape", "net/url.PathEscape", "net/url.JoinPath", "reflect.ValueOf", "reflect.Value.Interface", "reflect.Value).Interface", "reflect.Value.String", "reflect.Value).String", "reflect.Value.Bytes", "reflect.Value).Bytes", "reflect.Value.Convert", "reflect.Value).Convert"} {
			addPass("function", name, "conversion")
		}
		for _, name := range []string{"log.Print", "log.Printf", "log.Println", "log.Fatal", "log.Fatalf", "log.Fatalln", "log.Panic", "log.Panicf", "log.Panicln", "log/slog.Debug", "log/slog.Info", "log/slog.Warn", "log/slog.Error", "fmt.Print", "fmt.Printf", "fmt.Println", "fmt.Fprint", "fmt.Fprintf", "fmt.Fprintln"} {
			addSink("function", name, "logging", "user-input", "secret")
		}
	}
	if selected["http"] || mode == "all" || mode == "security" {
		for _, name := range []string{"FormValue", "PostFormValue", "Cookie", "Header.Get", "Header).Get", "Values.Get", "(*net/url.URL).Query", "ParseForm", "MultipartReader", "FormFile", "github.com/gin-gonic/gin", "Param", "PostForm", "DefaultQuery", "GetHeader", "Bind", "ShouldBind", "github.com/labstack/echo", "QueryParam", "Param", "FormValue", "github.com/gofiber/fiber", "Params", "Body", "Cookies"} {
			addSource("function", name, "http-input", "user-input")
		}
		addSink("function", "net/http.ResponseWriter.Write", "http-response", "user-input")
		addSink("function", "fmt.Fprintf", "formatted-output", "user-input")
		addSink("function", "http.Error", "http-response", "user-input")
		addSink("function", "encoding/json.(*Encoder).Encode", "http-response", "user-input")
		addSink("function", "http.Redirect", "redirect", "url")
		addCategorySan("function", "net/url.QueryEscape", "url-encoding", []string{"redirect"}, "url")
		addCategorySan("function", "net/url.PathEscape", "url-encoding", []string{"redirect"}, "url")
		addCategorySan("function", "html/template.HTMLEscapeString", "html-escaping", []string{"http-response", "formatted-output"})
	}
	if selected["frameworks"] || mode == "all" || mode == "security" {
		for _, sourceType := range []string{"gin.Context", "*gin.Context", "echo.Context", "fiber.Ctx", "*fiber.Ctx", "chi.Context", "mux.RouteMatch"} {
			addSource("type", sourceType, "framework-context", "user-input")
		}
		for _, passthrough := range []string{"github.com/gin-gonic/gin.Context", "github.com/labstack/echo", "github.com/gofiber/fiber", "github.com/go-chi/chi", "github.com/gorilla/mux"} {
			addPass("function", passthrough, "framework")
		}
	}
	if selected["process"] || mode == "all" || mode == "security" {
		addSink("function", "os/exec.Command", "command-execution", "user-input")
		addSink("function", "os/exec.CommandContext", "command-execution", "user-input")
		addSink("function", "plugin.Open", "dynamic-loading", "user-input", "path")
		addPass("function", "plugin.Lookup", "dynamic-loading")
	}
	if selected["data"] || mode == "all" || mode == "security" {
		for _, name := range []string{"database/sql.(*DB).Query", "database/sql.(*DB).QueryContext", "database/sql.(*DB).Exec", "database/sql.(*DB).ExecContext", "database/sql.(*Tx).Query", "database/sql.(*Tx).Exec", "database/sql.(*Conn).Query", "database/sql.(*Conn).Exec", "github.com/jmoiron/sqlx", "github.com/jackc/pgx", "gorm.io/gorm.(*DB).Raw", "gorm.io/gorm.(*DB).Exec", "encoding/gob.(*Decoder).Decode", "encoding/json.Unmarshal", "yaml.Unmarshal"} {
			addSink("function", name, "data", "user-input")
		}
		addCategorySan("function", "database/sql.(*Stmt).Exec", "sql-parameterization", []string{"data"}, "sql")
	}
	if selected["filesystem"] || mode == "all" || mode == "security" {
		for _, name := range []string{"os.Open", "os.OpenFile", "os.WriteFile", "os.ReadFile", "os.Create", "os.Mkdir", "os.MkdirAll", "os.Remove", "os.RemoveAll", "archive/zip", "archive/tar", "http.ServeFile"} {
			addSink("function", name, "filesystem", "path")
		}
		addPass("function", "path/filepath.Join", "path")
		addPass("function", "path.Join", "path")
		addCategorySan("function", "path/filepath.Base", "path-validation", []string{"filesystem"}, "path")
	}
	if selected["crypto"] || mode == "all" || mode == "crypto" || mode == "security" {
		for _, name := range []string{"crypto/aes.NewCipher", "crypto/des.NewCipher", "crypto/hmac.New", "crypto/x509.ParsePKCS1PrivateKey", "crypto/x509.ParsePKCS8PrivateKey", "crypto/x509.ParseCertificate", "crypto/tls.LoadX509KeyPair", "golang.org/x/crypto/pbkdf2.Key", "github.com/golang-jwt/jwt", "github.com/dgrijalva/jwt-go"} {
			addSink("function", name, "crypto", "secret", "crypto-key")
		}
		addSource("name", "(?i)(private.*key|secret|password|token|nonce|iv|salt)", "crypto-material", "secret", "crypto-key")
		addSan("function", "crypto/rand.Read", "secure-random", "insecure-random")
	}
	if selected["native"] || mode == "all" || mode == "security" {
		addSink("function", "_Cfunc_", "native-interop", "native")
		addPass("function", "_Cfunc_CString", "native-conversion")
		addPass("function", "_Cgo_ptr", "native-conversion")
		addSink("package", "unsafe", "unsafe", "native")
		for _, name := range []string{"unsafe.String", "unsafe.Slice", "reflect.Value.Call", "reflect.Value).Call", "reflect.Value.CallSlice", "reflect.Value).CallSlice"} {
			addSink("function", name, "unsafe", "native")
		}
		df := dfPattern("sink", "function", "syscall.", "syscall", "native")
		set.Sinks = append(set.Sinks, df)
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
		if p.Pattern != "" {
			out = append(out, p)
		}
	}
	return out
}

func (b *dataFlowBuilder) inferSummaries(funcs []*ssa.Function) {
	for _, fn := range funcs {
		b.summaries[fn] = &internalSummary{model: b.newSummary(fn), paramReturn: map[int]bool{}, paramSink: map[int]map[string]bool{}}
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
					state.memory[addrKey(x.Addr)] = tr
					b.rememberAggregateStore(state, x.Addr, tr)
				}
			case *ssa.MapUpdate:
				if tr, ok := b.summaryTaintOf(state, x.Value); ok {
					state.memory[addrKey(x.Map)+"[*]"] = tr
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
						for idx := range tr.params {
							changed = b.addParamReturn(fn, idx) || changed
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
	return dataFlowState{values: map[ssa.Value]dataFlowTrace{}, memory: map[string]dataFlowTrace{}, chans: map[string]dataFlowTrace{}, visiting: map[ssa.Value]bool{}}
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
		state.memory[addrKey(a.X)+"[*]"] = tr.withFieldPath("[*]")
	case *ssa.FieldAddr:
		state.memory[addrKey(a.X)+fmt.Sprintf(".field%d", a.Field)] = tr.withFieldPath(fmt.Sprintf("field%d", a.Field))
	}
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
				local := &dataFlowBuilder{analyzer: b.analyzer, out: localOut, patterns: b.patterns, regexps: b.regexps, summaries: b.summaries, endpoints: b.endpoints, dynamicCallees: b.dynamicCallees, nodeSeen: map[string]bool{}, edgeSeen: map[string]bool{}, sliceSeen: map[string]bool{}, diagnosticSeen: map[string]bool{}, sliceBudget: b.sliceBudget, maxSlices: b.maxSlices}
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
					state.memory[addrKey(x.Addr)] = tr
					b.rememberAggregateStore(state, x.Addr, tr)
				}
			case *ssa.MapUpdate:
				if tr, ok := b.taintOf(state, x.Value); ok {
					n := b.addNode("map-store", valueName(x.Map), valueSymbol(x.Map), valueType(x.Value), fn, x.Pos(), false, false, "", tr.taintKinds, "[*]", tr.confidence, nil)
					tr = b.connectTrace(tr, n, "map-store", x.Pos(), valueName(x.Map))
					state.memory[addrKey(x.Map)+"[*]"] = tr.withFieldPath("[*]")
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
					if tr, ok := b.valueTaint(state, v); ok {
						state.values[v] = tr
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
	for _, pat := range b.matchCall(common, b.patterns.Sources) {
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
	if b.shouldPropagate(common) {
		if tr, ok := b.combineCallArgTaints(state, common); ok {
			n := b.addNode("call", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), false, false, "", tr.taintKinds, "", tr.confidence, nil)
			state.values[call] = combineTraces(state.values[call], b.connectTrace(tr, n, "call-return", call.Pos(), callName(common)))
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
		pat := model.DataFlowPattern{Target: "sink", Kind: "builtin", Match: "exact", Pattern: "panic", Category: "panic", TaintKinds: []string{"user-input", "secret"}, Confidence: "medium"}
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
			if tr, ok := b.taintOf(state, arg); ok {
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
					pat := model.DataFlowPattern{Target: "sink", Kind: "function", Match: "exact", Pattern: callee.String(), Category: cat, Confidence: "medium"}
					b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, idx, fmt.Sprintf("Taint reaches %s sink in %s", edgeKind, callee.String()))
				}
			}
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
			if common.Value != nil && !common.IsInvoke() {
				return common.Value, true
			}
			return nil, false
		}
		argIndex := paramIndex - 1
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
		if tr, ok := b.taintOf(state, recv); ok && traceAllowsSink(tr, firstNonEmpty(pat.Category, "sink")) {
			b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, -1, "Taint reaches sink receiver")
		}
	}
}

func sinkArgumentRelevant(common *ssa.CallCommon, pat model.DataFlowPattern, idx int) bool {
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
	sink := b.addNode("sink", name, symbol, typ, fn, pos, false, true, pat.Category, mergeStrings(tr.taintKinds, taintsForPattern(pat)), "", firstNonEmpty(pat.Confidence, tr.confidence), map[string]string{"pattern": pat.Pattern})
	tr = b.connectTrace(tr, sink, "sink", pos, fmt.Sprint(argIndex))
	id := stableID("df-slice", sourceID, sink.ID, strings.Join(tr.edgeIDs, ":"), fmt.Sprint(argIndex))
	if b.sliceSeen[id] {
		b.sliceBudget.release()
		return
	}
	b.sliceSeen[id] = true
	b.out.Slices = append(b.out.Slices, model.DataFlowSlice{ID: id, SourceID: sourceID, SinkID: sink.ID, NodeIDs: orderedUniqueStrings(append(append([]string{}, tr.nodeIDs...), sink.ID)), EdgeIDs: orderedUniqueStrings(tr.edgeIDs), SourceCategory: tr.sourceCategory, SinkCategory: pat.Category, SourcePURL: tr.sourcePURL, SinkPURL: pat.PURL, SinkArgumentIndex: &idx, TaintKinds: uniqueStrings(mergeStrings(tr.taintKinds, taintsForPattern(pat))), FieldPaths: uniqueStrings(tr.fieldPaths), Confidence: firstNonEmpty(pat.Confidence, tr.confidence, "medium"), Description: summary})
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
			purl = modulePURL(mod)
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
		return tr
	}
	previousID := tr.nodeIDs[len(tr.nodeIDs)-1]
	id := stableID("df-edge", previousID, node.ID, kind, label, fmt.Sprint(b.analyzer.position(pos).Line))
	if !b.edgeSeen[id] {
		b.edgeSeen[id] = true
		b.out.Edges = append(b.out.Edges, model.DataFlowEdge{ID: id, SourceID: previousID, TargetID: node.ID, Kind: kind, Label: label, Position: b.analyzer.position(pos)})
	}
	tr.edgeIDs = appendLimitedUnique(tr.edgeIDs, id, maxTraceEdgeIDs)
	tr.nodeIDs = appendLimitedUnique(tr.nodeIDs, node.ID, maxTraceNodeIDs)
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
		}
		if x.Op == token.ARROW {
			if tr, ok := state.chans[addrKey(x.X)]; ok {
				return tr, true
			}
		}
		return b.taintOf(state, x.X)
	case *ssa.FieldAddr:
		if tr, ok := state.memory[addrKey(x)]; ok {
			return tr.withFieldPath(fmt.Sprintf("field%d", x.Field)), true
		}
		return b.taintOf(state, x.X)
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
		return b.taintOf(state, x.X)
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
			args := callArgs(common)
			var traces []dataFlowTrace
			for idx := range summary.paramReturn {
				if idx >= 0 && idx < len(args) {
					if tr, ok := b.taintOf(state, args[idx]); ok {
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
			args := callArgs(common)
			for paramIdx, cats := range summary.paramSink {
				if paramIdx < len(args) {
					if tr, ok := b.taintOf(state, args[paramIdx]); ok {
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
	s.model.ParamToReturn = append(s.model.ParamToReturn, model.DataFlowSummaryFlow{ParameterIndex: idx})
	sort.Slice(s.model.ParamToReturn, func(i, j int) bool {
		return s.model.ParamToReturn[i].ParameterIndex < s.model.ParamToReturn[j].ParameterIndex
	})
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
	p := callee.Pkg.Pkg.Path()
	return strings.HasPrefix(p, "strings") || strings.HasPrefix(p, "bytes") || strings.HasPrefix(p, "fmt") || strings.HasPrefix(p, "strconv") || strings.HasPrefix(p, "path") || strings.HasPrefix(p, "net/url")
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
	typeText := p.Type().String()
	name := strings.ToLower(p.Name())
	if strings.Contains(typeText, "net/http.Request") || strings.Contains(typeText, "gin.Context") || strings.Contains(typeText, "echo.Context") || strings.Contains(typeText, "fiber.Ctx") || strings.Contains(typeText, "context.Context") || name == "r" || name == "req" || name == "request" || name == "c" || name == "ctx" {
		return endpoints
	}
	return nil
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
	out := dataFlowTrace{nodeIDs: orderedUniqueLimit(append(a.nodeIDs, b.nodeIDs...), maxTraceNodeIDs), edgeIDs: orderedUniqueLimit(append(a.edgeIDs, b.edgeIDs...), maxTraceEdgeIDs), params: map[int]bool{}, taintKinds: uniqueStrings(append(a.taintKinds, b.taintKinds...)), fieldPaths: uniqueStrings(append(a.fieldPaths, b.fieldPaths...)), sanitizedCategories: uniqueStrings(append(a.sanitizedCategories, b.sanitizedCategories...)), sourceID: firstNonEmpty(a.sourceID, b.sourceID), sourceCategory: firstNonEmpty(a.sourceCategory, b.sourceCategory), sourcePURL: firstNonEmpty(a.sourcePURL, b.sourcePURL), sourcePatterns: append(append([]model.DataFlowPattern{}, a.sourcePatterns...), b.sourcePatterns...), confidence: firstNonEmpty(a.confidence, b.confidence, "medium"), generated: a.generated || b.generated}
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
			s.SinkPURL = firstNonEmpty(s.SinkPURL, sink.PURL)
			if s.SinkCategory == "" {
				s.SinkCategory = sink.Category
			}
		}
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
