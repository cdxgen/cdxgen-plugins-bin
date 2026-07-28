package seam

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"time"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	models_pkg "github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/models"
)

// Engine is the SEAM taint analysis engine.
type Engine struct {
	mode       string
	scope      string
	maxSlices  int
	fieldDepth int

	intraIterationCap int
	sccIterationCap   int
	maxPathLength     int

	models            *models_pkg.DB
	summaries         map[*ssa.Function]*FuncSummary
	summaryInProgress map[*ssa.Function]bool
	ifaceIdx          *InterfaceIndex

	globalTaint map[string]LabelSet

	nodes          []model.DataFlowNode
	edges          []model.DataFlowEdge
	slices         []model.DataFlowSlice
	nodeSeen       map[string]bool
	nodeByID       map[string]model.DataFlowNode
	edgeSeen       map[string]bool
	sliceSeen      map[string]bool
	diagnostics    []string
	unmodeledSinks map[string]int

	fset           *token.FileSet
	program        *ssa.Program
	allFuncs       []*ssa.Function
	callGraph      *callgraph.Graph
	dynamicCallees map[ssa.CallInstruction][]*ssa.Function
	// funcsByField resolves a call through a func-typed struct field. See
	// funcfield.go.
	funcsByField map[fieldFuncKey][]*ssa.Function

	// linknameAliases maps a body-less declaration to the function the linker
	// gives it, for //go:linkname. See SetLinknameAliases.
	linknameAliases map[*ssa.Function]*ssa.Function

	// calleeByCommon indexes dynamic callees by *ssa.CallCommon for O(1)
	// lookup in resolveFuncValueCallee. Without this index the function-value
	// resolution did a full scan of the callee map on every call instruction,
	// which was 78% of wall clock on prometheus/prometheus (463s of 594s).
	calleeByCommon map[*ssa.CallCommon][]*ssa.Function

	nextSeq int

	duringSummary bool

	moduleByPath  map[string]*model.Module
	packageByPath map[string]*packages.Package

	elapsed time.Duration
}

// Options configures a SEAM analysis run.
type Options struct {
	Mode         string
	Scope        string
	MaxSlices    int
	FieldDepth   int
	IntraIterCap int
	SCCIterCap   int
	TaintGlobals string
	AliasMode    string
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Mode:         "security",
		Scope:        "local",
		MaxSlices:    1000,
		FieldDepth:   4,
		IntraIterCap: 50,
		SCCIterCap:   20,
		TaintGlobals: "conservative",
		AliasMode:    "steensgaard",
	}
}

// NewEngine creates a new SEAM engine.
func NewEngine(opts Options) *Engine {
	e := &Engine{
		mode:              opts.Mode,
		scope:             opts.Scope,
		maxSlices:         opts.MaxSlices,
		fieldDepth:        opts.FieldDepth,
		intraIterationCap: opts.IntraIterCap,
		sccIterationCap:   opts.SCCIterCap,
		models:            models_pkg.NewDB(),
		summaries:         make(map[*ssa.Function]*FuncSummary),
		globalTaint:       make(map[string]LabelSet),
		nodeSeen:          make(map[string]bool),
		nodeByID:          make(map[string]model.DataFlowNode),
		edgeSeen:          make(map[string]bool),
		sliceSeen:         make(map[string]bool),
		unmodeledSinks:    make(map[string]int),
	}
	if e.intraIterationCap <= 0 {
		e.intraIterationCap = 50
	}
	if e.sccIterationCap <= 0 {
		e.sccIterationCap = 20
	}
	if e.fieldDepth <= 0 {
		e.fieldDepth = 4
	}
	if e.maxPathLength <= 0 {
		e.maxPathLength = 64
	}
	return e
}

// Analyze runs the full SEAM analysis and returns model.DataFlowEvidence.
func (e *Engine) Analyze(program *ssa.Program, pkgs []*packages.Package, cg *callgraph.Graph, dynamicCallees map[ssa.CallInstruction][]*ssa.Function, moduleByPath map[string]*model.Module, packageByPath map[string]*packages.Package, fset *token.FileSet) *model.DataFlowEvidence {
	started := time.Now()
	e.program = program
	e.callGraph = cg
	e.dynamicCallees = dynamicCallees
	e.calleeByCommon = make(map[*ssa.CallCommon][]*ssa.Function, len(dynamicCallees))
	for instr, callees := range dynamicCallees {
		if instr != nil && len(callees) > 0 {
			e.calleeByCommon[instr.Common()] = callees
		}
	}
	e.moduleByPath = moduleByPath
	e.packageByPath = packageByPath
	e.fset = fset

	if err := e.models.LoadBuiltins(); err != nil {
		e.diagnostics = append(e.diagnostics, fmt.Sprintf("models: %v", err))
	}

	e.allFuncs = e.collectFunctions(program, cg)
	e.ifaceIdx = NewInterfaceIndex(e.allFuncs, allPackages(pkgs))
	e.indexFieldFuncValues(e.allFuncs)
	e.allFuncs = e.withFieldCandidates(e.allFuncs)

	e.duringSummary = true
	e.computeSummaries(e.allFuncs, cg)
	e.duringSummary = false
	e.materializeSlices()

	out := &model.DataFlowEvidence{
		Engine:      "seam",
		Mode:        e.mode,
		Nodes:       e.nodes,
		Edges:       e.edges,
		Slices:      e.slices,
		Diagnostics: modelDiagnostics(e.diagnostics),
		Stats: model.DataFlowStats{
			NodeCount:     len(e.nodes),
			EdgeCount:     len(e.edges),
			SliceCount:    len(e.slices),
			SummaryCount:  len(e.summaries),
			FunctionCount: len(e.allFuncs),
			ElapsedMillis: int(time.Since(started).Milliseconds()),
		},
	}
	e.elapsed = time.Since(started)
	return out
}

// resolveCallTaint resolves the taint from a call instruction.
func (e *Engine) resolveCallTaint(caller *ssa.Function, common *ssa.CallCommon, argLabels LabelSet, recvLabels LabelSet, callPos token.Pos, argAt func(int) LabelSet) LabelSet {
	if common == nil {
		return NewLabelSet()
	}

	callee := e.throughLinkname(common.StaticCallee())

	// Interface dispatch: resolve through the implements-index and merge
	// summaries from every concrete implementation. This replaces the
	// name+signature string scan (defect 23).
	if callee == nil && common.IsInvoke() {
		if e.duringSummary {
			return recvLabels
		}
		return e.resolveInvokeTaint(caller, common, recvLabels, argAt, callPos)
	}

	// Func-value call through a struct field may reach a different function at
	// every call site, so the result's taint is the union over every
	// candidate, not the first one's. Taking only the first is what hid
	// go-test-bench's reflected-XSS route: the field holds one closure per
	// vulnerable route, and the XSS closure is the one that returns its
	// payload for the caller to write into the response.
	if callee == nil && !common.IsInvoke() {
		if candidates := e.fieldFuncCandidates(common); len(candidates) > 1 {
			var merged LabelSet
			for _, candidate := range candidates {
				merged = merged.Merge(e.resolveStaticCallTaint(caller, candidate, common, argLabels, recvLabels, callPos, argAt))
			}
			return merged
		}
	}

	// Func-value call: try MakeClosure first (common for anonymous functions),
	// then the dynamic callee index from the call graph.
	if callee == nil {
		callee = e.resolveFuncValueCallee(common)
		if callee == nil {
			// MakeClosure calls: the closure value carries binding taint.
			// Propagate it to the result so captured values reach the return.
			if common.Value != nil {
				if mc, ok := common.Value.(*ssa.MakeClosure); ok {
					return e.resolveClosureTaint(mc, common, argAt)
				}
			}
			return NewLabelSet()
		}
	}

	return e.resolveStaticCallTaint(caller, callee, common, argLabels, recvLabels, callPos, argAt)
}

// resolveStaticCallTaint handles a call with a known static callee.
func (e *Engine) resolveStaticCallTaint(caller *ssa.Function, callee *ssa.Function, common *ssa.CallCommon, argLabels LabelSet, recvLabels LabelSet, callPos token.Pos, argAt func(int) LabelSet) LabelSet {
	// A function can match several non-sink entries at once — cgo's
	// _Cfunc_GoString is simultaneously a passthrough (carrying the C-side
	// buffer's existing taint back into Go) and a source (a C-returned
	// buffer is untrusted input). When taint already reaches the call,
	// the passthrough carries that taint to the result and a fresh source
	// label would only describe the same data a second time, producing a
	// duplicate finding at every downstream sink. The legacy engine
	// enforces this by ordering passthroughs before sources and skipping
	// the latter once any taint propagated; the structured equivalent
	// here is the same: collect passthrough/sanitizer effects first, and
	// only introduce a source label when nothing was carried in.
	sourceEntries := e.models.MatchFunction(callee)
	var result LabelSet
	sanitizerFullStop := false
	propagated := false
	for _, entry := range sourceEntries {
		switch entry.Kind {
		case "passthrough":
			result = result.Merge(argLabels).Merge(recvLabels)
			propagated = true
		case "sanitizer":
			merged := argLabels.Merge(recvLabels)
			if len(entry.RemovesTaintKinds) > 0 {
				merged = merged.RemoveTaintKinds(entry.RemovesTaintKinds...)
			}
			if len(entry.SanitizesCategories) > 0 {
				merged = merged.AddSanitizedCategories(entry.SanitizesCategories...)
			}
			if merged.IsEmpty() {
				sanitizerFullStop = true
			}
			// Record the sanitizer as a hop so the report can show *where* a
			// path was cleaned. Removing the taint silently leaves a reader
			// unable to tell a sanitized path from one that was never
			// tainted, and it is the difference legacy's sanitizer nodes
			// carry in sanitizesCategories.
			merged = withStep(merged, e.sanitizerStep(caller, common, entry, callPos))
			result = result.Merge(merged)
			propagated = true
		}
	}
	for _, entry := range sourceEntries {
		if entry.Kind != "source" {
			continue
		}
		// Skip introducing a fresh source label when taint was already
		// propagated through this call: the data the source would describe
		// is the same data the passthrough already carries, and emitting
		// both labels doubles every downstream finding.
		if propagated && (!argLabels.IsEmpty() || !recvLabels.IsEmpty()) {
			continue
		}
		// During summary computation, do not introduce fresh source labels.
		// A summary tracks how parameter taint flows to returns and sinks;
		// a source label minted inside the body carries an unrelated identity
		// that the ParamReturn/ParamSink matcher (which keys on param-label
		// IDs) cannot recognise, so the effect is silently lost. This was the
		// cause of defect 31 on go-test-bench: GetParamValue calls
		// r.URL.Query(), whose net/url source model fired during summary
		// computation and replaced the param label with a source label,
		// leaving ParamReturn empty. Sources are introduced at materialisation
		// time, when the same model fires at the call site and taints the
		// result directly. Treating the call as a passthrough here (by falling
		// through to the summary / stdlib-propagate paths below) keeps the
		// param-to-return relationship intact.
		if e.duringSummary {
			// Keep the parameter relationship rather than discarding the
			// source outright. Suppressing it entirely was too strong: a
			// helper that wraps a source — util.GetCookie doing
			// `c, _ := r.Cookie(name); return c.Value` — then returns nothing
			// at all, and every caller of every such wrapper loses the flow.
			// Merging the incoming labels keeps ParamReturn intact while the
			// source label below still records what the call introduces.
			result = result.Merge(argLabels).Merge(recvLabels)
		}
		result = result.Add(e.newSourceLabel(caller, entry, callPos))
	}
	if !result.IsEmpty() || sanitizerFullStop {
		return result
	}

	// Check for summary, preferring the origin function for generics (defect 22).
	summary := e.summaryFor(callee)
	if summary != nil && (len(summary.ParamReturn) > 0 || len(summary.ParamSink) > 0 || len(summary.SourceReturns) > 0) {
		return e.applySummary(summary, common, recvLabels, argAt)
	}

	// Fallback: propagate for known stdlib carrier packages. Even when a
	// summary was computed, if it found no effects (common for methods whose
	// taint flows through internal state the summary can't capture), the
	// blanket carrier rule is more sound than dropping the taint entirely.
	if isStdlibPropagate(callee) {
		return argLabels.Merge(recvLabels)
	}

	// Record unmodeled.
	if len(callee.Blocks) == 0 {
		e.recordUnmodeledSink(callee.String())
	}

	return NewLabelSet()
}

// resolveInvokeTaint resolves taint through an interface dispatch site by
// consulting the implements-index and merging summaries from all concrete
// implementations.
//
// The interface method itself may have a model entry (the `error.Error`
// passthrough, the `context.Context.Value` passthrough). Those entries
// describe the contract every implementation shares, so they apply whether
// or not the concrete type carrying the value has its own matching model —
// which it almost never does, because the implementations of an interface
// are an open set. Without this lookup, every flow that crosses an interface
// method silently dies at the invoke site even when the model is precise.
func (e *Engine) resolveInvokeTaint(caller *ssa.Function, common *ssa.CallCommon, recvLabels LabelSet, argAt func(int) LabelSet, callPos token.Pos) LabelSet {
	if e.ifaceIdx == nil {
		return NewLabelSet()
	}
	var result LabelSet

	// Apply the interface method's own model entries first. These describe
	// the contract, not any specific implementation.
	if entries := e.models.MatchSymbol(common.Method); len(entries) > 0 {
		for _, entry := range entries {
			switch entry.Kind {
			case "source":
				result = result.Add(e.newSourceLabel(caller, entry, callPos))
			case "passthrough":
				if argAt != nil {
					for i := 0; i < len(common.Args); i++ {
						result = result.Merge(argAt(i))
					}
				}
				result = result.Merge(recvLabels)
			case "sanitizer":
				if argAt != nil {
					for i := 0; i < len(common.Args); i++ {
						result = result.Merge(argAt(i))
					}
				}
				result = result.Merge(recvLabels)
				if len(entry.RemovesTaintKinds) > 0 {
					result = result.RemoveTaintKinds(entry.RemovesTaintKinds...)
				}
				if len(entry.SanitizesCategories) > 0 {
					result = result.AddSanitizedCategories(entry.SanitizesCategories...)
				}
			}
		}
	}

	impls := e.ifaceIdx.LookupInterfaceCall(common)
	if len(impls) == 0 {
		return result
	}
	for _, impl := range impls {
		// Check models for each implementation.
		entries := e.models.MatchFunction(impl)
		for _, entry := range entries {
			switch entry.Kind {
			case "source":
				result = result.Add(e.newSourceLabel(caller, entry, callPos))
			case "passthrough":
				if argAt != nil {
					for i := 0; i < len(common.Args); i++ {
						result = result.Merge(argAt(i))
					}
				}
				result = result.Merge(recvLabels)
			case "sanitizer":
				if argAt != nil {
					for i := 0; i < len(common.Args); i++ {
						result = result.Merge(argAt(i))
					}
				}
				result = result.Merge(recvLabels)
				// sanitizer entries already applied above; skip summary for this impl
				continue
			}
		}
		summary := e.summaryFor(impl)
		if summary != nil {
			result = result.Merge(e.applySummary(summary, common, recvLabels, argAt))
		}
	}
	return result
}

// resolveFuncValueCallee attempts to resolve a func-value call through the
// dynamic callee index built from the call graph.
func (e *Engine) resolveFuncValueCallee(common *ssa.CallCommon) *ssa.Function {
	if callees := e.calleeByCommon[common]; len(callees) > 0 {
		return callees[0]
	}
	if candidates := e.fieldFuncCandidates(common); len(candidates) > 0 {
		return candidates[0]
	}
	return nil
}

// resolveClosureTaint handles a call through a MakeClosure value. The closure's
// bindings' taint is propagated to the call result, and the closure function's
// summary (if available) maps FreeVars to returns.
func (e *Engine) resolveClosureTaint(mc *ssa.MakeClosure, common *ssa.CallCommon, argAt func(int) LabelSet) LabelSet {
	fn := mc.Fn.(*ssa.Function)
	// The closure value itself carries merged binding taint (from evaluate).
	// Build an argAt that maps FreeVar positions to their binding taint.
	freeVarAt := func(i int) LabelSet {
		if i < 0 || i >= len(mc.Bindings) {
			return LabelSet{}
		}
		return argAt(i)
	}
	// Try the closure function's summary first.
	summary := e.summaryFor(fn)
	if summary != nil {
		return e.applySummary(summary, common, LabelSet{}, freeVarAt)
	}
	// Fallback: just merge all binding taint (over-approximate).
	var result LabelSet
	for i := range mc.Bindings {
		result = result.Merge(freeVarAt(i))
	}
	return result
}

// applySummary maps a callee's summary onto a call site.
//
// The parameter-to-return effects are resolved against the caller's actual
// arguments, which is the whole point of a summary: without the caller's
// argument taint there is nothing to carry across the call, and every
// interprocedural flow silently disappears.
func (e *Engine) applySummary(summary *FuncSummary, common *ssa.CallCommon, recvLabels LabelSet, argAt func(int) LabelSet) LabelSet {
	var result LabelSet
	for _, pattern := range summary.SourceReturns {
		sourceID := stableID("seam-source", summary.FuncID, pattern.Category, pattern.Pattern)
		result = result.Add(TaintLabel{
			ID:             NewLabelID(sourceID, 0),
			SourceID:       sourceID,
			SourceNode:     &Step{Kind: "source", EdgeKind: "source", Name: pattern.Pattern, Symbol: summary.FuncID, FunctionID: summary.FuncID},
			SourceCategory: pattern.Category,
			SourcePatterns: []SourcePattern{pattern},
			TaintKinds:     pattern.TaintKinds,
			Confidence:     firstNonEmptyStr(pattern.Confidence, "medium"),
			Provenance:     "summary-source-return",
			Generated:      true,
		})
	}
	if argAt == nil {
		return result
	}
	hasReceiver := summary.HasReceiver()
	for paramIdx := range summary.ParamReturn {
		if hasReceiver && paramIdx == 0 {
			if common.IsInvoke() {
				result = result.Merge(recvLabels)
				continue
			}
			// A method call on a concrete receiver passes it as argument zero.
			result = result.Merge(argAt(0))
			continue
		}
		argIdx := paramIdx
		if hasReceiver && common.IsInvoke() {
			argIdx = paramIdx - 1
		}
		result = result.Merge(argAt(argIdx))
	}
	return result
}

// materializeSlices analyses every in-scope function and emits its findings.
// For globals, multiple passes may be needed: a function that writes a global
// must be analysed before a function that reads it. We iterate until the
// global taint map stabilises.
func (e *Engine) materializeSlices() {
	prevGlobalCount := -1
	for pass := 0; pass < 3; pass++ {
		e.slices = e.slices[:0]
		e.sliceSeen = map[string]bool{}
		for _, fn := range e.allFuncs {
			if !e.shouldMaterialize(fn) {
				continue
			}
			if len(e.slices) >= e.maxSlices {
				e.addDiagnostic(fmt.Sprintf("slice limit reached at %d; further findings were not materialised", e.maxSlices))
				return
			}
			e.materializeFunction(fn)
		}
		curCount := len(e.globalTaint)
		if curCount == prevGlobalCount {
			break
		}
		prevGlobalCount = curCount
	}
}

// shouldMaterialize reports whether slices should be emitted for this function.
func (e *Engine) shouldMaterialize(fn *ssa.Function) bool {
	if fn == nil || len(fn.Blocks) == 0 || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	return e.inScope(fn)
}

// materializeFunction runs the fixpoint once and emits the sinks it found.
//
// The analysis result is used directly. Running an analysis and then throwing
// its state away to re-derive sinks in a second, non-iterating pass would
// reintroduce exactly the unsoundness the fixpoint exists to remove.
func (e *Engine) materializeFunction(fn *ssa.Function) {
	analysis := newIntra(e, fn)
	analysis.run(e.paramSourceLabels(fn))
	for _, diagnostic := range analysis.diagnostics {
		e.addDiagnostic(diagnostic)
	}
	for _, hit := range analysis.sinks {
		if len(e.slices) >= e.maxSlices {
			return
		}
		e.emitSlice(hit)
	}
}

// paramSourceLabels seeds parameters that a type-based source model matches,
// such as the *http.Request handed to a handler.
func (e *Engine) paramSourceLabels(fn *ssa.Function) []LabelSet {
	out := make([]LabelSet, len(fn.Params))
	for i, param := range fn.Params {
		entries := e.models.MatchParameterType(param.Type())
		// A parameter's *name* is the other evidence available here. In a
		// library whose callers are outside the analysed module there is no
		// call site to read taint from, so a parameter called "cmd" or
		// "password" is the only thing marking the entry point. Legacy has
		// had this as a regex source pattern since the beginning; without it
		// SEAM reported no parameter-sourced flow at all, which on
		// urfave/cli was 23 of the 139 flows legacy found.
		entries = append(entries, e.models.MatchParameterName(param.Name())...)
		for _, entry := range entries {
			if entry.Kind != "source" {
				continue
			}
			label := e.newSourceLabel(fn, entry, param.Pos())
			// A type-shaped model has no function to name, so the node would
			// otherwise carry an empty name and type. The tainted thing here
			// is the parameter itself; naming it is what lets a reader see
			// which argument the flow started from.
			if label.SourceNode != nil {
				label.SourceNode.Name = param.Name()
				label.SourceNode.Type = param.Type().String()
			}
			out[i] = out[i].Add(label)
		}
	}
	return out
}

// emitSlice turns one sink hit into a report slice, registering every node and
// edge the slice refers to.
func (e *Engine) emitSlice(hit sinkHit) {
	entry := hit.entry
	sinkSymbol := callSymbolOf(hit.common)
	sinkName := callDisplayName(hit.common)
	sinkType := callResultType(hit.common)
	if hit.common == nil {
		// A builtin sink such as panic is an instruction, not a call, so
		// there is no CallCommon to name it from. The model entry is the only
		// description available, and SinkSymbol is a published field that
		// must not be empty.
		sinkSymbol = hit.entry.Function
		sinkName = hit.entry.Function
	}
	// For a summary-derived sink, the call site (hit.common) is the indirect
	// dispatch through which taint reached the callee; the real sink — the
	// os/exec.Command, os.ReadFile, http.Get the reader must act on — lives
	// inside the callee and is recorded in the summary effect. Naming the
	// dispatch site instead leaves the slice pointing at an opaque temp call
	// no matcher or reader can recognise, which is why every go-test-bench
	// route was found-but-rejected (defect 31).
	if hit.summarySink != nil {
		if hit.summarySink.SinkSymbol != "" {
			sinkSymbol = hit.summarySink.SinkSymbol
		}
		if hit.summarySink.SinkName != "" {
			sinkName = hit.summarySink.SinkName
		}
		if hit.summarySink.SinkType != "" {
			sinkType = hit.summarySink.SinkType
		}
	}
	// The slice's identity is the finding it describes, not the route by
	// which the analysis discovered it. The same call site can fire both
	// checkSinks (because the callee is itself a modelled sink, like
	// database/sql.DB.Query) and checkSummarySinks (because the callee's
	// body reaches a different sink, like QueryContext, recorded in its
	// summary). Both describe the same user-visible finding — tainted data
	// reaches this call — and emitting it twice costs precision without
	// adding information. Keying on the call position rather than the
	// route-specific sink node makes the deduplication deterministic.
	sinkPos := hit.pos
	sliceID := stableID("seam-slice", hit.label.SourceID, e.positionKey(sinkPos), sinkSymbol, fmt.Sprint(hit.argIndex), entry.Category)
	if e.sliceSeen[sliceID] {
		return
	}
	// For summary-derived sinks (interprocedural), the sink is inside the
	// callee. Register the node under the callee's function context so the
	// slice correctly reflects which module the sink lives in.
	sinkFn := hit.fn
	if hit.summarySinkFn != nil {
		sinkFn = hit.summarySinkFn
		// The summary effect carries the real sink's source position (e.g.
		// the line of the exec.Command call inside execHandler), which is
		// what a reader needs to locate the vulnerability.
		if hit.summarySink != nil && hit.summarySink.Pos.IsValid() {
			sinkPos = hit.summarySink.Pos
		}
	}
	sinkNode := e.addNode("sink", sinkName, sinkSymbol, sinkType, sinkFn, sinkPos,
		false, true, entry.Category, mergeStrings(hit.label.TaintKinds, entry.TaintKinds), "",
		firstNonEmptyStr(entry.Confidence, hit.label.Confidence, "medium"),
		map[string]string{"model": entry.ID})

	nodeIDs, edgeIDs, edgeKinds, truncated := e.registerPath(hit.label, sinkNode.ID)
	nodeIDs = append(nodeIDs, sinkNode.ID)
	if last := len(nodeIDs) - 2; last >= 0 {
		if edgeID := e.addEdge(nodeIDs[last], sinkNode.ID, "sink", hit.pos); edgeID != "" {
			edgeIDs = append(edgeIDs, edgeID)
			edgeKinds = append(edgeKinds, "sink")
		}
	}

	argIndex := hit.argIndex
	sourceNode, _ := e.sourceNodeFor(hit.label)
	slice := model.DataFlowSlice{
		ID:                sliceID,
		SourceID:          hit.label.SourceID,
		SinkID:            sinkNode.ID,
		NodeIDs:           nodeIDs,
		EdgeIDs:           edgeIDs,
		EdgeKinds:         edgeKinds,
		SourceCategory:    hit.label.SourceCategory,
		SinkCategory:      entry.Category,
		SourceName:        sourceNode.Name,
		SourceSymbol:      sourceNode.Symbol,
		SourceFunction:    sourceNode.Function,
		SourcePackagePath: sourceNode.PackagePath,
		SourcePURL:        sourceNode.PURL,
		SinkName:          sinkNode.Name,
		SinkSymbol:        sinkSymbol,
		SinkFunction:      hit.fn.String(),
		SinkPackagePath:   sinkNode.PackagePath,
		SinkPURL:          sinkNode.PURL,
		PURLs:             uniqueStringsSorted([]string{sourceNode.PURL, sinkNode.PURL}),
		SinkArgumentIndex: &argIndex,
		TaintKinds:        mergeStrings(hit.label.TaintKinds, entry.TaintKinds),
		FieldPaths:        hit.label.FieldPaths,
		RuleID:            entry.RuleID,
		RuleName:          entry.RuleName,
		Severity:          entry.Severity,
		RiskScore:         entry.RiskScore,
		Confidence:        firstNonEmptyStr(entry.Confidence, hit.label.Confidence, "medium"),
		PathLength:        len(edgeIDs),
		Description:       fmt.Sprintf("%s reaches %s", firstNonEmptyStr(hit.label.SourceCategory, "tainted value"), sinkSymbol),
	}
	if truncated {
		slice.Properties = setProperty(slice.Properties, "pathTruncated", "true")
	}
	if hit.label.CrossesDependency {
		slice.CrossesDependency = true
		slice.DependencyHops = hit.label.DependencyHops
	}
	if e.sliceSeen[slice.ID] {
		return
	}
	e.sliceSeen[slice.ID] = true
	e.slices = append(e.slices, slice)
}

// registerPath materialises the source node and every hop of a label's route,
// returning the node and edge identifiers in source-to-sink order.
//
// Registration happens here, at emission, rather than while taint propagates:
// only routes that actually reach a sink become report nodes, so the report
// contains no unreferenced nodes and — because the same walk produces both the
// nodes and the identifiers naming them — no slice can reference a node the
// report does not define.
func (e *Engine) registerPath(label TaintLabel, sinkNodeID string) (nodeIDs, edgeIDs, edgeKinds []string, truncated bool) {
	sourceNode, ok := e.sourceNodeFor(label)
	if !ok {
		return nil, nil, nil, false
	}
	nodeIDs = append(nodeIDs, sourceNode.ID)
	previous := sourceNode.ID

	steps := label.Steps()
	if e.maxPathLength > 0 && len(steps) > e.maxPathLength {
		// Keep both ends and mark the slice, never silently drop the source.
		steps = append(append([]*Step{}, steps[:e.maxPathLength-1]...), steps[len(steps)-1])
		truncated = true
	}
	for _, step := range steps {
		node := e.addNodeForStep(step)
		if node.ID == "" || node.ID == previous || node.ID == sinkNodeID {
			continue
		}
		if edgeID := e.addEdge(previous, node.ID, step.EdgeKind, step.Pos); edgeID != "" {
			edgeIDs = append(edgeIDs, edgeID)
			edgeKinds = append(edgeKinds, step.EdgeKind)
		}
		nodeIDs = append(nodeIDs, node.ID)
		previous = node.ID
	}
	return nodeIDs, edgeIDs, edgeKinds, truncated
}

// sourceNodeFor registers and returns the report node for a label's source.
func (e *Engine) sourceNodeFor(label TaintLabel) (model.DataFlowNode, bool) {
	if label.SourceID == "" {
		return model.DataFlowNode{}, false
	}
	if node, ok := e.nodeByID[label.SourceID]; ok {
		return node, true
	}
	descriptor := label.SourceNode
	if descriptor == nil {
		return model.DataFlowNode{}, false
	}
	confidence := firstNonEmptyStr(label.Confidence, "high")
	node := e.addNodeWithID(label.SourceID, "source", descriptor.Name, descriptor.Symbol, descriptor.Type,
		descriptor.FunctionID, descriptor.PackagePath, descriptor.Pos, true, false,
		label.SourceCategory, label.TaintKinds, "", confidence, nil)
	return node, node.ID != ""
}

// addNodeForStep registers the report node described by one hop.
func (e *Engine) addNodeForStep(step *Step) model.DataFlowNode {
	if step == nil {
		return model.DataFlowNode{}
	}
	return e.addNodeWithID(step.NodeID(e.positionKey(step.Pos)), step.Kind, step.Name, step.Symbol, step.Type,
		step.FunctionID, step.PackagePath, step.Pos, false, false, "", nil, step.FieldPath, "medium", step.Properties)
}

// addEdge registers an edge between two nodes and returns its identifier.
func (e *Engine) addEdge(sourceID, targetID, kind string, pos token.Pos) string {
	if sourceID == "" || targetID == "" || sourceID == targetID {
		return ""
	}
	id := stableID("seam-edge", sourceID, targetID, kind)
	if !e.edgeSeen[id] {
		e.edgeSeen[id] = true
		e.edges = append(e.edges, model.DataFlowEdge{
			ID: id, SourceID: sourceID, TargetID: targetID, Kind: kind, Position: e.position(pos),
		})
	}
	return id
}

func setProperty(props map[string]string, key, value string) map[string]string {
	if props == nil {
		props = map[string]string{}
	}
	props[key] = value
	return props
}

// addNode registers a node whose identity is derived from its position.
func (e *Engine) addNode(kind, name, symbol, typ string, fn *ssa.Function, pos token.Pos, source, sink bool, category string, taints []string, fieldPath, confidence string, props map[string]string) model.DataFlowNode {
	fnID, pkgPath := "", ""
	if fn != nil {
		fnID = fn.String()
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			pkgPath = fn.Pkg.Pkg.Path()
		}
	}
	id := stableID("seam-node", kind, fnID, symbol, name, fieldPath, e.positionKey(pos), category)
	return e.addNodeWithID(id, kind, name, symbol, typ, fnID, pkgPath, pos, source, sink, category, taints, fieldPath, confidence, props)
}

func (e *Engine) recordUnmodeledSink(symbol string) {
	e.unmodeledSinks[symbol]++
}

// collectNestedFunctions finds anonymous functions created by MakeClosure
// instructions within a function's SSA, and adds them to the collection.
// These are not package members and would be missed by the member scan.
func (e *Engine) collectNestedFunctions(fn *ssa.Function, all map[*ssa.Function]bool, seeds *[]*ssa.Function) {
	if fn == nil || len(fn.Blocks) == 0 {
		return
	}
	for _, block := range fn.Blocks {
		if block == nil {
			continue
		}
		for _, instr := range block.Instrs {
			if mc, ok := instr.(*ssa.MakeClosure); ok {
				if closureFn, ok := mc.Fn.(*ssa.Function); ok && !all[closureFn] {
					all[closureFn] = true
					if e.inScope(closureFn) {
						*seeds = append(*seeds, closureFn)
					}
					e.collectNestedFunctions(closureFn, all, seeds)
				}
			}
			// Collect anonymous functions referenced as operands without a
			// MakeClosure wrapper. A closure with no captured variables is a
			// plain *ssa.Function value (commonly wrapped in ChangeType for
			// http.HandlerFunc conversion); MakeClosure is only emitted when
			// the closure has free variables. Without this scan, every
			// capture-free handler closure — the common case for HTTP handlers
			// registered as func(w, r) literals — is invisible to the engine.
			for _, op := range instr.Operands(nil) {
				if op == nil || *op == nil {
					continue
				}
				if closureFn, ok := (*op).(*ssa.Function); ok && !all[closureFn] && isAnonymousFunction(closureFn) {
					all[closureFn] = true
					if e.inScope(closureFn) {
						*seeds = append(*seeds, closureFn)
					}
					e.collectNestedFunctions(closureFn, all, seeds)
				}
			}
		}
	}
}

// isAnonymousFunction reports whether fn is an anonymous function (a closure
// literal), as opposed to a named package-level function or method. Anonymous
// SSA functions have a $N suffix in their name and a non-nil Parent().
func isAnonymousFunction(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	return fn.Parent() != nil || strings.Contains(fn.Name(), "$")
}

func (e *Engine) moduleForPackagePath(pkgPath string) *model.Module {
	if e.moduleByPath != nil {
		if mod, ok := e.moduleByPath[pkgPath]; ok {
			return mod
		}
	}
	var best *model.Module
	for path, mod := range e.moduleByPath {
		if mod == nil || mod.Path == "" {
			continue
		}
		if pkgPath == mod.Path || strings.HasPrefix(pkgPath, mod.Path+"/") {
			if best == nil || len(mod.Path) > len(best.Path) {
				best = mod
			}
		}
		_ = path
	}
	return best
}

// collectPackageMethods collects methods on named types declared in pkg.
// Methods are not package-level SSA members — they are created lazily by the
// SSA builder and resolved through types.MethodSet. Without this scan, every
// method body (http.Handler.ServeHTTP, (*bytes.Buffer).WriteString,
// (*DefaultLogFormatter).NewLogEntry, …) is invisible to both summary
// computation and materialisation, which is what made go-chi/chi's middleware
// flows disappear: the request reaches the sink inside a method that was never
// collected.
func (e *Engine) collectPackageMethods(program *ssa.Program, pkg *ssa.Package, all map[*ssa.Function]bool, seeds *[]*ssa.Function) {
	if pkg == nil || pkg.Pkg == nil {
		return
	}
	scope := pkg.Pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		typeName, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := typeName.Type().(*types.Named)
		if !ok {
			continue
		}
		// Value-receiver and pointer-receiver methods live in distinct
		// method sets; both must be scanned.
		for _, recv := range []types.Type{named, types.NewPointer(named)} {
			ms := types.NewMethodSet(recv)
			for i := 0; i < ms.Len(); i++ {
				fnObj, ok := ms.At(i).Obj().(*types.Func)
				if !ok {
					continue
				}
				fn := program.FuncValue(fnObj)
				if fn == nil || all[fn] {
					continue
				}
				all[fn] = true
				if e.inScope(fn) {
					*seeds = append(*seeds, fn)
				}
				e.collectNestedFunctions(fn, all, seeds)
			}
		}
	}
}

// collectFunctions returns the functions the engine will summarise: everything
// in scope, plus everything in-scope code can transitively reach through
// non-stdlib code. Stdlib functions directly called from local or dependency
// code are included (so their summaries can be consulted) but their own callees
// are not expanded further — the isStdlibPropagate heuristic handles carriers,
// and expanding the entire standard library's call graph costs far more than
// the precision it buys.
func (e *Engine) collectFunctions(program *ssa.Program, cg *callgraph.Graph) []*ssa.Function {
	if program == nil {
		return nil
	}
	var seeds []*ssa.Function
	all := map[*ssa.Function]bool{}
	for _, pkg := range program.AllPackages() {
		if pkg == nil {
			continue
		}
		// Collect package-level functions (Members) and methods on named
		// types. Methods are not package members in SSA; they are created
		// lazily and must be resolved through the type information. Without
		// this, every method on a named type — the overwhelming majority of
		// Go's method-based dispatch, including (*DefaultLogFormatter).NewLogEntry,
		// (*defaultLogEntry).Write, and every http.Handler.ServeHTTP — is
		// invisible to the engine.
		e.collectPackageMethods(program, pkg, all, &seeds)
		for _, member := range pkg.Members {
			fn, ok := member.(*ssa.Function)
			if !ok || fn == nil || all[fn] {
				continue
			}
			all[fn] = true
			if e.inScope(fn) {
				seeds = append(seeds, fn)
			}
			e.collectNestedFunctions(fn, all, &seeds)
		}
	}
	if e.scope == "all" || cg == nil {
		funcs := make([]*ssa.Function, 0, len(all))
		for fn := range all {
			funcs = append(funcs, fn)
		}
		sortFunctions(funcs)
		return funcs
	}

	reachable := map[*ssa.Function]bool{}
	queue := append([]*ssa.Function{}, seeds...)
	for _, fn := range seeds {
		reachable[fn] = true
	}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		node := cg.Nodes[fn]
		if node == nil {
			continue
		}
		fnIsStdlib := fn.Pkg != nil && fn.Pkg.Pkg != nil && isStandardPackagePath(fn.Pkg.Pkg.Path())
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			callee := edge.Callee.Func
			if reachable[callee] {
				continue
			}
			reachable[callee] = true
			// Don't expand callees of stdlib functions: their internal call
			// chains pull in thousands of functions for negligible precision
			// gain. Stdlib carriers are handled by isStdlibPropagate.
			if !fnIsStdlib {
				queue = append(queue, callee)
			}
		}
	}
	funcs := make([]*ssa.Function, 0, len(reachable))
	for fn := range reachable {
		funcs = append(funcs, fn)
	}
	sortFunctions(funcs)
	return funcs
}

// inScope reports whether a finding in this function is worth materialising.
//
// This is the materialisation half of the two-tier policy: summaries are always
// computed for the whole reachable program, and this decides where a slice is
// reported. The standard library is excluded by default - a finding inside fmt
// or bufio names a function the user did not write and cannot change - but a
// dependency is reported only under a wider scope, because a flow contained
// entirely within a library, with no local frame on its route, is not something
// the reader can act on from here.
//
// The scopes are: local (the main module), dependencies (and everything it
// imports bar the standard library), all (the standard library too). Nothing
// materialises inside the standard library by default: doing so on this corpus
// produced ten findings per fixture inside net/http and fmt, halving precision
// and costing six times the wall clock, for flows in code the user did not
// write.
//
// A package with no module information must not be treated as local: that was
// true of every dependency package until module attribution covered the
// transitive graph, and it made dependency-internal flows look like local ones.
func (e *Engine) inScope(fn *ssa.Function) bool {
	if fn == nil || len(fn.Blocks) == 0 || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	pkgPath := fn.Pkg.Pkg.Path()
	if isStandardPackagePath(pkgPath) {
		return e.scope == "all"
	}
	mod := e.moduleForPackagePath(pkgPath)
	switch e.scope {
	case "all", "dependencies":
		return true
	case "workspace":
		return mod == nil || mod.Main || isWorkspacePkg(pkgPath)
	default:
		return mod == nil || mod.Main
	}
}

// isStandardPackagePath reports whether a package path names a standard library
// package. Standard paths have no dot in their first segment.
func isStandardPackagePath(pkgPath string) bool {
	if pkgPath == "" {
		return false
	}
	first := pkgPath
	if i := strings.IndexByte(pkgPath, '/'); i >= 0 {
		first = pkgPath[:i]
	}
	return !strings.Contains(first, ".")
}

func sortFunctions(funcs []*ssa.Function) {
	sort.Slice(funcs, func(i, j int) bool { return funcs[i].String() < funcs[j].String() })
}

func allPackages(pkgs []*packages.Package) []*types.Package {
	var out []*types.Package
	seen := make(map[string]bool)
	for _, pkg := range pkgs {
		if pkg == nil || pkg.Types == nil {
			continue
		}
		if seen[pkg.PkgPath] {
			continue
		}
		seen[pkg.PkgPath] = true
		out = append(out, pkg.Types)
	}
	return out
}

func isStdlibPropagate(fn *ssa.Function) bool {
	if fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	p := fn.Pkg.Pkg.Path()
	return strings.HasPrefix(p, "strings") || strings.HasPrefix(p, "bytes") ||
		strings.HasPrefix(p, "fmt") || strings.HasPrefix(p, "strconv") ||
		strings.HasPrefix(p, "path") || strings.HasPrefix(p, "net/url") ||
		strings.HasPrefix(p, "io") || strings.HasPrefix(p, "bufio") ||
		strings.HasPrefix(p, "encoding") || strings.HasPrefix(p, "context") ||
		strings.HasPrefix(p, "reflect")
}

func isWorkspacePkg(path string) bool {
	return !strings.Contains(path, "/vendor/") && !strings.Contains(path, "/.cache/")
}

func callSite(common *ssa.CallCommon) ssa.CallInstruction {
	return nil
}

func labelContainsAnyKind(label TaintLabel, kinds []string) bool {
	for _, k := range label.TaintKinds {
		for _, match := range kinds {
			if strings.EqualFold(k, match) {
				return true
			}
		}
	}
	return false
}

func packagePURL(pkgPath string, mod *model.Module) string {
	if pkgPath == "" {
		return ""
	}
	if mod != nil && mod.Path != "" {
		return "pkg:golang/" + mod.Path
	}
	return "pkg:golang/" + pkgPath
}

func modelDiagnostics(diags []string) []model.Diagnostic {
	out := make([]model.Diagnostic, len(diags))
	for i, d := range diags {
		out[i] = model.Diagnostic{Kind: "seam", Message: d}
	}
	return out
}

func (e *Engine) UnmodeledSinks() map[string]int { return e.unmodeledSinks }
func (e *Engine) MatchedModels() []string        { return e.models.UnmatchedSymbols() }
func (e *Engine) AllFuncs() int                  { return len(e.allFuncs) }

// MaterializedFuncs returns the number of functions that were materialised
// (had slices emitted for them), for diagnostics.
func (e *Engine) MaterializedFuncs() int {
	count := 0
	for _, fn := range e.allFuncs {
		if e.shouldMaterialize(fn) {
			count++
		}
	}
	return count
}

// SummaryCount returns the number of summaries computed.
func (e *Engine) SummaryCount() int { return len(e.summaries) }

// sanitizerStep builds the report hop for an applied sanitizer.
func (e *Engine) sanitizerStep(caller *ssa.Function, common *ssa.CallCommon, entry models_pkg.ModelEntry, pos token.Pos) *Step {
	pkgPath, fnID := "", ""
	if caller != nil {
		fnID = caller.String()
		if caller.Pkg != nil && caller.Pkg.Pkg != nil {
			pkgPath = caller.Pkg.Pkg.Path()
		}
	}
	props := map[string]string{}
	if len(entry.SanitizesCategories) > 0 {
		props["sanitizesCategories"] = strings.Join(entry.SanitizesCategories, ",")
	}
	if len(entry.RemovesTaintKinds) > 0 {
		props["removesTaintKinds"] = strings.Join(entry.RemovesTaintKinds, ",")
	}
	if entry.Category != "" {
		props["sanitizerCategory"] = entry.Category
	}
	return &Step{
		Kind: "sanitizer", EdgeKind: "sanitize",
		Name: callDisplayName(common), Symbol: callSymbolOf(common), Type: callResultType(common),
		FunctionID: fnID, PackagePath: pkgPath, Pos: pos, Properties: props,
	}
}

// SetLinknameAliases records the //go:linkname mapping from a body-less local
// declaration to the function that actually implements it.
//
// A pull linkname is invisible to both the type checker and SSA: the local
// declaration has no body, so a call to it leads into nothing and taint stops
// there. The call graph already draws the alias edge from the directive; this
// gives the data-flow engine the same information, so a flow can cross it.
func (e *Engine) SetLinknameAliases(aliases map[*ssa.Function]*ssa.Function) {
	e.linknameAliases = aliases
}

// throughLinkname follows a body-less declaration to its linkname target.
// Functions that have a body, and those with no directive, are returned
// unchanged.
func (e *Engine) throughLinkname(fn *ssa.Function) *ssa.Function {
	if fn == nil || len(fn.Blocks) > 0 || len(e.linknameAliases) == 0 {
		return fn
	}
	if target, ok := e.linknameAliases[fn]; ok && target != nil {
		return target
	}
	return fn
}
