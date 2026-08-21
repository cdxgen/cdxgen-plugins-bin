package seam

import (
	"fmt"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// sccNode is a node in the call graph used for Tarjan's SCC algorithm.
type sccNode struct {
	fn      *ssa.Function
	index   int
	low     int
	onStack bool
}

// tarjanSCC computes strongly connected components of the call graph.
// Returns SCCs in reverse topological order (leaves first) and the adjacency
// map used to build them, so callers can check for self-edges.
func tarjanSCC(cg *callgraph.Graph, funcs []*ssa.Function) ([][]*ssa.Function, map[*ssa.Function][]*ssa.Function) {
	return tarjanSCCWithFieldEdges(cg, funcs, nil)
}

// tarjanSCCWithFieldEdges is tarjanSCC augmented with edges from indirect
// (func-field) dispatch, which the static call graph does not carry. Without
// these edges the SCC condensation cannot see that a dispatcher (e.g.
// GenericHandler$1 calling through Sink.VulnerableFnWrapper) depends on its
// candidates (osReadFile, osOpen, …), so it may summarise the dispatcher first
// — when every candidate's ParamSink is still empty — and silently lose every
// interprocedural sink behind the dispatch (defect 31).
func tarjanSCCWithFieldEdges(cg *callgraph.Graph, funcs []*ssa.Function, fieldEdges map[*ssa.Function][]*ssa.Function) ([][]*ssa.Function, map[*ssa.Function][]*ssa.Function) {
	if (cg == nil && fieldEdges == nil) || len(funcs) == 0 {
		return nil, nil
	}

	funcToNode := make(map[*ssa.Function]*callgraph.Node)
	if cg != nil {
		for _, node := range cg.Nodes {
			if node != nil && node.Func != nil {
				funcToNode[node.Func] = node
			}
		}
	}

	inSet := make(map[*ssa.Function]bool, len(funcs))
	for _, fn := range funcs {
		inSet[fn] = true
	}

	adj := make(map[*ssa.Function][]*ssa.Function)
	for _, fn := range funcs {
		adj[fn] = nil
	}
	for _, fn := range funcs {
		seen := make(map[*ssa.Function]bool)
		node := funcToNode[fn]
		if node != nil {
			for _, edge := range node.Out {
				if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
					continue
				}
				callee := edge.Callee.Func
				if !inSet[callee] || seen[callee] {
					continue
				}
				seen[callee] = true
				adj[fn] = append(adj[fn], callee)
			}
		} else {
			// A function the call graph does not know: nothing calls it
			// statically, so it has no node. Synthetic wrappers are the case
			// that matters — a method value such as
			// `Handler: sqliteInj{}.execHandler` compiles to a $bound thunk
			// whose whole body is a call to the method it wraps, and which is
			// reached only by being stored in a field. Leaving it with no
			// outgoing edges lets the condensation order it before the method
			// it calls, so its summary is computed while that method's
			// ParamSink is still empty and every sink behind it is lost. Read
			// the callees straight out of the SSA instead.
			for _, callee := range staticCalleesOf(fn) {
				if !inSet[callee] || seen[callee] {
					continue
				}
				seen[callee] = true
				adj[fn] = append(adj[fn], callee)
			}
		}
		// Edges from func-field dispatch: the dispatcher's summary reads each
		// candidate's ParamSink, so the candidate must be summarised first.
		for _, callee := range fieldEdges[fn] {
			if !inSet[callee] || seen[callee] {
				continue
			}
			seen[callee] = true
			adj[fn] = append(adj[fn], callee)
		}
	}

	state := make(map[*ssa.Function]*sccNode)
	for _, fn := range funcs {
		state[fn] = &sccNode{fn: fn, index: -1}
	}

	idx := 0
	var stack []*ssa.Function
	var sccs [][]*ssa.Function

	var strongconnect func(fn *ssa.Function)
	strongconnect = func(fn *ssa.Function) {
		node := state[fn]
		if node == nil || node.index >= 0 {
			return
		}
		node.index = idx
		node.low = idx
		idx++
		stack = append(stack, fn)
		node.onStack = true

		for _, callee := range adj[fn] {
			calleeNode := state[callee]
			if calleeNode == nil {
				continue
			}
			if calleeNode.index < 0 {
				strongconnect(callee)
				if calleeNode.low < node.low {
					node.low = calleeNode.low
				}
			} else if calleeNode.onStack {
				if calleeNode.index < node.low {
					node.low = calleeNode.index
				}
			}
		}

		if node.low == node.index {
			var scc []*ssa.Function
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				state[w].onStack = false
				scc = append(scc, w)
				if w == fn {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}

	for _, fn := range funcs {
		strongconnect(fn)
	}

	return sccs, adj
}

// hasSelfEdge reports whether fn has a call edge to itself.
func hasSelfEdge(adj map[*ssa.Function][]*ssa.Function, fn *ssa.Function) bool {
	for _, callee := range adj[fn] {
		if callee == fn {
			return true
		}
	}
	return false
}

// computeSummaries computes function summaries bottom-up over the SCC condensation.
func (e *Engine) computeSummaries(funcs []*ssa.Function, cg *callgraph.Graph) {
	if len(funcs) == 0 {
		return
	}

	for _, fn := range funcs {
		if _, ok := e.summaries[fn]; !ok {
			e.summaries[fn] = NewSummary(fn)
		}
	}

	sccs, _ := tarjanSCCWithFieldEdges(cg, funcs, e.buildFuncFieldEdges(funcs))

	if len(sccs) == 0 {
		for _, fn := range funcs {
			e.computeFuncSummary(fn)
		}
		return
	}

	multiCount := 0
	totalIter := 0
	for _, scc := range sccs {
		if len(scc) == 1 {
			e.computeFuncSummary(scc[0])
		} else {
			multiCount++
			e.computeSCCSummary(scc)
			for _, fn := range scc {
				if s := e.summaries[fn]; s != nil && s.IterationCount > 0 {
					totalIter += s.IterationCount
				}
			}
		}
	}
	if multiCount > 0 {
		e.addDiagnostic(fmt.Sprintf("SCC: %d multi-function SCCs, %d total iterations over %d functions",
			multiCount, totalIter, len(funcs)))
	}
}

// inProgress guards summary computation against re-entry. Bottom-up ordering
// should make this unnecessary; the guard is here so that a call graph edge the
// SCC condensation did not anticipate degrades into a missing summary rather
// than an exhausted stack.
func (e *Engine) beginSummary(fn *ssa.Function) bool {
	if e.summaryInProgress == nil {
		e.summaryInProgress = map[*ssa.Function]bool{}
	}
	if e.summaryInProgress[fn] {
		return false
	}
	e.summaryInProgress[fn] = true
	return true
}

func (e *Engine) endSummary(fn *ssa.Function) { delete(e.summaryInProgress, fn) }

// computeSCCSummary computes summaries for a mutually recursive SCC.
func (e *Engine) computeSCCSummary(scc []*ssa.Function) {
	if len(scc) == 0 {
		return
	}

	maxIter := e.sccIterationCap
	if maxIter <= 0 {
		maxIter = 20
	}

	for _, fn := range scc {
		e.summaries[fn] = NewSummary(fn)
	}

	for iter := 0; iter < maxIter; iter++ {
		changed := false
		for _, fn := range scc {
			prev := snapshotSummary(e.summaries[fn])
			e.computeFuncSummary(fn)
			cur := e.summaries[fn]
			if cur != nil && cur.Changed(prev) {
				changed = true
				cur.IterationCount = iter + 1
			}
		}
		if !changed {
			break
		}
		if iter == maxIter-1 {
			for _, fn := range scc {
				if s := e.summaries[fn]; s != nil {
					s.HitCap = true
				}
			}
			e.addDiagnostic(fmt.Sprintf("SCC containing %s hit iteration cap (%d functions)",
				describeSCC(scc), len(scc)))
		}
	}
}

// snapshotSummary returns a shallow copy with copied map contents, so changes
// to the original can be detected by comparing field lengths.
func snapshotSummary(s *FuncSummary) *FuncSummary {
	if s == nil {
		return nil
	}
	cp := &FuncSummary{
		FuncID:              s.FuncID,
		Passthrough:         s.Passthrough,
		IsSummarized:        s.IsSummarized,
		IterationCount:      s.IterationCount,
		HitCap:              s.HitCap,
		ParamReturn:         make(map[int][]TaintEffect, len(s.ParamReturn)),
		ParamSink:           make(map[int][]SinkEffect, len(s.ParamSink)),
		ReceiverFieldWrites: make(map[string][]int, len(s.ReceiverFieldWrites)),
		ArgumentWrites:      append([]int{}, s.ArgumentWrites...),
		ParamArgumentWrites: make(map[int][]int, len(s.ParamArgumentWrites)),
		Sanitizes:           make(map[int][]SanitizeEffect, len(s.Sanitizes)),
		Aliases:             make(map[int]int, len(s.Aliases)),
	}
	for k, v := range s.ParamReturn {
		cp.ParamReturn[k] = v
	}
	for k, v := range s.ParamSink {
		cp.ParamSink[k] = v
	}
	for k, v := range s.ReceiverFieldWrites {
		cp.ReceiverFieldWrites[k] = v
	}
	for k, v := range s.ParamArgumentWrites {
		cp.ParamArgumentWrites[k] = append([]int{}, v...)
	}
	for k, v := range s.Sanitizes {
		cp.Sanitizes[k] = v
	}
	for k, v := range s.Aliases {
		cp.Aliases[k] = v
	}
	if s.SourceReturns != nil {
		cp.SourceReturns = append([]SourcePattern{}, s.SourceReturns...)
	}
	return cp
}

func describeSCC(scc []*ssa.Function) string {
	names := make([]string, 0, len(scc))
	for _, fn := range scc {
		if fn != nil {
			names = append(names, fn.String())
		}
	}
	sort.Strings(names)
	if len(names) > 3 {
		return strings.Join(names[:3], ", ") + fmt.Sprintf(", ... (%d total)", len(names))
	}
	return strings.Join(names, ", ")
}

// computeFuncSummary computes the summary for a single function.
func (e *Engine) computeFuncSummary(fn *ssa.Function) {
	if !e.beginSummary(fn) {
		return
	}
	defer e.endSummary(fn)
	if fn == nil || len(fn.Blocks) == 0 {
		return
	}

	summary := e.summaries[fn]
	if summary == nil {
		summary = NewSummary(fn)
		e.summaries[fn] = summary
	}
	summary.IsSummarized = true

	// Build param label sets: each param starts with a label marking it as tainted.
	// FreeVars are also labelled so closures' captured-variable flows are captured.
	// Each param gets a distinct label ID (NewParamLabelID includes the index)
	// so summary ParamSink matching can tell param 0 (receiver) from param 1
	// (the request), which was impossible when every param shared one ID.
	totalInputs := len(fn.Params) + len(fn.FreeVars)
	paramLabels := make([]LabelSet, totalInputs)
	for i := 0; i < totalInputs; i++ {
		sourceID := fn.String() + "-param-" + fmt.Sprint(i)
		lbl := TaintLabel{
			ID:         NewParamLabelID(sourceID, i),
			SourceID:   sourceID,
			Provenance: "parameter",
		}
		paramLabels[i] = LabelSetOf(lbl)
	}

	// Run intra-procedural analysis. The intra fixpoint propagates param
	// labels through SSA and collects sinks during the final pass. This
	// handles variadic slice packing, field stores, and all the other
	// patterns that a separate traceToParam scan cannot follow.
	returnLabels, sinkHits, diags := e.analyzeIntra(fn, paramLabels)
	for _, d := range diags {
		e.addDiagnostic(d)
	}

	// ParamReturn: which params flow to the return value.
	for _, ls := range returnLabels {
		for _, label := range ls.Labels() {
			for paramIdx, pls := range paramLabels {
				for _, pl := range pls.Labels() {
					if label.ID == pl.ID {
						summary.AddParamReturn(paramIdx, label.TaintKinds, label.FieldPaths, label.Confidence)
					}
				}
			}
		}
	}

	// ParamSink: which params reach a sink inside this function. Derived from
	// the intra fixpoint's sink hits, which correctly follow all SSA patterns
	// including variadic slice packing.
	for _, hit := range sinkHits {
		paramIdx := -1
		for idx, pls := range paramLabels {
			for _, pl := range pls.Labels() {
				if hit.label.ID == pl.ID {
					paramIdx = idx
					break
				}
			}
			if paramIdx >= 0 {
				break
			}
		}
		if paramIdx < 0 {
			continue
		}
		// When the sink was found through a callee's summary (interprocedural,
		// including nested func-field dispatch), the real sink — os.ReadFile,
		// exec.Command — lives inside that callee and is described by
		// hit.summarySink. The call site (hit.common) is the indirect dispatch,
		// whose SSA temp name no reader or matcher can recognise; using it here
		// would propagate an opaque symbol through every layer of summary above.
		sinkSym := callSymbolOf(hit.common)
		sinkNm := callDisplayName(hit.common)
		sinkPos := hit.pos
		if hit.summarySink != nil {
			if hit.summarySink.SinkSymbol != "" {
				sinkSym = hit.summarySink.SinkSymbol
			}
			if hit.summarySink.SinkName != "" {
				sinkNm = hit.summarySink.SinkName
			}
			if hit.summarySink.Pos.IsValid() {
				sinkPos = hit.summarySink.Pos
			}
		}
		summary.AddParamSink(paramIdx, SinkEffect{
			Category:        hit.entry.Category,
			TaintKinds:      hit.entry.TaintKinds,
			ArgumentIndex:   hit.argIndex,
			ParamFieldPaths: hit.label.FieldPaths,
			SinkSymbol:      sinkSym,
			SinkName:        sinkNm,
			SinkType:        "",
			Pos:             sinkPos,
			ModelID:         hit.entry.ID,
			Severity:        hit.entry.Severity,
			Confidence:      hit.entry.Confidence,
			RuleID:          hit.entry.RuleID,
			RuleName:        hit.entry.RuleName,
			RiskScore:       hit.entry.RiskScore,
		})
	}

	if len(summary.ParamReturn) == len(fn.Params) && len(fn.Params) > 0 {
		summary.Passthrough = true
	}

	e.detectSummarySinks(fn, summary)
	e.detectSummaryFieldWrites(fn, summary)
	e.detectSummaryArgumentWrites(fn, summary)
}

// detectSummarySinks detects sink calls within fn that are reachable from tainted parameters.
func (e *Engine) detectSummarySinks(fn *ssa.Function, summary *FuncSummary) {
	if fn == nil || len(fn.Blocks) == 0 {
		return
	}

	for _, block := range fn.Blocks {
		if block == nil {
			continue
		}
		for _, instr := range block.Instrs {
			var common *ssa.CallCommon
			switch x := instr.(type) {
			case *ssa.Call:
				common = x.Common()
			case *ssa.Go:
				common = x.Common()
			case *ssa.Defer:
				common = x.Common()
			default:
				continue
			}
			if common == nil {
				continue
			}

			callee := common.StaticCallee()
			if callee == nil {
				continue
			}

			sinkEntries := e.models.MatchFunction(callee)
			for _, entry := range sinkEntries {
				if entry.Kind != "sink" {
					continue
				}
				for argIdx, arg := range common.Args {
					if !entry.ArgumentRelevant(argIdx) {
						continue
					}
					paramIdx := e.traceToParam(arg, fn)
					if paramIdx >= 0 {
						summary.AddParamSink(paramIdx, SinkEffect{
							Category:      entry.Category,
							TaintKinds:    entry.TaintKinds,
							ArgumentIndex: argIdx,
							SinkSymbol:    callee.String(),
							SinkName:      callee.Name(),
							Pos:           instr.Pos(),
							ModelID:       entry.ID,
							Severity:      entry.Severity,
							Confidence:    entry.Confidence,
							RuleID:        entry.RuleID,
							RuleName:      entry.RuleName,
							RiskScore:     entry.RiskScore,
						})
					}
				}
				if entry.ReceiverRelevant && common.Value != nil {
					paramIdx := e.traceToParam(common.Value, fn)
					if paramIdx >= 0 {
						summary.AddParamSink(paramIdx, SinkEffect{
							Category:      entry.Category,
							TaintKinds:    entry.TaintKinds,
							ArgumentIndex: -1,
							SinkSymbol:    callee.String(),
							SinkName:      callee.Name(),
							Pos:           instr.Pos(),
							ModelID:       entry.ID,
							Severity:      entry.Severity,
							Confidence:    entry.Confidence,
							RuleID:        entry.RuleID,
							RuleName:      entry.RuleName,
							RiskScore:     entry.RiskScore,
						})
					}
				}
			}
		}
	}
}

// traceToParam traces a value back to a function parameter. Returns -1 if not found.
func (e *Engine) traceToParam(v ssa.Value, fn *ssa.Function) int {
	if v == nil {
		return -1
	}

	if param, ok := v.(*ssa.Parameter); ok {
		for i, p := range fn.Params {
			if p == param {
				return i
			}
		}
		return -1
	}

	switch x := v.(type) {
	case *ssa.UnOp:
		return e.traceToParam(x.X, fn)
	case *ssa.Convert:
		return e.traceToParam(x.X, fn)
	case *ssa.ChangeType:
		return e.traceToParam(x.X, fn)
	case *ssa.Field:
		return e.traceToParam(x.X, fn)
	case *ssa.FieldAddr:
		return e.traceToParam(x.X, fn)
	case *ssa.Index:
		return e.traceToParam(x.X, fn)
	case *ssa.IndexAddr:
		return e.traceToParam(x.X, fn)
	case *ssa.Slice:
		return e.traceToParam(x.X, fn)
	case *ssa.Extract:
		return e.traceToParam(x.Tuple, fn)
	case *ssa.Alloc, *ssa.Global, *ssa.Const:
		return -1
	}
	return -1
}

// detectSummaryFieldWrites detects which parameters write to receiver fields.
func (e *Engine) detectSummaryFieldWrites(fn *ssa.Function, summary *FuncSummary) {
	if !summary.HasReceiver() || len(fn.Params) == 0 {
		return
	}
	receiver := fn.Params[0]

	for _, block := range fn.Blocks {
		if block == nil {
			continue
		}
		for _, instr := range block.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok {
				continue
			}

			if fieldAddr, isField := store.Addr.(*ssa.FieldAddr); isField {
				if fieldAddr.X == receiver {
					paramIdx := e.traceToParam(store.Val, fn)
					if paramIdx >= 0 {
						fieldStep := FieldStepByIndex(receiver.Type(), fieldAddr.Field)
						ap := AccessPath{Base: NewParamBase(fn.String(), 0, receiver.Name(), receiver.Type().String())}
						ap = ap.Extended(fieldStep, e.fieldDepth)
						summary.AddReceiverFieldWrite(ap.Key(), paramIdx)
					}
				}
			}
		}
	}
}

// detectSummaryArgumentWrites detects writes to memory reached through a
// parameter pointer, recording them as ArgumentWrites on the summary. This is
// the SSA-derived complement to the model-driven WritesToArguments: a
// user-written helper that fills `*argN` from a parameter deposits taint at
// the call site, and without the summary effect the caller never sees it.
//
// The combined-argument form is used (rather than per-source-param tracking)
// because that is the form the call-site application expects, and the
// precision cost is negligible: a function that writes one parameter into
// another argument's pointee is rare enough that the over-approximation is
// cheaper than carrying a second mapping.
func (e *Engine) detectSummaryArgumentWrites(fn *ssa.Function, summary *FuncSummary) {
	if fn == nil || len(fn.Blocks) == 0 || len(fn.Params) == 0 {
		return
	}
	paramSet := map[*ssa.Parameter]int{}
	for i, p := range fn.Params {
		paramSet[p] = i
	}

	written := map[int]bool{}
	for _, block := range fn.Blocks {
		if block == nil {
			continue
		}
		for _, instr := range block.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok {
				continue
			}
			target := unwrapWriteTarget(store.Addr)
			// Walk the address chain to find the base pointer; if that base
			// is one of the function's parameters, this store writes through
			// an argument.
			base := target
			for {
				switch x := base.(type) {
				case *ssa.FieldAddr:
					base = x.X
				case *ssa.IndexAddr:
					base = x.X
				case *ssa.Index:
					base = x.X
				case *ssa.Slice:
					base = x.X
				case *ssa.UnOp:
					if x.Op == token.MUL {
						base = x.X
						continue
					}
					base = x.X
				default:
					goto done
				}
			}
		done:
			if param, ok := base.(*ssa.Parameter); ok {
				if idx, found := paramSet[param]; found {
					written[idx] = true
				}
			}
		}
	}
	if len(written) == 0 {
		return
	}
	indices := make([]int, 0, len(written))
	for idx := range written {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	summary.ArgumentWrites = indices
}

// addDiagnostic adds a diagnostic message.
func (e *Engine) addDiagnostic(msg string) {
	e.diagnostics = append(e.diagnostics, msg)
}
