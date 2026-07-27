package seam

import (
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"

	models_pkg "github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/models"
)

// taintState is the abstract state at one program point: what taint each SSA
// register carries, and what taint each memory location named by an access path
// carries.
//
// The state has to map locations to taint. A flat set of labels with no
// location attached cannot say *what* is tainted, so joining such sets at a
// control-flow merge conveys nothing and the fixpoint it feeds is decorative.
type taintState struct {
	values map[ssa.Value]LabelSet
	memory map[string]LabelSet
}

func newTaintState() taintState {
	return taintState{values: map[ssa.Value]LabelSet{}, memory: map[string]LabelSet{}}
}

func (s taintState) clone() taintState {
	out := taintState{
		values: make(map[ssa.Value]LabelSet, len(s.values)),
		memory: make(map[string]LabelSet, len(s.memory)),
	}
	for k, v := range s.values {
		out.values[k] = v
	}
	for k, v := range s.memory {
		out.memory[k] = v
	}
	return out
}

// mergeInto joins other into s and reports whether s changed. Progress is
// monotone because LabelSet.Add keeps exactly one canonical route per label
// identity, so the iteration terminates.
func (s taintState) mergeInto(other taintState) bool {
	changed := false
	for value, labels := range other.values {
		before := s.values[value]
		merged := before.Merge(labels)
		if routesDiffer(before, merged) {
			s.values[value] = merged
			changed = true
		}
	}
	for key, labels := range other.memory {
		before := s.memory[key]
		merged := before.Merge(labels)
		if routesDiffer(before, merged) {
			s.memory[key] = merged
			changed = true
		}
	}
	return changed
}

// routesDiffer reports whether a merge added a label or replaced a route with a
// shorter one. Both count as progress.
func routesDiffer(before, after LabelSet) bool {
	if before.Len() != after.Len() {
		return true
	}
	for i, label := range after.labels {
		if before.labels[i].ID != label.ID {
			return true
		}
		if before.labels[i].Parent.Depth() != label.Parent.Depth() {
			return true
		}
	}
	return false
}

func (s taintState) setValue(v ssa.Value, labels LabelSet) {
	if v == nil || labels.IsEmpty() {
		return
	}
	s.values[v] = s.values[v].Merge(labels)
}

// sinkHit is one tainted argument arriving at a modelled sink.
type sinkHit struct {
	fn       *ssa.Function
	label    TaintLabel
	callee   *ssa.Function
	common   *ssa.CallCommon
	argIndex int
	pos      token.Pos
	entry    models_pkg.ModelEntry
	// summarySinkFn is the function whose summary detected the sink, when the
	// sink is interprocedural (the tainted value reached a sink inside a callee).
	summarySinkFn *ssa.Function
	// summarySink holds the actual sink call's identity when the hit was found
	// through a callee's summary (interprocedural). The call site (hit.common)
	// is the indirect dispatch; the real sink (e.g. os/exec.Command) lives inside
	// the callee and is described here so the report names the sink the reader
	// can act on, not the opaque call-through.
	summarySink *SinkEffect
}

// intra runs the per-block fixpoint for a single function.
type intra struct {
	engine *Engine
	fn     *ssa.Function
	blocks []*ssa.BasicBlock
	index  map[*ssa.BasicBlock]int
	in     []taintState
	out    []taintState

	returns []LabelSet
	sinks   []sinkHit

	collectSinks bool
	diagnostics  []string
}

func newIntra(engine *Engine, fn *ssa.Function) *intra {
	s := &intra{
		engine: engine,
		fn:     fn,
		blocks: fn.Blocks,
		index:  make(map[*ssa.BasicBlock]int, len(fn.Blocks)),
		in:     make([]taintState, len(fn.Blocks)),
		out:    make([]taintState, len(fn.Blocks)),
	}
	for i, block := range fn.Blocks {
		s.index[block] = i
		s.in[i] = newTaintState()
		s.out[i] = newTaintState()
	}
	if fn.Signature != nil && fn.Signature.Results() != nil {
		s.returns = make([]LabelSet, fn.Signature.Results().Len())
	}
	return s
}

// run iterates the transfer functions to a fixpoint, then makes one final pass
// over the converged state to record returns and sinks.
//
// Sinks are collected only once the state has converged. Collecting them while
// it is still growing reports whatever partial taint happened to exist when a
// block was first visited, which is the unsound single-pass behaviour a
// fixpoint exists to replace.
func (s *intra) run(paramLabels []LabelSet) {
	if len(s.blocks) == 0 {
		return
	}
	entry := s.index[s.blocks[0]]
	for i, labels := range paramLabels {
		if i < len(s.fn.Params) {
			s.in[entry].setValue(s.fn.Params[i], labels)
		} else {
			fi := i - len(s.fn.Params)
			if fi < len(s.fn.FreeVars) {
				s.in[entry].setValue(s.fn.FreeVars[fi], labels)
			}
		}
	}

	order := rpoBlocks(s.fn)
	queued := make([]bool, len(s.blocks))
	worklist := make([]int, 0, len(order))
	for _, block := range order {
		idx := s.index[block]
		worklist = append(worklist, idx)
		queued[idx] = true
	}

	visits := 0
	limit := s.engine.intraIterationCap * (len(s.blocks) + 1)
	for len(worklist) > 0 {
		visits++
		if visits > limit {
			s.diagnostics = append(s.diagnostics, fmt.Sprintf(
				"intra-procedural fixpoint did not converge for %s within %d block visits; results may be incomplete",
				s.fn.String(), limit))
			break
		}
		idx := worklist[0]
		worklist = worklist[1:]
		queued[idx] = false

		state := s.in[idx].clone()
		for _, instr := range s.blocks[idx].Instrs {
			s.transfer(state, instr)
		}
		if !s.out[idx].mergeInto(state) {
			continue
		}
		for _, succ := range s.blocks[idx].Succs {
			succIdx, ok := s.index[succ]
			if !ok {
				continue
			}
			if s.in[succIdx].mergeInto(s.out[idx]) && !queued[succIdx] {
				worklist = append(worklist, succIdx)
				queued[succIdx] = true
			}
		}
	}

	s.collectSinks = true
	// pendingAsync records Go and Defer instructions whose closure-summary
	// sink check ran before later instructions in the same function could
	// populate the bindings the closure reads. A goroutine launched before
	// a channel send is the canonical case: at the Go instruction the
	// channel is empty, so the closure's "FreeVar reaches sink" summary
	// produces no finding, even though the send happens before the
	// goroutine observes the channel in practice. We re-check these with
	// the block's converged output state, which reflects the send.
	var pendingAsync []asyncSinkCheck
	for _, block := range order {
		idx := s.index[block]
		state := s.in[idx].clone()
		for _, instr := range block.Instrs {
			s.transfer(state, instr)
			if com, ok := asyncCallCommon(instr); ok {
				if summary := s.engine.summaryFor(calleeOfCommon(com)); summary != nil && len(summary.ParamSink) > 0 {
					pendingAsync = append(pendingAsync, asyncSinkCheck{common: com, pos: instr.Pos(), stateIdx: idx})
				}
			}
		}
	}
	s.collectSinks = false
	for _, ac := range pendingAsync {
		state := s.out[ac.stateIdx].clone()
		s.checkSummarySinks(state, ac.common, ac.pos)
	}
}

// asyncCallCommon returns the CallCommon of a Go or Defer instruction, which
// represent asynchronous control flow whose sink-relevance may not be visible
// at the launch site.
func asyncCallCommon(instr ssa.Instruction) (*ssa.CallCommon, bool) {
	switch x := instr.(type) {
	case *ssa.Go:
		return x.Common(), true
	case *ssa.Defer:
		return x.Common(), true
	}
	return nil, false
}

func calleeOfCommon(common *ssa.CallCommon) *ssa.Function {
	if common == nil {
		return nil
	}
	if c := common.StaticCallee(); c != nil {
		return c
	}
	return nil
}

type asyncSinkCheck struct {
	common   *ssa.CallCommon
	pos      token.Pos
	stateIdx int
}

// transfer applies one instruction to the state.
func (s *intra) transfer(state taintState, instr ssa.Instruction) {
	switch x := instr.(type) {
	case *ssa.Store:
		labels := s.taintOf(state, x.Val)
		if labels.IsEmpty() {
			// Storing untainted data kills whatever the location held.
			delete(state.memory, s.pathKey(x.Addr))
			return
		}
		step := s.step("store", "store", valueName(x.Addr), valueSymbol(x.Addr), valueTypeOf(x.Val), s.fieldPathOf(x.Addr), x.Pos())
		labels = withStep(labels, step)
		state.memory[s.pathKey(x.Addr)] = labels
		s.rememberAggregate(state, x.Addr, labels)

		// If storing to a package-level global, propagate to the engine's
		// global taint map so other functions can read it.
		//
		// Only labels that carry a real source are published. The map is
		// program-wide and is read during materialisation in some other
		// function, where a parameter label — whose whole meaning is "this
		// function's parameter N", and which has no source node — cannot be
		// resolved. A slice built from one omits its own source and fails the
		// connectivity check. Parameter taint reaching a global is still
		// recorded, as a param-to-sink effect in this function's summary.
		if published := labels.WithRealSource(); !published.IsEmpty() {
			if global, ok := x.Addr.(*ssa.Global); ok {
				key := "global:" + global.String()
				s.engine.globalTaint[key] = s.engine.globalTaint[key].Merge(published)
			} else if addr := unwrapAddr(x.Addr); addr != nil {
				if global, ok := addr.(*ssa.Global); ok {
					key := "global:" + global.String()
					s.engine.globalTaint[key] = s.engine.globalTaint[key].Merge(published)
				}
			}
		}

	case *ssa.MapUpdate:
		if labels := s.taintOf(state, x.Value); !labels.IsEmpty() {
			step := s.step("map-store", "store", valueName(x.Map), valueSymbol(x.Map), valueTypeOf(x.Value), "[*]", x.Pos())
			state.memory[s.pathKey(x.Map)+"[*]"] = withStep(labels, step)
		}

	case *ssa.Send:
		if labels := s.taintOf(state, x.X); !labels.IsEmpty() {
			step := s.step("channel-send", "channel", valueName(x.Chan), valueSymbol(x.Chan), valueTypeOf(x.X), "chan", x.Pos())
			state.memory[s.chanKey(x.Chan)] = withStep(labels, step)
		}

	case *ssa.Select:
		s.transferSelect(state, x)

	case *ssa.Call:
		state.setValue(x, s.transferCall(state, x.Common(), x.Pos()))

	case *ssa.Go:
		s.transferCall(state, x.Common(), x.Pos())

	case *ssa.Defer:
		s.transferCall(state, x.Common(), x.Pos())

	case *ssa.Panic:
		// panic is a builtin, not a call, so it can be modelled only in the
		// engine and not in the model database. Tainted data reaching it
		// leaks whatever it holds into the crash output.
		s.checkPanicSink(state, x)

	case *ssa.Convert:
		s.checkConversionSink(state, x, x.X, x.Type(), x.Pos())

	case *ssa.ChangeType:
		s.checkConversionSink(state, x, x.X, x.Type(), x.Pos())

	case *ssa.Return:
		for i, result := range x.Results {
			if i < len(s.returns) {
				s.returns[i] = s.returns[i].Merge(s.taintOf(state, result))
			}
		}

	default:
		if value, ok := instr.(ssa.Value); ok {
			state.setValue(value, s.evaluate(state, value, nil))
		}
	}
}

func (s *intra) transferSelect(state taintState, sel *ssa.Select) {
	var received LabelSet
	for _, st := range sel.States {
		if st.Chan == nil {
			continue
		}
		if st.Send != nil {
			if labels := s.taintOf(state, st.Send); !labels.IsEmpty() {
				step := s.step("select-send", "channel", valueName(st.Chan), valueSymbol(st.Chan), valueTypeOf(st.Send), "chan", st.Pos)
				state.memory[s.chanKey(st.Chan)] = withStep(labels, step)
			}
			continue
		}
		if labels, ok := state.memory[s.chanKey(st.Chan)]; ok {
			step := s.step("select-receive", "channel", valueName(st.Chan), valueSymbol(st.Chan), valueTypeOf(st.Chan), "chan", st.Pos)
			received = received.Merge(withStep(labels, step))
		}
	}
	state.setValue(sel, received)
}

// transferCall reports any sink the call reaches and returns the taint of its
// result.
func (s *intra) transferCall(state taintState, common *ssa.CallCommon, pos token.Pos) LabelSet {
	if common == nil {
		return LabelSet{}
	}
	// Variadic arguments are packed into a slice before the call, so the
	// taint is on the slice's elements rather than on the value passed. Only
	// checkSinks looked through that; a passthrough or a summary applied here
	// saw a clean argument. fmt.Sprintf is the case that matters — it is the
	// most common way tainted data is carried in Go, and
	// `query := fmt.Sprintf("... %s ...", in)` followed by db.Exec(query) is
	// go-test-bench's entire SQL-injection route, invisible because Sprintf
	// returned nothing.
	var argLabels LabelSet
	for _, arg := range common.Args {
		argLabels = argLabels.Merge(s.taintOf(state, arg)).Merge(s.variadicElementTaint(state, arg))
	}
	var recvLabels LabelSet
	if common.IsInvoke() && common.Value != nil {
		recvLabels = s.taintOf(state, common.Value)
	}

	if s.collectSinks {
		s.checkSinks(state, common, pos)
		s.checkSummarySinks(state, common, pos)
	}

	argAt := func(i int) LabelSet {
		if i < 0 || i >= len(common.Args) {
			return LabelSet{}
		}
		return s.taintOf(state, common.Args[i]).Merge(s.variadicElementTaint(state, common.Args[i]))
	}

	// For MakeClosure calls, extend argAt to map FreeVar positions to bindings.
	if common.Value != nil {
		if _, ok := common.Value.(*ssa.MakeClosure); ok {
			nArgs := len(common.Args)
			argAt = func(i int) LabelSet {
				if i >= 0 && i < nArgs {
					return s.taintOf(state, common.Args[i])
				}
				if mc, ok := common.Value.(*ssa.MakeClosure); ok {
					bi := i - nArgs
					if bi >= 0 && bi < len(mc.Bindings) {
						return s.taintOf(state, mc.Bindings[bi])
					}
				}
				return LabelSet{}
			}
		}
	}
	result := s.engine.resolveCallTaint(s.fn, common, argLabels, recvLabels, pos, argAt)
	s.applyCallArgumentWrites(state, common, argLabels, pos)
	if result.IsEmpty() {
		return result
	}
	step := s.step("call", "call-return", callDisplayName(common), callSymbolOf(common), callResultType(common), "", pos)
	step.CrossesDependency = s.engine.crossesDependency(s.fn, common.StaticCallee())
	return withStep(result, step)
}

// applyCallArgumentWrites deposits taint into the memory locations a call
// writes through its arguments. Go's standard library moves a great deal of
// data this way rather than by returning it: io.Copy fills its destination,
// json.Unmarshal fills the value behind a pointer, a strings.Builder
// accumulates into its receiver. Without modelling the side effect, every
// flow that crosses one of these calls dies at the call site even when the
// source is correctly identified.
//
// Sources of the effect:
//   - model entries with WritesToArguments (the structured equivalent of the
//     legacy writesToArguments pattern pack);
//   - a callee's FuncSummary.ArgumentWrites, detected from its body or
//     populated from a model when no body is available.
//
// The combined argument taint is written to each target. That matches the
// legacy semantics and is sound: anything any argument carried into the call
// is potentially part of what the callee deposits at the destination.
func (s *intra) applyCallArgumentWrites(state taintState, common *ssa.CallCommon, argLabels LabelSet, pos token.Pos) {
	if common == nil || argLabels.IsEmpty() {
		return
	}
	targets := s.engine.argumentWriteTargets(common)
	if len(targets) == 0 {
		return
	}
	args := common.Args
	for _, idx := range targets {
		if idx < 0 || idx >= len(args) {
			continue
		}
		target := unwrapAddr(args[idx])
		// Storing through a MakeInterface-wrapped pointer (io.Writer passed
		// to io.Copy, any passed to json.Unmarshal) must write through to the
		// allocation the caller supplied, not the ephemeral interface value.
		target = unwrapWriteTarget(target)
		if target == nil {
			continue
		}
		step := s.step("argument-write", "argument-write", valueName(target), callSymbolOf(common), valueTypeOf(target), s.fieldPathOf(target), pos)
		written := withStep(argLabels, step)
		key := s.pathKey(target)
		state.memory[key] = state.memory[key].Merge(written)
		// A destination is usually a pointer to an aggregate, so record the
		// element and field views a later read will look through. Without
		// these, taint stored into a struct pointer would be invisible to a
		// later field load.
		state.memory[key+"[*]"] = state.memory[key+"[*]"].Merge(written)
		if field, isField := target.(*ssa.FieldAddr); isField {
			state.memory[key+fieldSuffix(field)] = state.memory[key+fieldSuffix(field)].Merge(written)
		}
	}
}

// unwrapWriteTarget looks through the conversions a destination argument
// passes through on its way to an interface or generic parameter.
//
// io.Copy takes an io.Writer and json.Unmarshal takes an any, so the pointer
// the caller supplied arrives wrapped in a MakeInterface. Keying memory off
// the wrapper rather than the allocation it wraps means the later read of
// that allocation never sees what was written into it.
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

// checkSinks records every tainted argument arriving at a modelled sink.
func (s *intra) checkSinks(state taintState, common *ssa.CallCommon, pos token.Pos) {
	targets := s.engine.sinkModelsFor(common)
	if len(targets) == 0 {
		return
	}
	for _, entry := range targets {
		for argIdx, arg := range common.Args {
			if !entry.ArgumentRelevant(argIdx) {
				continue
			}
			labels := s.taintOf(state, arg).Merge(s.variadicElementTaint(state, arg))
			for _, label := range labels.Labels() {
				if !label.AllowsSink(entry.Category) {
					continue
				}
				if !s.engine.sinkAcceptsLabel(entry, label) {
					continue
				}
				s.sinks = append(s.sinks, sinkHit{
					fn: s.fn, label: label, callee: common.StaticCallee(), common: common,
					argIndex: argIdx, pos: pos, entry: entry,
				})
			}
		}
	}
}

// checkSummarySinks records sink hits for tainted arguments reaching sinks
// inside a callee through that callee's summary. This is the interprocedural
// path: without it, a flow that enters a helper and hits a sink inside it is
// invisible from the caller.
func (s *intra) checkSummarySinks(state taintState, common *ssa.CallCommon, pos token.Pos) {
	callee := s.engine.throughLinkname(common.StaticCallee())
	if callee == nil && common.IsInvoke() {
		callee = s.engine.resolveInvokeCallee(common)
	}
	// A call through a func-typed struct field has no static callee and is not
	// an invoke, and unlike an interface method it may hold a genuinely
	// different function at every call — go-test-bench keeps one closure per
	// vulnerable route in a single Sink.VulnerableFnWrapper field. Resolving
	// only the first candidate follows one route and misses the rest, so every
	// candidate is checked. See funcfield.go.
	if callee == nil {
		if candidates := s.engine.fieldFuncCandidates(common); len(candidates) > 0 {
			for _, candidate := range candidates {
				s.checkSummarySinksFor(state, common, pos, candidate)
			}
			return
		}
	}
	s.checkSummarySinksFor(state, common, pos, callee)
}

func (s *intra) checkSummarySinksFor(state taintState, common *ssa.CallCommon, pos token.Pos, callee *ssa.Function) {
	// Handle MakeClosure calls (deferred or immediate closures). The closure's
	// bindings are the source of taint for its captured FreeVars. Even when
	// StaticCallee resolved the callee (which it does for *ssa.MakeClosure,
	// returning the underlying closure function), the bindings are needed to
	// map a summary's FreeVar indices back to the values the caller captured.
	// Without this, every summary-derived sink inside a closure is invisible.
	var mc *ssa.MakeClosure
	if common.Value != nil {
		if v, ok := common.Value.(*ssa.MakeClosure); ok {
			mc = v
			if callee == nil {
				if fn, ok := v.Fn.(*ssa.Function); ok {
					callee = fn
				}
			}
		}
	}
	if callee == nil {
		return
	}
	// A modelled sink is an abstraction boundary. When we have a model for the
	// callee, that model *is* the finding, and descending into the body to
	// report what it does internally describes the same call a second time at
	// a lower level. http.Redirect writes its Location header with
	// fmt.Fprintf, so without this every redirect also reported a
	// formatted-output finding inside net/http — a function the reader did not
	// write, at a call they cannot change. checkSinks has already recorded the
	// modelled hit for this call.
	if len(s.engine.sinkModelsFor(common)) > 0 {
		return
	}
	summary := s.engine.summaryFor(callee)
	if summary == nil || len(summary.ParamSink) == 0 {
		return
	}

	// nParams is the number of regular parameters (not FreeVars) in the
	// callee's signature. Summary indices >= nParams correspond to FreeVars,
	// whose taint comes from the MakeClosure bindings, not common.Args.
	nParams := summary.NumParams()

	hasReceiver := summary.HasReceiver()
	for paramIdx, effects := range summary.ParamSink {
		var labels LabelSet
		if mc != nil && paramIdx >= nParams {
			// FreeVar position: map to binding.
			bi := paramIdx - nParams
			if bi >= 0 && bi < len(mc.Bindings) {
				labels = s.taintOf(state, mc.Bindings[bi])
			}
		} else if hasReceiver && paramIdx == 0 && common.IsInvoke() {
			if common.Value != nil {
				labels = s.taintOf(state, common.Value)
			}
		} else {
			argIdx := paramIdx
			if hasReceiver && common.IsInvoke() {
				argIdx = paramIdx - 1
			}
			if argIdx >= 0 && argIdx < len(common.Args) {
				labels = s.taintOf(state, common.Args[argIdx])
			}
		}
		if labels.IsEmpty() {
			continue
		}
		for _, label := range labels.Labels() {
			for _, effect := range effects {
				if !label.AllowsSink(effect.Category) {
					continue
				}
				if !s.engine.sinkAcceptsLabelKind(effect.Category, label) {
					continue
				}
				// Extend the label with a step for the interprocedural hop
				// into the callee, so the slice's path and dependency-crossing
				// flag are correct.
				hop := s.step("call", "call", callDisplayName(common), callSymbolOf(common), "", "", pos)
				hop.CrossesDependency = s.engine.crossesDependency(s.fn, callee)
				extendedLabel := label.WithParent(hop)
				effectCopy := effect
				s.sinks = append(s.sinks, sinkHit{
					fn:            s.fn,
					label:         extendedLabel,
					callee:        callee,
					common:        common,
					argIndex:      paramIdx,
					pos:           pos,
					entry:         modelEntryFromEffect(effect),
					summarySinkFn: summary.Func,
					summarySink:   &effectCopy,
				})
			}
		}
	}
}

// variadicElementTaint returns taint stored into the elements of the slice a
// variadic call packs its tail into.
//
// Go lowers f(a, b, c) with a variadic tail into an allocation, element stores
// and a slice of that allocation, so the register at the call site is the
// slice, not the values. Without following that indirection almost every real
// sink is invisible: exec.Command, fmt.Printf, log.Printf and db.Query all take
// their interesting arguments variadically.
func (s *intra) variadicElementTaint(state taintState, arg ssa.Value) LabelSet {
	slice, ok := arg.(*ssa.Slice)
	if !ok {
		return LabelSet{}
	}
	prefix := s.pathKey(slice.X)
	var out LabelSet
	for key, labels := range state.memory {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			out = out.Merge(labels)
		}
	}
	return out
}

// taintOf returns the taint of a value in this state.
func (s *intra) taintOf(state taintState, v ssa.Value) LabelSet {
	if v == nil {
		return LabelSet{}
	}
	if labels, ok := state.values[v]; ok && !labels.IsEmpty() {
		return labels
	}
	if key := s.pathKey(v); key != "" {
		if labels, ok := state.memory[key]; ok && !labels.IsEmpty() {
			return labels
		}
	}
	// A channel's taint lives in its buffer (populated by Send), not in the
	// channel value itself. A closure that receives from a captured channel
	// and sinks the value carries the channel as a FreeVar; checking the
	// buffer here is what lets the caller-side summary application see what
	// was sent in. Without it every flow through a worker pool dies at the
	// goroutine boundary.
	if labels, ok := state.memory[s.chanKey(v)]; ok && !labels.IsEmpty() {
		return labels
	}
	return s.evaluate(state, v, map[ssa.Value]bool{})
}

// evaluate derives the taint of a value from its operands. The visited set
// bounds recursion through cyclic SSA; the enclosing fixpoint, not this
// recursion, is what carries taint around a loop.
func (s *intra) evaluate(state taintState, v ssa.Value, visited map[ssa.Value]bool) LabelSet {
	if v == nil {
		return LabelSet{}
	}
	if visited == nil {
		visited = map[ssa.Value]bool{}
	}
	if visited[v] {
		return LabelSet{}
	}
	visited[v] = true
	if labels, ok := state.values[v]; ok && !labels.IsEmpty() {
		return labels
	}

	switch x := v.(type) {
	case *ssa.UnOp:
		switch x.Op {
		case token.MUL:
			if labels, ok := state.memory[s.pathKey(x.X)]; ok {
				return withStep(labels, s.step("load", "load", valueName(x.X), valueSymbol(x.X), valueTypeOf(x), s.fieldPathOf(x.X), x.Pos()))
			}
		case token.ARROW:
			if labels, ok := state.memory[s.chanKey(x.X)]; ok {
				return withStep(labels, s.step("channel-receive", "channel", valueName(x.X), valueSymbol(x.X), valueTypeOf(x), "chan", x.Pos()))
			}
		}
		return s.evaluate(state, x.X, visited)

	case *ssa.FieldAddr:
		if labels, ok := state.memory[s.pathKey(x)]; ok {
			return labels
		}
		// A field load through a pointer that was tainted as a whole — most
		// often the destination of json.Unmarshal(&p) or io.Copy(&dst) —
		// must pick up the aggregate's taint, or every flow that crosses
		// one of those calls dies between the write and the next field
		// read. The [*] view is set by call-side argument writes and by
		// element stores; the base key itself is also set by field stores
		// of OTHER fields (via rememberAggregate), so falling back to it
		// would erase field discrimination. Reading only the [*] view
		// keeps the call-side write visible without conflating fields.
		baseKey := s.pathKey(x.X)
		if labels, ok := state.memory[baseKey+"[*]"]; ok && !labels.IsEmpty() {
			return labels
		}
		return s.evaluate(state, x.X, visited)

	case *ssa.Field:
		if labels, ok := state.memory[s.pathKey(x)]; ok {
			return labels
		}
		return s.evaluate(state, x.X, visited)

	case *ssa.IndexAddr:
		if labels, ok := state.memory[s.pathKey(x)]; ok {
			return labels
		}
		if labels, ok := state.memory[s.pathKey(x.X)+"[*]"]; ok {
			return labels
		}
		return s.evaluate(state, x.X, visited)

	case *ssa.Index:
		if labels, ok := state.memory[s.pathKey(x.X)+"[*]"]; ok {
			return labels
		}
		return s.evaluate(state, x.X, visited)

	case *ssa.Lookup:
		if labels, ok := state.memory[s.pathKey(x.X)+"[*]"]; ok {
			return labels
		}
		return s.evaluate(state, x.X, visited)

	case *ssa.Slice:
		if labels, ok := state.memory[s.pathKey(x.X)+"[*]"]; ok {
			return labels
		}
		return s.evaluate(state, x.X, visited)

	case *ssa.Phi:
		var out LabelSet
		for _, edge := range x.Edges {
			out = out.Merge(s.evaluate(state, edge, visited))
		}
		return out

	case *ssa.BinOp:
		return s.evaluate(state, x.X, visited).Merge(s.evaluate(state, x.Y, visited))
	case *ssa.Convert:
		return s.evaluate(state, x.X, visited)
	case *ssa.ChangeType:
		return s.evaluate(state, x.X, visited)
	case *ssa.ChangeInterface:
		return s.evaluate(state, x.X, visited)
	case *ssa.MakeInterface:
		return s.evaluate(state, x.X, visited)
	case *ssa.TypeAssert:
		return s.evaluate(state, x.X, visited)
	case *ssa.SliceToArrayPointer:
		return s.evaluate(state, x.X, visited)
	case *ssa.Extract:
		return s.evaluate(state, x.Tuple, visited)
	case *ssa.Next:
		return s.evaluate(state, x.Iter, visited)
	case *ssa.Range:
		return s.evaluate(state, x.X, visited)

	case *ssa.MakeClosure:
		var out LabelSet
		for _, binding := range x.Bindings {
			out = out.Merge(s.evaluate(state, binding, visited))
		}
		return out

	case *ssa.Global:
		return s.engine.globalTaintFor(x)
	}
	return LabelSet{}
}

// unwrapAddr follows FieldAddr/IndexAddr chains to find the base address.
func unwrapAddr(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.FieldAddr:
			v = x.X
		case *ssa.IndexAddr:
			v = x.X
		default:
			return v
		}
	}
}

// rememberAggregate records a store through a field or index so a later read of
// the whole aggregate still sees the taint. The aggregate base is also marked,
// so returning a struct pointer carries taint from any tainted field.
func (s *intra) rememberAggregate(state taintState, addr ssa.Value, labels LabelSet) {
	switch a := addr.(type) {
	case *ssa.IndexAddr:
		baseKey := s.pathKey(a.X)
		state.memory[baseKey+"[*]"] = labels
		state.memory[baseKey] = state.memory[baseKey].Merge(labels)
	case *ssa.FieldAddr:
		baseKey := s.pathKey(a.X)
		state.memory[baseKey+fieldSuffix(a)] = labels
		state.memory[baseKey] = state.memory[baseKey].Merge(labels)
	}
}

func (s *intra) step(kind, edgeKind, name, symbol, typ, fieldPath string, pos token.Pos) *Step {
	pkgPath := ""
	if s.fn.Pkg != nil && s.fn.Pkg.Pkg != nil {
		pkgPath = s.fn.Pkg.Pkg.Path()
	}
	return &Step{
		Kind: kind, EdgeKind: edgeKind, Name: name, Symbol: symbol, Type: typ,
		FunctionID: s.fn.String(), PackagePath: pkgPath, FieldPath: fieldPath, Pos: pos,
	}
}

// withStep extends every label in the set by one hop.
func withStep(labels LabelSet, step *Step) LabelSet {
	if step == nil || labels.IsEmpty() {
		return labels
	}
	var out LabelSet
	for _, label := range labels.Labels() {
		hop := *step
		out = out.Add(label.WithParent(&hop))
	}
	return out
}

// pathKey names the memory location a value addresses.
func (s *intra) pathKey(v ssa.Value) string {
	switch x := v.(type) {
	case nil:
		return ""
	case *ssa.Alloc:
		return fmt.Sprintf("alloc:%s:%d", x.Name(), int(x.Pos()))
	case *ssa.Global:
		return "global:" + x.String()
	case *ssa.Parameter:
		return "param:" + s.fn.String() + ":" + x.Name()
	case *ssa.FreeVar:
		return "freevar:" + s.fn.String() + ":" + x.Name()
	case *ssa.FieldAddr:
		return s.pathKey(x.X) + fieldSuffix(x)
	case *ssa.Field:
		return s.pathKey(x.X) + fieldSuffixOfField(x)
	case *ssa.IndexAddr:
		return s.pathKey(x.X) + "[*]"
	case *ssa.Index:
		return s.pathKey(x.X) + "[*]"
	case *ssa.Lookup:
		// A map lookup yields an element of the map; two lookups of the same
		// map produce distinct SSA values, so keying off the Lookup itself
		// would split a store and a later load of the same element into
		// different locations and silently lose every flow through a map
		// value. Collapsing to the map's [*] location, the way Index and
		// IndexAddr do, keeps the location stable.
		return s.pathKey(x.X) + "[*]"
	default:
		return "value:" + s.fn.String() + ":" + x.Name()
	}
}

// chanKey returns the memory key under which a channel's buffer is stored.
//
// A channel captured by a closure lives behind a heap-allocated pointer:
// SSA represents `jobs` (the local) as an Alloc containing the channel, and
// every access — including the Send on it — dereferences with a UnOp(MUL).
// Keying off the dereference alone would split the Send and the binding's
// lookup into different locations, silently dropping every flow through a
// worker pool. Following the UnOp to its operand recovers the allocation
// both ends share.
func (s *intra) chanKey(v ssa.Value) string {
	if op, ok := v.(*ssa.UnOp); ok && op.Op == token.MUL {
		v = op.X
	}
	return "chan:" + s.pathKey(v)
}

func (s *intra) fieldPathOf(addr ssa.Value) string {
	switch x := addr.(type) {
	case *ssa.FieldAddr:
		return fieldName(x.X.Type(), x.Field)
	case *ssa.Field:
		return fieldName(x.X.Type(), x.Field)
	case *ssa.IndexAddr:
		return "[*]"
	}
	return ""
}

func fieldSuffix(x *ssa.FieldAddr) string { return "." + fieldName(x.X.Type(), x.Field) }

func fieldSuffixOfField(x *ssa.Field) string { return "." + fieldName(x.X.Type(), x.Field) }

// fieldName resolves a field index to its declared name, so a report says
// ".Cmd" rather than ".field3".
func fieldName(base types.Type, index int) string {
	t := types.Unalias(base)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	if named, ok := t.(*types.Named); ok {
		t = named.Underlying()
	}
	strct, ok := t.(*types.Struct)
	if !ok || index < 0 || index >= strct.NumFields() {
		return fmt.Sprintf("field%d", index)
	}
	return strct.Field(index).Name()
}

func valueName(v ssa.Value) string {
	if v == nil {
		return ""
	}
	if name := v.Name(); name != "" {
		return name
	}
	return v.String()
}

func valueSymbol(v ssa.Value) string {
	if v == nil {
		return ""
	}
	if object, ok := v.(interface{ Object() types.Object }); ok && object.Object() != nil {
		obj := object.Object()
		if obj.Pkg() != nil {
			return obj.Pkg().Path() + "." + obj.Name()
		}
		return obj.Name()
	}
	return v.String()
}

func valueTypeOf(v ssa.Value) string {
	if v == nil || v.Type() == nil {
		return ""
	}
	return v.Type().String()
}

func callDisplayName(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if callee := common.StaticCallee(); callee != nil {
		return callee.Name()
	}
	if common.Method != nil {
		return common.Method.Name()
	}
	return common.String()
}

func callSymbolOf(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if callee := common.StaticCallee(); callee != nil {
		return callee.String()
	}
	if common.Method != nil {
		if common.Method.Pkg() != nil {
			return common.Method.Pkg().Path() + "." + common.Method.Name()
		}
		return common.Method.Name()
	}
	return common.String()
}

func callResultType(common *ssa.CallCommon) string {
	if common == nil || common.Signature() == nil {
		return ""
	}
	results := common.Signature().Results()
	if results == nil || results.Len() == 0 {
		return ""
	}
	return results.At(0).Type().String()
}

// rpoBlocks returns the function's blocks in reverse post-order.
//
// The traversal is an explicit stack rather than recursion: control-flow graphs
// in the standard library run to thousands of blocks, and a recursive depth-first
// walk overflows the goroutine stack long before it reaches them.
func rpoBlocks(fn *ssa.Function) []*ssa.BasicBlock {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil
	}
	visited := make(map[*ssa.BasicBlock]bool, len(fn.Blocks))
	post := make([]*ssa.BasicBlock, 0, len(fn.Blocks))

	type frame struct {
		block *ssa.BasicBlock
		next  int
	}
	walk := func(root *ssa.BasicBlock) {
		if root == nil || visited[root] {
			return
		}
		visited[root] = true
		stack := []frame{{block: root}}
		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.next < len(top.block.Succs) {
				succ := top.block.Succs[top.next]
				top.next++
				if succ != nil && !visited[succ] {
					visited[succ] = true
					stack = append(stack, frame{block: succ})
				}
				continue
			}
			post = append(post, top.block)
			stack = stack[:len(stack)-1]
		}
	}

	walk(fn.Blocks[0])
	for _, block := range fn.Blocks {
		walk(block)
	}
	out := make([]*ssa.BasicBlock, 0, len(post))
	for i := len(post) - 1; i >= 0; i-- {
		out = append(out, post[i])
	}
	return out
}

// checkPanicSink records tainted data reaching a panic.
//
// panic is a builtin rather than a function, so no model database entry can
// describe it and the check has to live in the engine — which is why SEAM
// missed it while legacy, whose walker handles the instruction directly, did
// not. A panic value is formatted into the crash output and usually into logs,
// so a secret or user-controlled string arriving here is the same class of
// finding as one arriving at a logging call.
func (s *intra) checkPanicSink(state taintState, p *ssa.Panic) {
	if p == nil || p.X == nil || !s.collectSinks {
		return
	}
	entry := models_pkg.ModelEntry{
		ID: "go.panic.sink", Kind: "sink", Module: "std", Function: "panic",
		Category: "panic", TaintKinds: []string{"user-input", "secret"},
		Severity: "medium", Confidence: "medium",
	}
	for _, label := range s.taintOf(state, p.X).Labels() {
		if !label.AllowsSink(entry.Category) || !s.engine.sinkAcceptsLabelKind(entry.Category, label) {
			continue
		}
		s.sinks = append(s.sinks, sinkHit{fn: s.fn, label: label, pos: p.Pos(), entry: entry})
	}
}

// checkConversionSink records tainted data converted to a type whose whole
// meaning is "this value has already been made safe".
//
// html/template.HTML and its siblings are named string types, so
// template.HTML(userInput) is a conversion and not a call: there is no callee
// for a function-keyed model to match, and both engines walked past the single
// most common way a Go program gets stored XSS. The conversion is the
// vulnerability — it is the point at which the template package is told to
// stop escaping.
func (s *intra) checkConversionSink(state taintState, result ssa.Value, operand ssa.Value, typ types.Type, pos token.Pos) {
	if !s.collectSinks || operand == nil || typ == nil {
		return
	}
	entries := s.engine.models.MatchConversion(typ)
	if len(entries) == 0 {
		return
	}
	labels := s.taintOf(state, operand)
	if labels.IsEmpty() {
		return
	}
	for _, entry := range entries {
		if entry.Kind != "sink" {
			continue
		}
		for _, label := range labels.Labels() {
			if !label.AllowsSink(entry.Category) || !s.engine.sinkAcceptsLabelKind(entry.Category, label) {
				continue
			}
			s.sinks = append(s.sinks, sinkHit{fn: s.fn, label: label, pos: pos, entry: entry})
		}
	}
}
