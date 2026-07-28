package seam

import (
	"fmt"
	"go/token"
	"sort"

	"golang.org/x/tools/go/ssa"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	models_pkg "github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/models"
)

// newSourceLabel creates the label for a modelled source and registers its
// report node, so any slice that later cites this source can resolve it.
func (e *Engine) newSourceLabel(fn *ssa.Function, entry models_pkg.ModelEntry, pos token.Pos) TaintLabel {
	pkgPath, fnID := "", ""
	if fn != nil {
		fnID = fn.String()
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			pkgPath = fn.Pkg.Pkg.Path()
		}
	}
	sourceID := stableID("seam-source", fnID, entry.ID, e.positionKey(pos))
	return TaintLabel{
		ID:       NewLabelID(sourceID, 0),
		SourceID: sourceID,
		SourceNode: &Step{
			Kind: "source", EdgeKind: "source", Name: entry.Function, Symbol: entry.QualifiedName(),
			FunctionID: fnID, PackagePath: pkgPath, Pos: pos,
		},
		SourceCategory: entry.Category,
		SourcePatterns: []SourcePattern{{
			Category: entry.Category, TaintKinds: entry.TaintKinds,
			Confidence: entry.Confidence, Pattern: entry.Function, PURL: entry.PURL,
		}},
		TaintKinds: entry.TaintKinds,
		Confidence: firstNonEmptyStr(entry.Confidence, "high"),
		Provenance: "model-source",
		Generated:  true,
	}
}

// addNodeWithID registers a node under a caller-supplied identity.
func (e *Engine) addNodeWithID(id, kind, name, symbol, typ, fnID, pkgPath string, pos token.Pos,
	source, sink bool, category string, taints []string, fieldPath, confidence string, props map[string]string) model.DataFlowNode {
	if id == "" {
		return model.DataFlowNode{}
	}
	if existing, ok := e.nodeByID[id]; ok {
		return existing
	}
	mod := e.moduleForPackagePath(pkgPath)
	node := model.DataFlowNode{
		ID: id, Kind: kind, Name: name, Symbol: symbol, Type: typ,
		PackagePath: pkgPath, Module: mod, PURL: packagePURL(pkgPath, mod),
		FunctionID: fnID, Function: fnID, Position: e.position(pos),
		Source: source, Sink: sink, Category: category,
		TaintKinds: uniqueStringsSorted(taints), FieldPath: fieldPath,
		Confidence: firstNonEmptyStr(confidence, "medium"), Properties: props,
	}
	if e.nodeByID == nil {
		e.nodeByID = map[string]model.DataFlowNode{}
	}
	e.nodeByID[id] = node
	e.nodeSeen[id] = true
	e.nodes = append(e.nodes, node)
	return node
}

// positionKey renders a source position deterministically, for node identity.
func (e *Engine) positionKey(pos token.Pos) string {
	p := e.position(pos)
	return fmt.Sprintf("%s:%d:%d", p.Filename, p.Line, p.Column)
}

// position converts an SSA position into a report position.
func (e *Engine) position(pos token.Pos) model.Position {
	if e.fset == nil || !pos.IsValid() {
		return model.Position{}
	}
	p := e.fset.Position(pos)
	return model.Position{Filename: p.Filename, Offset: p.Offset, Line: p.Line, Column: p.Column}
}

// sinkModelsFor returns the sink models matching a call site.
func (e *Engine) sinkModelsFor(common *ssa.CallCommon) []models_pkg.ModelEntry {
	var out []models_pkg.ModelEntry
	for _, entry := range e.modelsForCall(common) {
		if entry.Kind == "sink" {
			out = append(out, entry)
		}
	}
	return out
}

// argumentWriteTargets returns the set of argument indices that this call
// writes taint into, drawn from model entries (for external functions like
// io.Copy) and from the callee's summary (for functions with bodies that
// perform the write themselves). Deduped and sorted for deterministic output.
func (e *Engine) argumentWriteTargets(common *ssa.CallCommon) []int {
	if common == nil {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	add := func(idx int) {
		if idx < 0 || seen[idx] {
			return
		}
		seen[idx] = true
		out = append(out, idx)
	}
	for _, entry := range e.modelsForCall(common) {
		for _, idx := range entry.WritesToArguments {
			add(idx)
		}
	}
	if callee := common.StaticCallee(); callee != nil {
		if summary := e.summaryFor(callee); summary != nil {
			for _, idx := range summary.ArgumentWrites {
				add(idx)
			}
		}
	} else if common.IsInvoke() {
		// Interface dispatch: union the write targets of every concrete
		// implementation. The side effect happens on whatever instance is
		// reached at runtime, and any of them could write.
		for _, impl := range e.resolveInvokeCallees(common) {
			if summary := e.summaryFor(impl); summary != nil {
				for _, idx := range summary.ArgumentWrites {
					add(idx)
				}
			}
		}
	}
	sort.Ints(out)
	return out
}

// modelsForCall resolves the models matching a call, following interface
// dispatch when the callee is not statically known.
func (e *Engine) modelsForCall(common *ssa.CallCommon) []models_pkg.ModelEntry {
	if common == nil {
		return nil
	}
	if callee := common.StaticCallee(); callee != nil {
		return e.models.MatchFunction(callee)
	}
	if common.IsInvoke() && common.Method != nil {
		return e.models.MatchSymbol(common.Method)
	}
	return nil
}

// sinkAcceptsLabel reports whether a label's taint is the kind this sink cares
// about. In security mode only attacker-influenced kinds qualify; the wider
// modes report any taint.
func (e *Engine) sinkAcceptsLabel(_ models_pkg.ModelEntry, label TaintLabel) bool {
	if e.mode != "security" {
		return true
	}
	if e.duringSummary {
		// During summary computation the param labels carry no source-specific
		// taint kinds. Accept them unconditionally so the summary records which
		// params reach sinks; kind filtering happens at materialisation.
		return true
	}
	return labelContainsAnyKind(label, []string{"user-input", "secret", "environment", "crypto-key", "path", "url", "native"})
}

// crossesDependency reports whether a call leaves the module under analysis.
func (e *Engine) crossesDependency(caller, callee *ssa.Function) bool {
	if caller == nil || callee == nil {
		return false
	}
	return e.moduleOf(caller) != e.moduleOf(callee)
}

func (e *Engine) moduleOf(fn *ssa.Function) string {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return ""
	}
	if mod := e.moduleForPackagePath(fn.Pkg.Pkg.Path()); mod != nil {
		return mod.Path
	}
	return ""
}

// globalTaintFor returns the taint recorded for a package-level variable.
func (e *Engine) globalTaintFor(global *ssa.Global) LabelSet {
	if global == nil || e.globalTaint == nil {
		return LabelSet{}
	}
	return e.globalTaint["global:"+global.String()]
}

// summaryFor looks up the summary for a function, preferring the instantiation
// over the generic origin and falling back to the origin when the
// instantiation has none.
//
// The instantiation is strictly the more precise of the two. Inside the generic
// origin a call on a value of type-parameter type is an invoke against the
// constraint interface, which cannot be resolved; in the instantiation the same
// call is static against the concrete type. Execute[T, C Commander[T]] calling
// c.Run(v) is the case: the origin's summary records no sink because it cannot
// see past the constraint, while Execute[string, ShellCmd] reaches
// ShellCmd.Run directly. Preferring the origin therefore threw away the only
// summary that knew about the sink.
//
// The origin remains the fallback, which is what lets one instantiation's
// summary serve a container instantiated at several types.
func (e *Engine) summaryFor(fn *ssa.Function) *FuncSummary {
	if fn == nil {
		return nil
	}
	if s := e.summaries[fn]; s != nil && s.IsSummarized {
		return s
	}
	if origin := fn.Origin(); origin != nil {
		if s := e.summaries[origin]; s != nil && s.IsSummarized {
			return s
		}
	}
	return nil
}

// resolveInvokeCallee resolves an interface dispatch site to a single
// concrete callee via the implements-index, intersected with the call graph
// when available. If multiple implementations exist, the first (deterministic)
// one is returned — over-approximation is handled by resolveInvokeCallees.
func (e *Engine) resolveInvokeCallee(common *ssa.CallCommon) *ssa.Function {
	callees := e.resolveInvokeCallees(common)
	if len(callees) == 0 {
		return nil
	}
	return callees[0]
}

// resolveInvokeCallees returns all concrete functions an interface dispatch
// could reach, via the implements-index.
func (e *Engine) resolveInvokeCallees(common *ssa.CallCommon) []*ssa.Function {
	if e.ifaceIdx == nil || common == nil || !common.IsInvoke() {
		return nil
	}
	return e.ifaceIdx.LookupInterfaceCall(common)
}

// sinkAcceptsLabelKind reports whether a label's taint is the kind this sink
// category cares about, using the category to infer expected kinds when the
// sink model is not directly available (as with summary-derived sinks).
func (e *Engine) sinkAcceptsLabelKind(category string, label TaintLabel) bool {
	if e.mode != "security" {
		return true
	}
	if e.duringSummary {
		return true
	}
	return labelContainsAnyKind(label, []string{"user-input", "secret", "environment", "crypto-key", "path", "url", "native"})
}

// modelEntryFromEffect builds a ModelEntry from a summary SinkEffect, so a
// summary-derived sink hit can reuse the same emission path as a direct one.
func modelEntryFromEffect(effect SinkEffect) models_pkg.ModelEntry {
	return models_pkg.ModelEntry{
		ID:         effect.ModelID,
		Kind:       "sink",
		Category:   effect.Category,
		TaintKinds: effect.TaintKinds,
		Severity:   effect.Severity,
		Confidence: firstNonEmptyStr(effect.Confidence, "medium"),
		RuleID:     effect.RuleID,
		RuleName:   effect.RuleName,
		RiskScore:  effect.RiskScore,
	}
}

// analyzeIntra runs the fixpoint for one function and returns the taint
// reaching each result, the sink hits found, and diagnostics — for summary
// construction.
func (e *Engine) analyzeIntra(fn *ssa.Function, paramLabels []LabelSet) (returnLabels []LabelSet, sinkHits []sinkHit, diagnostics []string) {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil, nil, nil
	}
	analysis := newIntra(e, fn)
	analysis.run(paramLabels)
	return analysis.returns, analysis.sinks, analysis.diagnostics
}
