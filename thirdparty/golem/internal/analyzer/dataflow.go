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

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

type dataFlowTrace struct {
	nodeIDs        []string
	edgeIDs        []string
	params         map[int]bool
	tauntKinds     []string
	fieldPaths     []string
	sourceID       string
	sourceCategory string
	sourcePURL     string
	sourcePatterns []model.DataFlowPattern
	confidence     string
	generated      bool
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
	analyzer      *Analyzer
	out           *model.DataFlowEvidence
	patterns      *model.DataFlowPatternSet
	summaries     map[*ssa.Function]*internalSummary
	nodeSeen      map[string]bool
	edgeSeen      map[string]bool
	sliceSeen     map[string]bool
	maxSlices     int
	instructionCt int
}

func (a *Analyzer) buildDataFlow(pkgs []*packages.Package) *model.DataFlowEvidence {
	patterns, diagnostics := loadDataFlowPatterns(a.options.DataFlowMode, a.options.DataFlowPacks, a.options.DataFlowConfig)
	out := &model.DataFlowEvidence{Mode: a.options.DataFlowMode, Patterns: patterns, Diagnostics: diagnostics}
	mode := ssa.BuilderMode(ssa.InstantiateGenerics | ssa.GlobalDebug)
	prog, _ := ssautil.AllPackages(pkgs, mode)
	prog.Build()
	funcSet := ssautil.AllFunctions(prog)
	funcs := make([]*ssa.Function, 0, len(funcSet))
	for fn := range funcSet {
		if fn == nil || fn.Blocks == nil || !a.includeDataFlowFunction(fn) {
			continue
		}
		funcs = append(funcs, fn)
	}
	sort.Slice(funcs, func(i, j int) bool { return funcs[i].String() < funcs[j].String() })
	b := &dataFlowBuilder{analyzer: a, out: out, patterns: patterns, summaries: map[*ssa.Function]*internalSummary{}, nodeSeen: map[string]bool{}, edgeSeen: map[string]bool{}, sliceSeen: map[string]bool{}, maxSlices: a.options.DataFlowMax}
	b.inferSummaries(funcs)
	for _, fn := range funcs {
		b.analyzeFunction(fn)
	}
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
	sortDataFlowEvidence(out)
	out.Stats.NodeCount = len(out.Nodes)
	out.Stats.EdgeCount = len(out.Edges)
	out.Stats.SliceCount = len(out.Slices)
	out.Stats.SummaryCount = len(out.Summaries)
	out.Stats.FunctionCount = len(funcs)
	out.Stats.InstructionCount = b.instructionCt
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

func builtinDataFlowPatterns(mode string, packs []string) *model.DataFlowPatternSet {
	selected := map[string]bool{}
	if len(packs) == 0 {
		for _, p := range []string{"base", "http", "data", "filesystem", "process", "crypto", "native"} {
			selected[p] = true
		}
	} else {
		for _, p := range packs {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "all" {
				for _, name := range []string{"base", "http", "data", "filesystem", "process", "crypto", "native"} {
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
	if selected["base"] || mode == "all" || mode == "security" {
		addSource("symbol", "os.Args", "cli", "user-input")
		addSource("function", "os.Getenv", "environment", "environment", "secret")
		addSource("function", "os.LookupEnv", "environment", "environment", "secret")
		addSource("function", "flag.Arg", "cli", "user-input")
		addSource("function", "flag.Args", "cli", "user-input")
		addSource("parameter", "^(input|query|command|cmd|path|file|filename|url|uri|token|key|secret|password)$", "parameter", "user-input")
		for _, name := range []string{"fmt.Sprintf", "strings.Join", "strings.Trim", "strings.TrimSpace", "strings.Replace", "strings.ReplaceAll", "bytes.(*Buffer).String", "strconv.Itoa", "strconv.Format"} {
			addPass("function", name, "conversion")
		}
	}
	if selected["http"] || mode == "all" || mode == "security" {
		for _, name := range []string{"FormValue", "PostFormValue", "Cookie", "Header.Get", "Header).Get", "Values.Get", "github.com/gin-gonic/gin", "Param", "Query", "PostForm", "github.com/labstack/echo", "github.com/gofiber/fiber"} {
			addSource("function", name, "http-input", "user-input")
		}
		addSink("function", "net/http.ResponseWriter.Write", "http-response", "user-input")
		addSink("function", "fmt.Fprintf", "formatted-output", "user-input")
	}
	if selected["process"] || mode == "all" || mode == "security" {
		addSink("function", "os/exec.Command", "command-execution", "user-input")
		addSink("function", "Command", "command-execution", "user-input")
		addSink("function", "CommandContext", "command-execution", "user-input")
	}
	if selected["data"] || mode == "all" || mode == "security" {
		for _, name := range []string{"database/sql.(*DB).Query", "database/sql.(*DB).QueryContext", "database/sql.(*DB).Exec", "database/sql.(*DB).ExecContext", "database/sql.(*Tx).Query", "database/sql.(*Tx).Exec", "encoding/gob.(*Decoder).Decode", "encoding/json.Unmarshal", "yaml.Unmarshal"} {
			addSink("function", name, "data", "user-input")
		}
		addSan("function", "database/sql.(*Stmt).Exec", "sql-parameterization", "sql")
	}
	if selected["filesystem"] || mode == "all" || mode == "security" {
		for _, name := range []string{"os.OpenFile", "os.WriteFile", "os.Create", "os.Mkdir", "os.MkdirAll", "archive/zip", "archive/tar"} {
			addSink("function", name, "filesystem", "path")
		}
		addPass("function", "path/filepath.Join", "path")
		addPass("function", "path.Join", "path")
		addSan("function", "path/filepath.Base", "path-validation", "path")
	}
	if selected["crypto"] || mode == "all" || mode == "crypto" || mode == "security" {
		for _, name := range []string{"crypto/aes.NewCipher", "crypto/hmac.New", "crypto/x509.ParsePKCS1PrivateKey", "crypto/x509.ParsePKCS8PrivateKey", "crypto/x509.ParseCertificate", "crypto/tls.LoadX509KeyPair", "golang.org/x/crypto/pbkdf2.Key", "github.com/golang-jwt/jwt"} {
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
				}
			case *ssa.MapUpdate:
				if tr, ok := b.summaryTaintOf(state, x.Value); ok {
					state.memory[addrKey(x.Map)+"[*]"] = tr
				}
			case *ssa.Send:
				if tr, ok := b.summaryTaintOf(state, x.X); ok {
					state.chans[addrKey(x.Chan)] = tr
				}
			case *ssa.Call:
				if tr, ok := b.summaryCallTaint(state, x.Common()); ok {
					state.values[x] = tr
				}
				changed = b.recordSummarySink(fn, x.Common(), state) || changed
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

func (b *dataFlowBuilder) analyzeFunction(fn *ssa.Function) {
	state := newDataFlowState()
	for i, p := range fn.Params {
		for _, pat := range b.matchParameterSource(fn, i, p) {
			n := b.addNode("source", p.Name(), p.String(), p.Type().String(), fn, p.Pos(), true, false, pat.Category, pat.TaintKinds, "", pat.Confidence, nil)
			state.values[p] = combineTraces(state.values[p], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{pat}, tauntKinds: taintsForPattern(pat), confidence: pat.Confidence})
		}
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			b.instructionCt++
			switch x := instr.(type) {
			case *ssa.Store:
				if tr, ok := b.taintOf(state, x.Val); ok {
					n := b.addNode("store", valueName(x.Addr), valueSymbol(x.Addr), valueType(x.Val), fn, x.Pos(), false, false, "", tr.tauntKinds, strings.Join(tr.fieldPaths, "."), tr.confidence, nil)
					tr = b.connectTrace(tr, n, "store", x.Pos(), valueName(x.Addr))
					state.memory[addrKey(x.Addr)] = tr
				}
			case *ssa.MapUpdate:
				if tr, ok := b.taintOf(state, x.Value); ok {
					n := b.addNode("map-store", valueName(x.Map), valueSymbol(x.Map), valueType(x.Value), fn, x.Pos(), false, false, "", tr.tauntKinds, "[*]", tr.confidence, nil)
					tr = b.connectTrace(tr, n, "map-store", x.Pos(), valueName(x.Map))
					state.memory[addrKey(x.Map)+"[*]"] = tr.withFieldPath("[*]")
				}
			case *ssa.Send:
				if tr, ok := b.taintOf(state, x.X); ok {
					n := b.addNode("channel-send", valueName(x.Chan), valueSymbol(x.Chan), valueType(x.X), fn, x.Pos(), false, false, "", tr.tauntKinds, "chan", tr.confidence, nil)
					state.chans[addrKey(x.Chan)] = b.connectTrace(tr, n, "channel-send", x.Pos(), valueName(x.Chan))
				}
			case *ssa.Call:
				b.processCall(fn, state, x, x.Common())
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
		state.values[call] = combineTraces(state.values[call], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{pat}, tauntKinds: taintsForPattern(pat), confidence: pat.Confidence, generated: true})
	}
	if len(b.matchCall(common, b.patterns.Sanitizers)) > 0 {
		return
	}
	if callee := common.StaticCallee(); callee != nil {
		if summary := b.summaries[callee]; summary != nil {
			for _, pat := range summary.sourceReturns {
				n := b.addNode("source", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), true, false, pat.Category, pat.TaintKinds, "", pat.Confidence, map[string]string{"summaryFunction": callee.String()})
				state.values[call] = combineTraces(state.values[call], dataFlowTrace{nodeIDs: []string{n.ID}, sourceID: n.ID, sourceCategory: n.Category, sourcePURL: n.PURL, sourcePatterns: []model.DataFlowPattern{pat}, tauntKinds: taintsForPattern(pat), confidence: pat.Confidence, generated: true})
			}
			args := callArgs(common)
			for idx := range summary.paramReturn {
				if idx >= 0 && idx < len(args) {
					if tr, ok := b.taintOf(state, args[idx]); ok {
						n := b.addNode("call-summary", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), false, false, "", tr.tauntKinds, "", tr.confidence, map[string]string{"summaryFunction": callee.String(), "parameterIndex": fmt.Sprint(idx)})
						state.values[call] = combineTraces(state.values[call], b.connectTrace(tr, n, "interprocedural-return", call.Pos(), fmt.Sprint(idx)))
					}
				}
			}
			for idx, cats := range summary.paramSink {
				if idx >= 0 && idx < len(args) {
					if tr, ok := b.taintOf(state, args[idx]); ok {
						for cat := range cats {
							pat := model.DataFlowPattern{Target: "sink", Kind: "function", Match: "exact", Pattern: callee.String(), Category: cat, Confidence: "medium"}
							b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, idx, fmt.Sprintf("Taint reaches summarized sink in %s", callee.String()))
						}
					}
				}
			}
		}
	}
	if b.shouldPropagate(common) {
		if tr, ok := b.combineCallArgTaints(state, common); ok {
			n := b.addNode("call", callName(common), callSymbol(common), valueType(call), fn, call.Pos(), false, false, "", tr.tauntKinds, "", tr.confidence, nil)
			state.values[call] = combineTraces(state.values[call], b.connectTrace(tr, n, "call-return", call.Pos(), callName(common)))
		}
	}
}

func (b *dataFlowBuilder) processAsyncCall(fn *ssa.Function, state dataFlowState, common *ssa.CallCommon, pos token.Pos, kind string) {
	for _, pat := range b.matchCall(common, b.patterns.Sinks) {
		args := callArgs(common)
		for idx, arg := range args {
			if tr, ok := b.taintOf(state, arg); ok {
				b.emitSliceSink(fn, tr, pos, callName(common), callSymbol(common), "", pat, idx, "Taint reaches asynchronous "+kind+" sink")
			}
		}
	}
}

func (b *dataFlowBuilder) emitSink(fn *ssa.Function, state dataFlowState, call ssa.Value, common *ssa.CallCommon, pat model.DataFlowPattern) {
	args := callArgs(common)
	for idx, arg := range args {
		if tr, ok := b.taintOf(state, arg); ok {
			b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, idx, "Taint reaches "+firstNonEmpty(pat.Category, "sink"))
		}
	}
	if recv := receiverValue(common); recv != nil {
		if tr, ok := b.taintOf(state, recv); ok {
			b.emitSliceSink(fn, tr, call.Pos(), callName(common), callSymbol(common), valueType(call), pat, -1, "Taint reaches sink receiver")
		}
	}
}

func (b *dataFlowBuilder) emitSliceSink(fn *ssa.Function, tr dataFlowTrace, pos token.Pos, name, symbol, typ string, pat model.DataFlowPattern, argIndex int, summary string) {
	if b.maxSlices > 0 && len(b.out.Slices) >= b.maxSlices {
		return
	}
	idx := argIndex
	sink := b.addNode("sink", name, symbol, typ, fn, pos, false, true, pat.Category, mergeStrings(tr.tauntKinds, taintsForPattern(pat)), "", firstNonEmpty(pat.Confidence, tr.confidence), map[string]string{"pattern": pat.Pattern})
	tr = b.connectTrace(tr, sink, "sink", pos, fmt.Sprint(argIndex))
	sourceID := firstNonEmpty(tr.sourceID, firstString(tr.nodeIDs))
	if sourceID == "" {
		return
	}
	id := stableID("df-slice", sourceID, sink.ID, strings.Join(tr.edgeIDs, ":"), fmt.Sprint(argIndex))
	if b.sliceSeen[id] {
		return
	}
	b.sliceSeen[id] = true
	b.out.Slices = append(b.out.Slices, model.DataFlowSlice{ID: id, SourceID: sourceID, SinkID: sink.ID, NodeIDs: uniqueStrings(append(append([]string{}, tr.nodeIDs...), sink.ID)), EdgeIDs: uniqueStrings(tr.edgeIDs), SourceCategory: tr.sourceCategory, SinkCategory: pat.Category, SourcePURL: tr.sourcePURL, SinkPURL: pat.PURL, SinkArgumentIndex: &idx, TaintKinds: uniqueStrings(mergeStrings(tr.tauntKinds, taintsForPattern(pat))), FieldPaths: uniqueStrings(tr.fieldPaths), Confidence: firstNonEmpty(pat.Confidence, tr.confidence, "medium"), Summary: summary})
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
	for _, sourceID := range tr.nodeIDs {
		id := stableID("df-edge", sourceID, node.ID, kind, label, fmt.Sprint(b.analyzer.position(pos).Line))
		if !b.edgeSeen[id] {
			b.edgeSeen[id] = true
			b.out.Edges = append(b.out.Edges, model.DataFlowEdge{ID: id, SourceID: sourceID, TargetID: node.ID, Kind: kind, Label: label, Position: b.analyzer.position(pos)})
		}
		tr.edgeIDs = append(tr.edgeIDs, id)
	}
	tr.nodeIDs = append(tr.nodeIDs, node.ID)
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
				return dataFlowTrace{generated: true, tauntKinds: taintsForPattern(pat), confidence: pat.Confidence}, true
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
			if tr, ok := b.taintOf(state, arg); ok {
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
	return matchDataFlowPatterns(patterns, symbol, name, pkgPath, typ, "")
}

func (b *dataFlowBuilder) matchValueSource(v ssa.Value) []model.DataFlowPattern {
	return matchDataFlowPatterns(b.patterns.Sources, valueSymbol(v), valueName(v), valuePackage(v), valueType(v), valueConstString(v))
}

func (b *dataFlowBuilder) matchParameterSource(fn *ssa.Function, idx int, p *ssa.Parameter) []model.DataFlowPattern {
	text := p.Name() + " " + p.Type().String()
	matches := matchDataFlowPatterns(b.patterns.Sources, fn.String()+"."+p.Name(), p.Name(), callPackageForFunction(fn), p.Type().String(), text)
	out := matches[:0]
	for _, m := range matches {
		if m.Kind == "parameter" || m.Kind == "name" || m.Kind == "type" || m.Kind == "symbol" {
			out = append(out, m)
		}
	}
	_ = idx
	return out
}

func matchDataFlowPatterns(patterns []model.DataFlowPattern, symbol, name, pkgPath, typ, code string) []model.DataFlowPattern {
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
		if patternMatches(value, p) {
			out = append(out, p)
		}
	}
	return out
}

func patternMatches(value string, p model.DataFlowPattern) bool {
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
		return regexp.MustCompile(p.Pattern).MatchString(value)
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
	if common.Method != nil && common.Method.Pkg() != nil {
		return common.Method.Pkg().Path()
	}
	return ""
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
	out := dataFlowTrace{nodeIDs: uniqueStrings(append(a.nodeIDs, b.nodeIDs...)), edgeIDs: uniqueStrings(append(a.edgeIDs, b.edgeIDs...)), params: map[int]bool{}, tauntKinds: uniqueStrings(append(a.tauntKinds, b.tauntKinds...)), fieldPaths: uniqueStrings(append(a.fieldPaths, b.fieldPaths...)), sourceID: firstNonEmpty(a.sourceID, b.sourceID), sourceCategory: firstNonEmpty(a.sourceCategory, b.sourceCategory), sourcePURL: firstNonEmpty(a.sourcePURL, b.sourcePURL), sourcePatterns: append(append([]model.DataFlowPattern{}, a.sourcePatterns...), b.sourcePatterns...), confidence: firstNonEmpty(a.confidence, b.confidence, "medium"), generated: a.generated || b.generated}
	for k := range a.params {
		out.params[k] = true
	}
	for k := range b.params {
		out.params[k] = true
	}
	return out
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
