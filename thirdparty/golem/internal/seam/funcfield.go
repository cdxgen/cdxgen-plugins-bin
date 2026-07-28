package seam

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// Function values stored in struct fields.
//
// A great deal of real Go dispatches through a function value held in a struct
// field rather than through an interface: a router keeps a handler per route, a
// middleware chain keeps the next link, a test harness keeps the thing under
// test. The call site is
//
//	t1 = &s.Handler   // *ssa.FieldAddr
//	t2 = *t1          // *ssa.UnOp MUL
//	t3 = t2(args...)  // *ssa.Call, Value = t2
//
// which has no static callee, is not an interface invoke, and has no
// MakeClosure at the call. SEAM builds its call graph in "static" mode, which
// resolves no dynamic calls at all, so nothing downstream of such a call was
// reachable and taint stopped dead at the call.
//
// Contrast Security's go-test-bench routes every one of its nine declared
// vulnerabilities through exactly this shape — internal/common/handler.go calls
// s.VulnerableFnWrapper(opaque, payload) — which is why both engines found
// almost none of them.
//
// The resolution here is deliberately simple and unsound in the same direction
// as CHA: index every function value ever stored into a given struct field
// anywhere in the program, and treat a call through that field as possibly
// reaching any of them. It over-approximates when one field holds different
// functions in different places, which is the safe direction for taint, and it
// costs one pass over the instructions already being walked.

// buildFuncFieldEdges returns, for each function that contains a call through a
// func-typed struct field, the candidate callees that call may reach. These are
// the edges the static call graph cannot carry and that the SCC condensation
// needs so a dispatcher is summarised after — not before — its candidates.
func (e *Engine) buildFuncFieldEdges(funcs []*ssa.Function) map[*ssa.Function][]*ssa.Function {
	if len(e.funcsByField) == 0 {
		return nil
	}
	out := map[*ssa.Function][]*ssa.Function{}
	for _, fn := range funcs {
		if fn == nil || len(fn.Blocks) == 0 {
			continue
		}
		seen := map[*ssa.Function]bool{}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				var common *ssa.CallCommon
				switch c := instr.(type) {
				case *ssa.Call:
					common = c.Common()
				case *ssa.Go:
					common = c.Common()
				case *ssa.Defer:
					common = c.Common()
				default:
					continue
				}
				if common == nil || common.StaticCallee() != nil || common.IsInvoke() {
					continue
				}
				candidates := e.fieldFuncCandidates(common)
				for _, cand := range candidates {
					if !seen[cand] {
						seen[cand] = true
						out[fn] = append(out[fn], cand)
					}
				}
			}
		}
	}
	return out
}

// fieldFuncKey identifies a struct field that holds a function value.
type fieldFuncKey struct {
	structType string
	fieldIndex int
}

// indexFieldFuncValues records, for every struct field of function type, the
// functions stored into it anywhere in the program.
func (e *Engine) indexFieldFuncValues(funcs []*ssa.Function) {
	e.funcsByField = map[fieldFuncKey][]*ssa.Function{}
	seen := map[fieldFuncKey]map[*ssa.Function]bool{}
	for _, fn := range funcs {
		if fn == nil {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				store, ok := instr.(*ssa.Store)
				if !ok {
					continue
				}
				addr, ok := store.Addr.(*ssa.FieldAddr)
				if !ok {
					continue
				}
				target := functionValueOf(store.Val)
				if target == nil {
					continue
				}
				key, ok := fieldKeyOf(addr)
				if !ok {
					continue
				}
				if seen[key] == nil {
					seen[key] = map[*ssa.Function]bool{}
				}
				if seen[key][target] {
					continue
				}
				seen[key][target] = true
				e.funcsByField[key] = append(e.funcsByField[key], target)
			}
		}
	}
	// Determinism: the candidate order decides which summary is applied first
	// and therefore which route a slice reports.
	for key := range e.funcsByField {
		sortFunctions(e.funcsByField[key])
	}
}

// functionValueOf unwraps a value that denotes a function: a plain function
// reference, a closure with captured variables, or either behind the type
// conversion a named func type introduces.
func functionValueOf(v ssa.Value) *ssa.Function {
	return functionValueOfSeen(v, map[*ssa.Extract]bool{})
}

// functionValueOfSeen is functionValueOf carrying the set of Extracts already
// being resolved, so a factory whose result is an Extract of a call to itself
// cannot recurse forever.
func functionValueOfSeen(v ssa.Value, seen map[*ssa.Extract]bool) *ssa.Function {
	switch x := v.(type) {
	case *ssa.Function:
		return x
	case *ssa.MakeClosure:
		if fn, ok := x.Fn.(*ssa.Function); ok {
			return fn
		}
	case *ssa.ChangeType:
		return functionValueOfSeen(x.X, seen)
	case *ssa.Convert:
		return functionValueOfSeen(x.X, seen)
	case *ssa.Extract:
		return functionFromExtract(x, seen)
	}
	return nil
}

// functionFromExtract traces a multi-valued call's extracted element back to
// the function the callee returns at that index. It inspects the callee's
// Return instructions for a directly-returned function value (a Function or
// MakeClosure), which is the shape of every factory/wrapper that produces a
// handler. Returns nil when the callee is unknown, has no body, or does not
// directly return a function at the index — the safe (no-false-positive)
// direction.
func functionFromExtract(ex *ssa.Extract, seen map[*ssa.Extract]bool) *ssa.Function {
	if ex == nil || ex.Tuple == nil || seen[ex] {
		// Recursion guard. A function that returns the result of calling
		// itself — a retry wrapper, a decorator, a middleware chain builder —
		// produces an Extract whose resolution leads back to the same Extract.
		// go-test-bench has one, and under --dataflow all, where more of the
		// program is in scope, it overflowed the stack and killed the run.
		return nil
	}
	seen[ex] = true
	call, ok := ex.Tuple.(*ssa.Call)
	if !ok {
		return nil
	}
	callee := call.Common().StaticCallee()
	if callee == nil || len(callee.Blocks) == 0 {
		return nil
	}
	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			if ex.Index < 0 || ex.Index >= len(ret.Results) {
				continue
			}
			if fn := functionValueOfSeen(ret.Results[ex.Index], seen); fn != nil {
				return fn
			}
		}
	}
	return nil
}

// fieldKeyOf identifies the field a FieldAddr addresses, keyed on the struct's
// named type so the same field of the same type matches across packages.
func fieldKeyOf(addr *ssa.FieldAddr) (fieldFuncKey, bool) {
	if addr == nil || addr.X == nil {
		return fieldFuncKey{}, false
	}
	typ := addr.X.Type()
	if ptr, ok := typ.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok {
		// An anonymous struct has no stable cross-package identity; skip it
		// rather than key on a rendering that may not be unique.
		return fieldFuncKey{}, false
	}
	return fieldFuncKey{structType: named.String(), fieldIndex: addr.Field}, true
}

// fieldFuncCandidates returns the functions a call through a func-typed struct
// field may reach, or nil when the call is not of that shape.
func (e *Engine) fieldFuncCandidates(common *ssa.CallCommon) []*ssa.Function {
	if common == nil || common.IsInvoke() || len(e.funcsByField) == 0 {
		return nil
	}
	addr := fieldAddrBehind(common.Value)
	if addr == nil {
		return nil
	}
	key, ok := fieldKeyOf(addr)
	if !ok {
		return nil
	}
	return e.funcsByField[key]
}

// fieldAddrBehind finds the FieldAddr a called value was loaded from, seeing
// through the load and through any conversions between named func types.
func fieldAddrBehind(v ssa.Value) *ssa.FieldAddr {
	for i := 0; i < 8 && v != nil; i++ {
		switch x := v.(type) {
		case *ssa.UnOp:
			if x.Op != token.MUL {
				return nil
			}
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		case *ssa.Convert:
			v = x.X
		case *ssa.FieldAddr:
			return x
		case *ssa.Field:
			// A field read from a non-addressable struct value. There is no
			// FieldAddr to key on, but the same identity applies.
			return nil
		default:
			return nil
		}
	}
	return nil
}

// withFieldCandidates returns funcs extended with every function reachable
// from a func-typed field, and with what those functions themselves call.
//
// collectFunctions seeds from package members and walks the *static* call
// graph, so a function that is only ever reached by being stored in a field is
// not in the set: nothing calls it statically. A method value is the sharpest
// case — go-test-bench registers its SQL handler as
// `Handler: sqliteInj{}.execHandler`, which SSA compiles to a synthetic $bound
// thunk that is neither a package member nor a nested function of one. Missing
// from the set, it gets no summary, its edge is dropped from the SCC
// condensation, and the (*sql.DB).Exec inside it is unreachable however well
// the dispatch itself resolves.
func (e *Engine) withFieldCandidates(funcs []*ssa.Function) []*ssa.Function {
	if len(e.funcsByField) == 0 {
		return funcs
	}
	present := make(map[*ssa.Function]bool, len(funcs))
	for _, fn := range funcs {
		present[fn] = true
	}
	var queue []*ssa.Function
	for _, candidates := range e.funcsByField {
		for _, candidate := range candidates {
			if candidate != nil && !present[candidate] {
				present[candidate] = true
				funcs = append(funcs, candidate)
				queue = append(queue, candidate)
			}
		}
	}
	// A $bound thunk's whole body is a call to the method it wraps, so
	// stopping at the thunk would gain nothing. Walk what the new functions
	// call, by the same static-callee rule collectFunctions uses.
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				var common *ssa.CallCommon
				switch c := instr.(type) {
				case *ssa.Call:
					common = c.Common()
				case *ssa.Go:
					common = c.Common()
				case *ssa.Defer:
					common = c.Common()
				default:
					continue
				}
				callee := common.StaticCallee()
				if callee == nil || present[callee] || len(callee.Blocks) == 0 {
					continue
				}
				present[callee] = true
				funcs = append(funcs, callee)
				queue = append(queue, callee)
			}
		}
	}
	sortFunctions(funcs)
	return funcs
}

// staticCalleesOf reads a function's statically-resolved callees directly from
// its SSA body, for functions the call graph has no node for.
func staticCalleesOf(fn *ssa.Function) []*ssa.Function {
	if fn == nil {
		return nil
	}
	var out []*ssa.Function
	seen := map[*ssa.Function]bool{}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			var common *ssa.CallCommon
			switch c := instr.(type) {
			case *ssa.Call:
				common = c.Common()
			case *ssa.Go:
				common = c.Common()
			case *ssa.Defer:
				common = c.Common()
			default:
				continue
			}
			callee := common.StaticCallee()
			if callee == nil || seen[callee] {
				continue
			}
			seen[callee] = true
			out = append(out, callee)
		}
	}
	return out
}
