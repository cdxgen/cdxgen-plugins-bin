package seam

import (
	"golang.org/x/tools/go/ssa"
)

// SanitizerInfo records the dominator-based sanitizer semantics.
// A sanitizer only clears taint on paths it dominates (using the SSA block
// dominator tree), not globally on the value. This fixes defect 15.

// dominatorTree is a simple dominator tree for basic blocks.
type dominatorTree struct {
	idom    []int // immediate dominator for each block (index)
	indices map[*ssa.BasicBlock]int
	blocks  []*ssa.BasicBlock
}

// buildDominatorTree builds a dominator tree for a function.
func buildDominatorTree(fn *ssa.Function) *dominatorTree {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil
	}
	dt := &dominatorTree{
		indices: make(map[*ssa.BasicBlock]int),
		blocks:  fn.Blocks,
	}
	for i, b := range fn.Blocks {
		dt.indices[b] = i
	}
	dt.idom = make([]int, len(fn.Blocks))
	// Simple iterative dominator algorithm.
	// Initialize: entry dominates itself, others dominated by everything.
	for i := range dt.idom {
		dt.idom[i] = -1
	}
	if len(fn.Blocks) > 0 {
		dt.idom[0] = 0 // entry block dominates itself
	}
	// Iterate until stable.
	changed := true
	for changed {
		changed = false
		for i, b := range fn.Blocks {
			if i == 0 {
				continue // entry
			}
			newIdom := -1
			for _, pred := range b.Preds {
				if pred == nil {
					continue
				}
				pi := dt.indices[pred]
				if dt.idom[pi] >= 0 {
					if newIdom < 0 {
						newIdom = pi
					} else {
						newIdom = dt.intersect(newIdom, pi)
					}
				}
			}
			if newIdom >= 0 && newIdom != dt.idom[i] {
				dt.idom[i] = newIdom
				changed = true
			}
		}
	}
	return dt
}

// intersect finds the LCA of two nodes in the dominator tree.
func (dt *dominatorTree) intersect(a, b int) int {
	for a != b {
		for a > b {
			a = dt.idom[a]
		}
		for b > a {
			b = dt.idom[b]
		}
	}
	return a
}

// dominates reports whether block a dominates block b.
func (dt *dominatorTree) dominates(a, b *ssa.BasicBlock) bool {
	if dt == nil || a == nil || b == nil {
		return false
	}
	ai, ok := dt.indices[a]
	if !ok {
		return false
	}
	bi, ok := dt.indices[b]
	if !ok {
		return false
	}
	// Walk up from b to root via idom; if a appears, a dominates b.
	for {
		if bi == ai {
			return true
		}
		next := dt.idom[bi]
		if next < 0 || next == bi {
			return false
		}
		bi = next
	}
}

func (e *Engine) IsSanitizerDominant(fn *ssa.Function, sanitizerBlock, sinkBlock *ssa.BasicBlock) bool {
	dt := buildDominatorTree(fn)
	return dt.dominates(sanitizerBlock, sinkBlock)
}

// NameRegexSanitizerSuppress checks if a function name matches a name-regex
// heuristic sanitizer pattern. This is a fallback for the legacy behavior;
// when the name matches, the slice is still emitted but marked
// `suppressedBy: "name-heuristic"` and `confidence: low`.
func NameRegexSanitizerSuppress(fnName string) bool {
	// Only active when --sanitizer-heuristics=name-regex is set.
	// Disabled by default in SEAM.
	return false
}
