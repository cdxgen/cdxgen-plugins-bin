package seam

import (
	"go/token"
	"strconv"
)

// Step is an immutable node in a taint propagation chain. Each step records one
// hop — a call return, a store, a load, an interprocedural transfer — and links
// back to the previous hop through Parent, so a label always knows the whole
// route it travelled.
//
// A step carries everything needed to materialise a report node, rather than a
// node identifier alone. Nodes are therefore registered only for paths that
// actually reach a sink: the report never contains an unreferenced node, and a
// slice can never reference a node the report does not define.
type Step struct {
	// Kind is the node kind, such as "call", "store" or "load".
	Kind string
	// EdgeKind describes the transfer, such as "call-return" or "store".
	EdgeKind string
	// Name and Symbol describe the program element at this hop.
	Name   string
	Symbol string
	// Type is the Go type of the value at this hop, when known.
	Type string
	// FunctionID is the enclosing SSA function.
	FunctionID string
	// PackagePath is the package the hop occurs in, used for module attribution.
	PackagePath string
	// FieldPath records an access path traversed at this hop.
	FieldPath string
	// Pos is the source position.
	Pos token.Pos
	// CrossesDependency marks a hop that leaves the module under analysis.
	CrossesDependency bool
	// Properties carries node attributes that only some hops have, such as a
	// sanitizer's sanitizesCategories. It reaches the report unchanged.
	Properties map[string]string
	// Parent is the previous hop, closer to the source. A nil parent means the
	// previous hop is the source itself.
	Parent *Step

	// Cached signature for route comparison. Steps are immutable after
	// creation, so computing the signature twice yields the same value; the
	// cache just avoids the O(depth) walk on repeated comparisons.
	sigCache string
	sigDone  bool
}

// NodeID returns the deterministic identifier for this hop's report node.
//
// Identity is the program location and role, never a counter: the same hop
// discovered twice during a fixpoint must produce the same node, or the
// analysis cannot converge and its output cannot be compared between runs.
func (s *Step) NodeID(positionKey string) string {
	if s == nil {
		return ""
	}
	return stableID("seam-node", s.Kind, s.FunctionID, s.Symbol, s.Name, s.FieldPath, positionKey)
}

// EdgeID returns the deterministic identifier for the edge into this hop.
func (s *Step) EdgeID(previousNodeID, nodeID string) string {
	if s == nil || previousNodeID == "" || nodeID == "" {
		return ""
	}
	return stableID("seam-edge", previousNodeID, nodeID, s.EdgeKind)
}

// Depth returns the number of hops from the source to this step.
func (s *Step) Depth() int {
	depth := 0
	for cur := s; cur != nil; cur = cur.Parent {
		depth++
	}
	return depth
}

// Chain returns the steps from source to this step, in order.
func (s *Step) Chain() []*Step {
	var reversed []*Step
	for cur := s; cur != nil; cur = cur.Parent {
		reversed = append(reversed, cur)
	}
	chain := make([]*Step, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		chain = append(chain, reversed[i])
	}
	return chain
}

// signature is a deterministic description of the whole chain, used to choose
// canonically between two routes of the same length. Cached on first call;
// Steps are immutable so this is safe.
func (s *Step) signature() string {
	if s == nil {
		return ""
	}
	if !s.sigDone {
		// Composed from the parent's signature rather than re-walking the
		// chain, so a chain of n steps costs O(n) in total instead of O(n^2).
		// This orders the string tail-first, where Chain() walks root-first.
		// The signature is only ever compared against another signature to
		// break a tie between two equal-length routes, so any total order will
		// do — but it is not the same order, and it therefore picks a
		// different (still deterministic) winner than the root-first form did.
		out := make([]byte, 0, len(s.Kind)+len(s.Symbol)+24)
		out = append(out, s.Kind...)
		out = append(out, '|')
		out = append(out, s.Symbol...)
		out = append(out, '|')
		out = strconv.AppendInt(out, int64(s.Pos), 10)
		out = append(out, ';')
		s.sigCache = string(out) + s.Parent.signature()
		s.sigDone = true
	}
	return s.sigCache
}

func (s *Step) String() string {
	if s == nil {
		return "<source>"
	}
	return "step[" + s.EdgeKind + " " + s.Symbol + "]"
}
