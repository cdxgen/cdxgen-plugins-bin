package seam

import (
	"testing"
)

func label(id string, hops int) TaintLabel {
	l := TaintLabel{ID: id, SourceID: "src-" + id, SourceCategory: "http-input", TaintKinds: []string{"user-input"}}
	for i := 0; i < hops; i++ {
		l = l.WithParent(&Step{Kind: "call", EdgeKind: "call-return", Symbol: "hop", Pos: 1})
	}
	return l
}

// TestLabelIdentityIgnoresRoute is the property the whole fixpoint rests on: the
// same taint arriving twice is one label, not two. A label identity that varied
// with the route — or with a counter — would let a set grow without bound and
// the iteration would never terminate.
func TestLabelIdentityIgnoresRoute(t *testing.T) {
	short, long := label("a", 1), label("a", 5)
	set := LabelSetOf(short).Add(long)
	if set.Len() != 1 {
		t.Fatalf("two routes to the same taint produced %d labels, want 1", set.Len())
	}
	if got := set.Labels()[0].Parent.Depth(); got != 1 {
		t.Errorf("kept a %d-hop route, want the 1-hop one", got)
	}
}

// TestLabelMergeIsCommutative keeps the block join order-independent, which is
// what makes the fixpoint deterministic.
func TestLabelMergeIsCommutative(t *testing.T) {
	short, long := label("a", 2), label("a", 6)
	forward := LabelSetOf(short).Merge(LabelSetOf(long))
	backward := LabelSetOf(long).Merge(LabelSetOf(short))
	if forward.Len() != backward.Len() {
		t.Fatalf("merge is not commutative in size: %d vs %d", forward.Len(), backward.Len())
	}
	if forward.Labels()[0].Parent.Depth() != backward.Labels()[0].Parent.Depth() {
		t.Errorf("merge order changed the route kept: %d vs %d",
			forward.Labels()[0].Parent.Depth(), backward.Labels()[0].Parent.Depth())
	}
}

func TestLabelSetKeepsDistinctSources(t *testing.T) {
	set := LabelSetOf(label("a", 1)).Add(label("b", 1))
	if set.Len() != 2 {
		t.Fatalf("two distinct sources collapsed into %d label(s)", set.Len())
	}
}

// TestNewLabelIDIsStable guards against reintroducing a counter in the identity.
func TestNewLabelIDIsStable(t *testing.T) {
	first := NewLabelID("seam-source|pkg.Handler|model", 0)
	second := NewLabelID("seam-source|pkg.Handler|model", 99)
	if first != second {
		t.Errorf("label identity depends on a sequence number: %q vs %q", first, second)
	}
}

func TestWithParentBuildsAnOrderedChain(t *testing.T) {
	l := TaintLabel{ID: "a", SourceID: "src"}
	l = l.WithParent(&Step{Kind: "call", Symbol: "first"})
	l = l.WithParent(&Step{Kind: "store", Symbol: "second"})
	chain := l.Steps()
	if len(chain) != 2 {
		t.Fatalf("chain has %d steps, want 2", len(chain))
	}
	if chain[0].Symbol != "first" || chain[1].Symbol != "second" {
		t.Errorf("chain is not in source-to-sink order: %s then %s", chain[0].Symbol, chain[1].Symbol)
	}
}

func TestWithParentTracksDependencyCrossings(t *testing.T) {
	l := TaintLabel{ID: "a", SourceID: "src"}
	l = l.WithParent(&Step{Kind: "call", CrossesDependency: true})
	l = l.WithParent(&Step{Kind: "call"})
	l = l.WithParent(&Step{Kind: "call", CrossesDependency: true})
	if !l.CrossesDependency || l.DependencyHops != 2 {
		t.Errorf("crossesDependency=%v hops=%d, want true and 2", l.CrossesDependency, l.DependencyHops)
	}
}

func TestStepIdentityIsPositional(t *testing.T) {
	a := &Step{Kind: "call", FunctionID: "pkg.F", Symbol: "os/exec.Command", Name: "Command"}
	b := &Step{Kind: "call", FunctionID: "pkg.F", Symbol: "os/exec.Command", Name: "Command"}
	if a.NodeID("main.go:10:2") != b.NodeID("main.go:10:2") {
		t.Error("identical hops at the same position produced different node identities")
	}
	if a.NodeID("main.go:10:2") == a.NodeID("main.go:11:2") {
		t.Error("hops at different positions collapsed to one node identity")
	}
}

func TestAllowsSinkRespectsSanitizedCategories(t *testing.T) {
	l := TaintLabel{ID: "a", SourceID: "src", SanitizedCategories: []string{"filesystem"}}
	if l.AllowsSink("filesystem") {
		t.Error("a sanitised category still reached its sink")
	}
	if !l.AllowsSink("command-execution") {
		t.Error("sanitising one category suppressed an unrelated one")
	}
}
