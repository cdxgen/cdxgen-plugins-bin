package seam

import "testing"

// TestStateMergeIsMonotoneAndTerminating checks the property that lets the block
// worklist stop: merging the same information twice must report no change.
func TestStateMergeIsMonotoneAndTerminating(t *testing.T) {
	a, b := newTaintState(), newTaintState()
	b.memory["alloc:x"] = LabelSetOf(label("a", 1))

	if !a.mergeInto(b) {
		t.Fatal("merging new information reported no change")
	}
	if a.mergeInto(b) {
		t.Fatal("merging the same information twice reported a change; the worklist would never drain")
	}
}

// TestStateMergePrefersShorterRoutes lets a later, better witness replace an
// earlier one without the set growing.
func TestStateMergePrefersShorterRoutes(t *testing.T) {
	current, incoming := newTaintState(), newTaintState()
	current.memory["k"] = LabelSetOf(label("a", 4))
	incoming.memory["k"] = LabelSetOf(label("a", 2))

	if !current.mergeInto(incoming) {
		t.Fatal("a shorter route was not treated as progress")
	}
	if got := current.memory["k"].Labels()[0].Parent.Depth(); got != 2 {
		t.Errorf("kept a %d-hop route after merging a 2-hop one", got)
	}
	if current.memory["k"].Len() != 1 {
		t.Errorf("the set grew to %d labels instead of replacing the route", current.memory["k"].Len())
	}
}

func TestStateCloneIsIndependent(t *testing.T) {
	original := newTaintState()
	original.memory["k"] = LabelSetOf(label("a", 1))
	copied := original.clone()
	copied.memory["k2"] = LabelSetOf(label("b", 1))
	if _, leaked := original.memory["k2"]; leaked {
		t.Error("writing to a cloned state mutated the original")
	}
}
