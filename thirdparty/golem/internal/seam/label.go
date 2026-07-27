// Package seam implements the SEAM (Summary Evaluation Across Modules) taint
// engine. It replaces the legacy dataflow engine with a sound intra-procedural
// fixpoint, SCC-based interprocedural summaries, whole-program dependency
// analysis, and structured model matching.
package seam

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// TaintLabel tracks one taint source through the program. A value can carry
// multiple labels, and a sink emits one slice per label that reaches it.
// Labels carry an immutable parent chain (Step pointers) for path
// reconstruction on demand, never accumulated in a ring buffer.
type TaintLabel struct {
	// ID is a unique identifier for this label, stable across runs.
	ID string
	// SourceID is the node ID of the source that introduced this taint.
	SourceID string
	// SourceCategory is the category of the source (e.g. "http-input").
	SourceCategory string
	// SourcePURL is the purl of the source package.
	SourcePURL string
	// SourcePatterns are the model patterns that matched the source.
	SourcePatterns []SourcePattern
	// TaintKinds are the kinds of taint carried (e.g. "user-input", "secret").
	TaintKinds []string
	// Confidence is the confidence level of the taint.
	Confidence string
	// Provenance records how the label was introduced.
	Provenance string
	// SourceNode describes the report node for the source, registered only if a
	// slice is emitted. Describing it rather than creating it keeps the report
	// free of nodes for taint that never reached a sink.
	SourceNode *Step
	// Parent is the previous step in the taint propagation chain.
	// nil means this label is at its source.
	Parent *Step
	// FieldPaths tracks the access path fields traversed.
	FieldPaths []string
	// SanitizedCategories records categories that have been sanitized along
	// this path.
	SanitizedCategories []string
	// Generated is true when the label was introduced by a model source
	// pattern rather than direct user input.
	Generated bool
	// PathTruncated is set to true when the path was truncated because it
	// exceeded the maximum path length. Both ends of the path are kept.
	PathTruncated bool
	// DependencyHops counts how many dependency boundaries the taint has crossed.
	DependencyHops int
	// CrossesDependency is true when the taint crosses at least one dependency
	// boundary.
	CrossesDependency bool
}

// String returns a short description of the label.
func (l TaintLabel) String() string {
	return fmt.Sprintf("label[%s src=%s cat=%s]", l.ID[:min(8, len(l.ID))], l.SourceCategory, strings.Join(l.TaintKinds, ","))
}

// Clone returns a shallow copy of the label suitable for extending with a new
// parent step. The Parent is NOT copied — the caller sets the new parent.
func (l TaintLabel) Clone() TaintLabel {
	cp := TaintLabel{
		ID:                  l.ID,
		SourceID:            l.SourceID,
		SourceCategory:      l.SourceCategory,
		SourcePURL:          l.SourcePURL,
		TaintKinds:          copyStrings(l.TaintKinds),
		Confidence:          l.Confidence,
		Provenance:          l.Provenance,
		Parent:              l.Parent,
		FieldPaths:          copyStrings(l.FieldPaths),
		SanitizedCategories: copyStrings(l.SanitizedCategories),
		Generated:           l.Generated,
		PathTruncated:       l.PathTruncated,
		DependencyHops:      l.DependencyHops,
		CrossesDependency:   l.CrossesDependency,
	}
	if len(l.SourcePatterns) > 0 {
		cp.SourcePatterns = make([]SourcePattern, len(l.SourcePatterns))
		copy(cp.SourcePatterns, l.SourcePatterns)
	}
	return cp
}

// WithParent returns a copy with a new parent step prepended.
func (l TaintLabel) WithParent(step *Step) TaintLabel {
	if step == nil {
		return l
	}
	step.Parent = l.Parent
	out := l
	out.Parent = step
	if step.CrossesDependency {
		out.CrossesDependency = true
		out.DependencyHops = l.DependencyHops + 1
	}
	if step.FieldPath != "" {
		out.FieldPaths = uniqueStringsSorted(append(copyStrings(l.FieldPaths), step.FieldPath))
	}
	return out
}

// PathLen returns the number of hops travelled from the source.
func (l TaintLabel) PathLenHops() int { return l.Parent.Depth() }

func (l TaintLabel) IsEmpty() bool {
	return l.ID == "" && l.SourceID == ""
}

// AllowsSink reports whether the label's taint is allowed to reach a sink
// of the given category (i.e., it has not been sanitized for that category).
func (l TaintLabel) AllowsSink(category string) bool {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		return true
	}
	for _, sanitized := range l.SanitizedCategories {
		if strings.EqualFold(sanitized, category) {
			return false
		}
	}
	return true
}

// PathLen returns the number of steps from this label to the source.
func (l TaintLabel) PathLen() int {
	n := 0
	for s := l.Parent; s != nil; s = s.Parent {
		n++
	}
	return n
}

// MaterializePath walks the parent chain and returns the node IDs, edge IDs,
// edge kinds, and whether the path was truncated. nodeIDs are in source→sink
// order.
// Steps returns the propagation chain from source to the label's current
// position.
func (l TaintLabel) Steps() []*Step {
	return l.Parent.Chain()
}

// LabelSet is a set of taint labels carried by a value. It provides set-like
// merge operations.
type LabelSet struct {
	labels []TaintLabel
}

// NewLabelSet creates an empty label set.
func NewLabelSet() LabelSet {
	return LabelSet{}
}

// LabelSetOf creates a label set containing the given label.
func LabelSetOf(l TaintLabel) LabelSet {
	if l.IsEmpty() {
		return LabelSet{}
	}
	return LabelSet{labels: []TaintLabel{l}}
}

// Add inserts a label, keeping one route per label identity.
//
// When the same taint arrives by two routes the shorter one is kept, ties
// broken by a deterministic signature. Choosing canonically is what makes the
// merge commutative, and therefore what allows the block fixpoint to converge
// to the same answer regardless of the order blocks happen to be visited.
func (ls LabelSet) Add(l TaintLabel) LabelSet {
	if l.IsEmpty() {
		return ls
	}
	for i, existing := range ls.labels {
		if existing.ID != l.ID {
			continue
		}
		if preferLabel(l, existing) {
			out := LabelSet{labels: append([]TaintLabel{}, ls.labels...)}
			out.labels[i] = l
			return out
		}
		return ls
	}
	return LabelSet{labels: append(append([]TaintLabel{}, ls.labels...), l)}
}

// preferLabel reports whether candidate is the better route to keep.
func preferLabel(candidate, existing TaintLabel) bool {
	candidateHops, existingHops := candidate.Parent.Depth(), existing.Parent.Depth()
	if candidateHops != existingHops {
		return candidateHops < existingHops
	}
	return candidate.Parent.signature() < existing.Parent.signature()
}

// Merge returns the union of two label sets.
func (ls LabelSet) Merge(other LabelSet) LabelSet {
	if other.IsEmpty() {
		return ls
	}
	if ls.IsEmpty() {
		return other
	}
	result := ls
	for _, l := range other.labels {
		result = result.Add(l)
	}
	return result
}

// IsEmpty reports whether the set contains no labels.
func (ls LabelSet) IsEmpty() bool {
	return len(ls.labels) == 0
}

// Len returns the number of labels in the set.
func (ls LabelSet) Len() int {
	return len(ls.labels)
}

// Labels returns the underlying slice. The caller must not modify it.
func (ls LabelSet) Labels() []TaintLabel {
	return ls.labels
}

// FilterBySink returns labels whose taint is allowed for the given sink category.
func (ls LabelSet) FilterBySink(category string) LabelSet {
	if category == "" {
		return ls
	}
	filtered := make([]TaintLabel, 0, len(ls.labels))
	for _, l := range ls.labels {
		if l.AllowsSink(category) {
			filtered = append(filtered, l)
		}
	}
	return LabelSet{labels: filtered}
}

// FilterByTaintKind returns labels carrying any of the given taint kinds.
func (ls LabelSet) FilterByTaintKind(kinds ...string) LabelSet {
	if len(kinds) == 0 {
		return ls
	}
	kindSet := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		kindSet[strings.ToLower(k)] = true
	}
	filtered := make([]TaintLabel, 0, len(ls.labels))
	for _, l := range ls.labels {
		for _, k := range l.TaintKinds {
			if kindSet[strings.ToLower(k)] {
				filtered = append(filtered, l)
				break
			}
		}
	}
	return LabelSet{labels: filtered}
}

// RemoveTaintKinds returns labels with the given taint kinds removed.
func (ls LabelSet) RemoveTaintKinds(kinds ...string) LabelSet {
	if len(kinds) == 0 {
		return ls
	}
	remove := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		remove[strings.ToLower(k)] = true
	}
	result := make([]TaintLabel, 0, len(ls.labels))
	for _, l := range ls.labels {
		kept := make([]string, 0, len(l.TaintKinds))
		for _, k := range l.TaintKinds {
			if !remove[strings.ToLower(k)] {
				kept = append(kept, k)
			}
		}
		if len(kept) == 0 {
			continue
		}
		cp := l.Clone()
		cp.TaintKinds = kept
		result = append(result, cp)
	}
	return LabelSet{labels: result}
}

// AddSanitizedCategories adds sanitized categories to all labels.
func (ls LabelSet) AddSanitizedCategories(categories ...string) LabelSet {
	if len(categories) == 0 {
		return ls
	}
	result := make([]TaintLabel, 0, len(ls.labels))
	for _, l := range ls.labels {
		cp := l.Clone()
		cp.SanitizedCategories = mergeStrings(cp.SanitizedCategories, categories)
		result = append(result, cp)
	}
	return LabelSet{labels: result}
}

// SourcePattern is a simplified source pattern for labels.
type SourcePattern struct {
	Category   string
	TaintKinds []string
	Confidence string
	Pattern    string
	PURL       string
}

// NewLabelID returns a stable, deterministic label identifier.
// NewLabelID derives a label identity from the source site alone.
//
// NewLabelID derives a stable label identity from a source node ID. It deliberately
// takes no sequence number for source-derived labels: a counter would mint a fresh
// identity every time a value was revisited, so a set could never stop growing
// and the fixpoint would never terminate.
func NewLabelID(sourceNodeID string, _ int) string {
	return stableID("seam-label", sourceNodeID)
}

// NewParamLabelID derives a label identity for a parameter or free variable.
// Unlike NewLabelID, it incorporates the index, because two parameters of the
// same function must have distinct identities for summary ParamSink matching to
// attribute a sink to the correct parameter.
func NewParamLabelID(sourceNodeID string, idx int) string {
	return stableID("seam-label", sourceNodeID, fmt.Sprint(idx))
}

func stableID(parts ...string) string {
	joined := strings.Join(parts, "|")
	if len(joined) < 180 {
		return joined
	}
	sum := sha256.Sum256([]byte(joined))
	return parts[0] + "|sha256:" + hex.EncodeToString(sum[:])
}

func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func uniqueStringsSorted(in []string) []string {
	return mergeStrings(in, nil)
}

// WithRealSource returns the labels that name a source the report defines,
// dropping parameter labels.
//
// A parameter label is meaningful only inside the summary of the function whose
// parameter it describes; it has no source node, so anything published outside
// that scope and later materialised produces a slice that cannot name where its
// taint came from.
func (ls LabelSet) WithRealSource() LabelSet {
	kept := make([]TaintLabel, 0, len(ls.labels))
	for _, l := range ls.labels {
		if l.Provenance == "parameter" || l.SourceNode == nil {
			continue
		}
		kept = append(kept, l)
	}
	if len(kept) == len(ls.labels) {
		return ls
	}
	return LabelSet{labels: kept}
}
