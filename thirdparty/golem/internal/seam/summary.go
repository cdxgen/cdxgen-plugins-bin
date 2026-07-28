package seam

import (
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// FuncSummary captures the taint behaviour of a function. It is computed
// bottom-up over the call graph's SCC condensation and stored by the engine.
type FuncSummary struct {
	// Func is the SSA function this summary describes.
	Func *ssa.Function
	// FuncID is the stable identifier (fn.String() or fn.Origin().String()).
	FuncID string

	// ParamReturn maps parameter index → effect on return value.
	// A parameter whose taint flows to the return value.
	ParamReturn map[int][]TaintEffect

	// ParamSink maps parameter index → sink categories reached inside the function.
	// When a tainted argument reaches a sink within this function.
	ParamSink map[int][]SinkEffect

	// ReceiverFieldWrites maps receiver field path keys → parameter indices that write them.
	ReceiverFieldWrites map[string][]int

	// ArgumentWrites records argument indices whose pointee is written from
	// the combined argument taint. The summary lattice equivalent of the
	// legacy writesToArguments pattern: a function that fills memory reached
	// through one of its arguments (io.Copy fills dst; json.Unmarshal fills
	// the value behind the pointer) deposits taint there, and the summary
	// must carry that effect for the caller to see it.
	ArgumentWrites []int

	// ParamArgumentWrites maps source parameter index → argument indices
	// that the parameter's taint is written into, detected from the function
	// body. This is the SSA-derived complement to ArgumentWrites, used when a
	// user-written helper writes *argN from one specific parameter rather
	// than from the merged argument set.
	ParamArgumentWrites map[int][]int

	// SourceReturns records that this function introduces new taint sources
	// into its return value.
	SourceReturns []SourcePattern

	// Sanitizes maps parameter index → categories/tintkinds this function sanitizes.
	Sanitizes map[int][]SanitizeEffect

	// Aliases records that param i and param j may alias after the call.
	Aliases map[int]int

	// Passthrough is true when the function passes all arguments through to the
	// return without modification.
	Passthrough bool

	// IsSummarized is true once the summary has been computed.
	IsSummarized bool

	// IterationCount records how many iterations were needed to reach fixpoint.
	IterationCount int

	// HitCap is true when the SCC iteration cap was reached.
	HitCap bool
}

// TaintEffect describes how a tainted parameter affects the return value.
type TaintEffect struct {
	// TaintKinds carried through.
	TaintKinds []string
	// FieldPaths on the return value affected.
	FieldPaths []string
	// Confidence level.
	Confidence string
}

// SinkEffect describes a sink reached by a tainted parameter.
type SinkEffect struct {
	// Category is the sink category (e.g. "command-execution").
	Category string
	// TaintKinds that trigger the sink.
	TaintKinds []string
	// ArgumentIndex is which argument position the sink applies to.
	ArgumentIndex int
	// SinkSymbol is the qualified name of the sink call inside the function.
	SinkSymbol string
	// SinkName is the display name of the sink call.
	SinkName string
	// SinkType is the return type of the sink call, if any.
	SinkType string
	// Pos is the source position of the sink call.
	Pos token.Pos
	// ModelID is the model entry identifier that matched the sink.
	ModelID string
	// Severity, Confidence, RuleID, RuleName, RiskScore mirror the model entry.
	Severity   string
	Confidence string
	RuleID     string
	RuleName   string
	RiskScore  int
}

// SanitizeEffect describes how a function sanitizes its input.
type SanitizeEffect struct {
	// RemovesCategories clears these sink categories for the tainted value.
	RemovesCategories []string
	// RemovesTaintKinds removes these taint kinds.
	RemovesTaintKinds []string
	// Dominates is true when the sanitizer dominates the path to return.
	Dominates bool
}

// NewSummary creates an empty summary for a function.
func NewSummary(fn *ssa.Function) *FuncSummary {
	funcID := fn.String()
	if fn.Origin() != nil {
		funcID = fn.Origin().String()
	}
	return &FuncSummary{
		Func:                fn,
		FuncID:              funcID,
		ParamReturn:         make(map[int][]TaintEffect),
		ParamSink:           make(map[int][]SinkEffect),
		ReceiverFieldWrites: make(map[string][]int),
		Sanitizes:           make(map[int][]SanitizeEffect),
		Aliases:             make(map[int]int),
	}
}

// OriginKey returns the key used for generic origin lookup.
func (s *FuncSummary) OriginKey() string {
	if s.Func == nil {
		return s.FuncID
	}
	if origin := s.Func.Origin(); origin != nil {
		return origin.String()
	}
	return s.FuncID
}

// AddParamReturn records that parameter idx flows to the return value.
func (s *FuncSummary) AddParamReturn(idx int, kinds []string, confidence string) bool {
	existing := s.ParamReturn[idx]
	for _, e := range existing {
		if stringsJoin(e.TaintKinds) == stringsJoin(kinds) {
			return false
		}
	}
	s.ParamReturn[idx] = append(existing, TaintEffect{
		TaintKinds: copyStrings(kinds),
		Confidence: firstNonEmptyStr(confidence, "medium"),
	})
	return true
}

// AddParamSink records that parameter idx reaches a sink of the given category.
func (s *FuncSummary) AddParamSink(idx int, effect SinkEffect) bool {
	cat := strings.ToLower(effect.Category)
	existing := s.ParamSink[idx]
	for _, e := range existing {
		if strings.EqualFold(e.Category, cat) && strings.EqualFold(e.SinkSymbol, effect.SinkSymbol) {
			return false
		}
	}
	effect.Category = cat
	s.ParamSink[idx] = append(existing, effect)
	return true
}

// AddParamArgumentWrite records that parameter srcParam writes its taint into
// the memory location pointed to by argument dstArgIdx. Returns true when the
// summary grew.
func (s *FuncSummary) AddParamArgumentWrite(srcParam, dstArgIdx int) bool {
	if s.ParamArgumentWrites == nil {
		s.ParamArgumentWrites = map[int][]int{}
	}
	for _, existing := range s.ParamArgumentWrites[srcParam] {
		if existing == dstArgIdx {
			return false
		}
	}
	s.ParamArgumentWrites[srcParam] = append(s.ParamArgumentWrites[srcParam], dstArgIdx)
	return true
}

// AddReceiverFieldWrite records a receiver field written by a parameter.
func (s *FuncSummary) AddReceiverFieldWrite(fieldKey string, paramIdx int) bool {
	for _, idx := range s.ReceiverFieldWrites[fieldKey] {
		if idx == paramIdx {
			return false
		}
	}
	s.ReceiverFieldWrites[fieldKey] = append(s.ReceiverFieldWrites[fieldKey], paramIdx)
	return true
}

// AddSourceReturn records a source pattern that the function introduces.
func (s *FuncSummary) AddSourceReturn(sp SourcePattern) bool {
	for _, existing := range s.SourceReturns {
		if existing.Category == sp.Category && existing.Pattern == sp.Pattern {
			return false
		}
	}
	s.SourceReturns = append(s.SourceReturns, sp)
	return true
}

// AddSanitize records that parameter idx is sanitized.
func (s *FuncSummary) AddSanitize(idx int, removesCategories, removesKinds []string) bool {
	existing := s.Sanitizes[idx]
	for _, e := range existing {
		if setsEqual(e.RemovesCategories, removesCategories) && setsEqual(e.RemovesTaintKinds, removesKinds) {
			return false
		}
	}
	s.Sanitizes[idx] = append(existing, SanitizeEffect{
		RemovesCategories: copyStrings(removesCategories),
		RemovesTaintKinds: copyStrings(removesKinds),
	})
	return true
}

// NumParams returns the number of parameters (including receiver for methods).
func (s *FuncSummary) NumParams() int {
	if s.Func == nil || s.Func.Signature == nil {
		return 0
	}
	n := s.Func.Signature.Params().Len()
	if s.Func.Signature.Recv() != nil {
		n++
	}
	return n
}

// HasReceiver reports whether the function has a receiver.
func (s *FuncSummary) HasReceiver() bool {
	return s.Func != nil && s.Func.Signature != nil && s.Func.Signature.Recv() != nil
}

// Changed reports whether two summaries differ.
func (s *FuncSummary) Changed(other *FuncSummary) bool {
	if s == nil || other == nil {
		return s != other
	}
	if len(s.ParamReturn) != len(other.ParamReturn) {
		return true
	}
	if len(s.ParamSink) != len(other.ParamSink) {
		return true
	}
	if len(s.ReceiverFieldWrites) != len(other.ReceiverFieldWrites) {
		return true
	}
	if len(s.ArgumentWrites) != len(other.ArgumentWrites) {
		return true
	}
	if len(s.ParamArgumentWrites) != len(other.ParamArgumentWrites) {
		return true
	}
	if len(s.SourceReturns) != len(other.SourceReturns) {
		return true
	}
	if len(s.Sanitizes) != len(other.Sanitizes) {
		return true
	}
	return false
}

func stringsJoin(ss []string) string {
	sort.Strings(ss)
	return strings.Join(ss, ",")
}

func setsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := make([]string, len(a))
	sb := make([]string, len(b))
	copy(sa, a)
	copy(sb, b)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
