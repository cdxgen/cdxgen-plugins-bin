package seam

import (
	"fmt"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// AccessPath represents a typed access path for field-sensitive taint tracking.
// It replaces the legacy string-concatenated addrKey with a structured
// representation that supports field names, k-limiting, and Steensgaard unification.
type AccessPath struct {
	// Base identifies the root of the access path.
	Base BaseRef
	// Steps are the path elements from base to the current value.
	Steps []PathStep
}

// BaseRef identifies a root variable or allocation.
type BaseRef struct {
	Kind  BaseKind
	Name  string // human-readable name
	ID    string // stable identifier
	Type  string // type string
	FnID  string // enclosing function, if local
	Pkg   string // package path, if global
	Index int    // parameter index, if parameter
}

// BaseKind classifies the root of an access path.
type BaseKind int

const (
	BaseLocal     BaseKind = iota // local SSA value (Alloc, etc.)
	BaseGlobal                    // package-level variable
	BaseParameter                 // function parameter
	BaseHeap                      // heap-allocated (via & escaping)
	BaseResult                    // function result
	BaseConst                     // constant value
)

func (k BaseKind) String() string {
	switch k {
	case BaseLocal:
		return "local"
	case BaseGlobal:
		return "global"
	case BaseParameter:
		return "param"
	case BaseHeap:
		return "heap"
	case BaseResult:
		return "result"
	case BaseConst:
		return "const"
	default:
		return "unknown"
	}
}

// PathStep is one step in an access path.
type PathStep struct {
	Kind      PathStepKind
	FieldName string // Go field name, when Kind is PathField
	FieldIdx  int    // field index, when Kind is PathField
}

// PathStepKind classifies an access path step.
type PathStepKind int

const (
	PathField    PathStepKind = iota // struct field access
	PathIndex                        // array/slice index
	PathDeref                        // pointer dereference
	PathMapValue                     // map value
	PathChanElem                     // channel element
	PathWiden                        // widening past k-limit
)

func (k PathStepKind) String() string {
	switch k {
	case PathField:
		return "field"
	case PathIndex:
		return "index"
	case PathDeref:
		return "deref"
	case PathMapValue:
		return "map"
	case PathChanElem:
		return "chan"
	case PathWiden:
		return "*"
	default:
		return "?"
	}
}

// String returns the human-readable access path.
func (ap AccessPath) String() string {
	var b strings.Builder
	b.WriteString(ap.Base.Kind.String())
	b.WriteString(":")
	b.WriteString(ap.Base.Name)
	for _, s := range ap.Steps {
		b.WriteString(".")
		b.WriteString(s.FieldName)
	}
	return b.String()
}

// FieldPath returns the field path string for backward compatibility (e.g., "field0.field1").
func (ap AccessPath) FieldPath() string {
	parts := make([]string, 0, len(ap.Steps))
	for _, s := range ap.Steps {
		switch s.Kind {
		case PathField:
			if s.FieldName != "" {
				parts = append(parts, s.FieldName)
			} else {
				parts = append(parts, fmt.Sprintf("field%d", s.FieldIdx))
			}
		case PathIndex:
			parts = append(parts, "[*]")
		case PathDeref:
			parts = append(parts, "*")
		case PathMapValue:
			parts = append(parts, "[*]")
		case PathChanElem:
			parts = append(parts, "<-chan")
		case PathWiden:
			parts = append(parts, "*")
		}
	}
	return strings.Join(parts, ".")
}

// LegacyFieldPath returns the legacy-style field path (e.g., "field3") for backward
// compatibility in the JSON output.
func (ap AccessPath) LegacyFieldPath() string {
	parts := make([]string, 0, len(ap.Steps))
	for _, s := range ap.Steps {
		switch s.Kind {
		case PathField:
			parts = append(parts, fmt.Sprintf("field%d", s.FieldIdx))
		case PathIndex:
			parts = append(parts, "[*]")
		case PathDeref:
			parts = append(parts, "*")
		case PathMapValue:
			parts = append(parts, "[*]")
		case PathChanElem:
			parts = append(parts, "<-chan")
		case PathWiden:
			parts = append(parts, "*")
		}
	}
	return strings.Join(parts, ".")
}

// Extended returns a new AccessPath with an additional step appended.
// If the path is already at the k-limit, a widening step (*) is appended instead.
func (ap AccessPath) Extended(step PathStep, kLimit int) AccessPath {
	out := AccessPath{Base: ap.Base}
	out.Steps = make([]PathStep, len(ap.Steps), len(ap.Steps)+1)
	copy(out.Steps, ap.Steps)
	if kLimit > 0 && len(out.Steps) >= kLimit {
		// Check if we already have a widen step.
		if len(out.Steps) > 0 && out.Steps[len(out.Steps)-1].Kind == PathWiden {
			return out
		}
		out.Steps = append(out.Steps, PathStep{Kind: PathWiden, FieldName: "*"})
		return out
	}
	out.Steps = append(out.Steps, step)
	return out
}

// Key returns a string key suitable for use as a map key.
func (ap AccessPath) Key() string {
	var b strings.Builder
	b.WriteString(ap.Base.Kind.String())
	b.WriteByte(':')
	b.WriteString(ap.Base.ID)
	for _, s := range ap.Steps {
		b.WriteByte('.')
		b.WriteString(s.Kind.String())
		if s.Kind == PathField {
			b.WriteByte(':')
			b.WriteString(s.FieldName)
		}
	}
	return b.String()
}

// IsEmpty reports whether the access path has no base.
func (ap AccessPath) IsEmpty() bool {
	return ap.Base.ID == "" && ap.Base.Name == ""
}

// Equal reports whether two access paths are structurally equal.
func (ap AccessPath) Equal(other AccessPath) bool {
	if ap.Base.Kind != other.Base.Kind || ap.Base.ID != other.Base.ID {
		return false
	}
	if len(ap.Steps) != len(other.Steps) {
		return false
	}
	for i := range ap.Steps {
		if ap.Steps[i].Kind != other.Steps[i].Kind {
			return false
		}
		if ap.Steps[i].Kind == PathField && ap.Steps[i].FieldIdx != other.Steps[i].FieldIdx {
			return false
		}
	}
	return true
}

// NewLocalBase creates an access path base for a local allocation.
func NewLocalBase(v ssa.Value, fnID string) BaseRef {
	name := ""
	if v != nil {
		name = v.Name()
		if name == "" {
			name = v.String()
		}
	}
	typeStr := ""
	if v != nil && v.Type() != nil {
		typeStr = v.Type().String()
	}
	return BaseRef{
		Kind: BaseLocal,
		Name: name,
		ID:   fmt.Sprintf("local:%s:%s:%d", fnID, name, v.Pos()),
		Type: typeStr,
		FnID: fnID,
	}
}

// NewGlobalBase creates an access path base for a global variable.
func NewGlobalBase(g *ssa.Global) BaseRef {
	pkgPath := ""
	if g.Pkg != nil && g.Pkg.Pkg != nil {
		pkgPath = g.Pkg.Pkg.Path()
	}
	typeStr := ""
	if g.Type() != nil {
		typeStr = g.Type().String()
	}
	return BaseRef{
		Kind: BaseGlobal,
		Name: g.Name(),
		ID:   fmt.Sprintf("global:%s.%s", pkgPath, g.Name()),
		Type: typeStr,
		Pkg:  pkgPath,
	}
}

// NewParamBase creates an access path base for a function parameter.
func NewParamBase(fnID string, idx int, name, typ string) BaseRef {
	return BaseRef{
		Kind:  BaseParameter,
		Name:  name,
		ID:    fmt.Sprintf("param:%s:%d", fnID, idx),
		Type:  typ,
		FnID:  fnID,
		Index: idx,
	}
}

// NewHeapBase creates an access path base for a heap allocation.
func NewHeapBase(id string) BaseRef {
	return BaseRef{
		Kind: BaseHeap,
		ID:   "heap:" + id,
		Name: id,
	}
}

// FieldStep creates a PathStep for a struct field access.
func FieldStep(field *types.Var) PathStep {
	if field == nil {
		return PathStep{Kind: PathField, FieldName: "?"}
	}
	name := field.Name()
	idx := -1
	// Try to find the field index from the struct.
	if named, ok := field.Type().(*types.Named); ok {
		_ = named
	}
	return PathStep{
		Kind:      PathField,
		FieldName: name,
		FieldIdx:  idx,
	}
}

// FieldStepByIndex creates a PathStep for a struct field access by index.
// The field name is resolved from the struct type if available.
func FieldStepByIndex(structType types.Type, idx int) PathStep {
	if idx < 0 {
		return PathStep{Kind: PathField, FieldName: "?", FieldIdx: idx}
	}
	// Try to resolve field name.
	if ptr, ok := structType.(*types.Pointer); ok {
		structType = ptr.Elem()
	}
	structType = types.Unalias(structType)
	if named, ok := structType.(*types.Named); ok {
		if st, ok := named.Underlying().(*types.Struct); ok {
			if idx < st.NumFields() {
				return PathStep{
					Kind:      PathField,
					FieldName: st.Field(idx).Name(),
					FieldIdx:  idx,
				}
			}
		}
	}
	return PathStep{
		Kind:      PathField,
		FieldName: fmt.Sprintf("field%d", idx),
		FieldIdx:  idx,
	}
}

var (
	IndexStep    = PathStep{Kind: PathIndex, FieldName: "[*]"}
	DerefStep    = PathStep{Kind: PathDeref, FieldName: "*"}
	MapValueStep = PathStep{Kind: PathMapValue, FieldName: "[*]"}
	ChanElemStep = PathStep{Kind: PathChanElem, FieldName: "<-chan"}
	WidenStep    = PathStep{Kind: PathWiden, FieldName: "*"}
)
