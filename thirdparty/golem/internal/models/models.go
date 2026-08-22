package models

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"go/types"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// ModelEntry is one source, sink, passthrough or sanitizer rule.
type ModelEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`    // source | sink | passthrough | sanitizer
	Module   string `json:"module"`  // "std" or module path
	Package  string `json:"package"` // package path
	Receiver string `json:"receiver,omitempty"`
	Function string `json:"function"`
	// Match governs how Function is compared to a callee's name. The default
	// (empty / "exact") requires equality. "prefix" matches any callee whose
	// name starts with Function, which is how cgo's generated wrappers
	// (`_Cfunc_*`) are recognised without enumerating every wrapper the
	// compiler may emit. "contains" matches by substring; reserve it for
	// user patterns and stamp confidence low, since substring matches are
	// the source of the false positives the structured matcher exists to
	// eliminate.
	Match string `json:"match,omitempty"`
	// ParameterName is a regular expression matched against a function
	// parameter's declared name, for sources that are not calls at all. A
	// parameter called "cmd" or "password" is untrusted by convention rather
	// than by type or provenance, and it is the only evidence available at the
	// boundary of a library whose callers are not in the analysed module.
	// Entries carrying it name no Package or Function and match no call site.
	ParameterName string     `json:"parameterName,omitempty"`
	Arity         *AritySpec `json:"arity,omitempty"`
	// Arguments names the parameters that carry the value this entry is
	// about, by source-level position: the receiver of a method is not
	// one of them, whatever SSA does with it. See ArgumentRelevantAt.
	Arguments           []ArgumentRole `json:"arguments,omitempty"`
	ReceiverRelevant    bool           `json:"receiverRelevant,omitempty"`
	Category            string         `json:"category,omitempty"`
	TaintKinds          []string       `json:"taintKinds,omitempty"`
	RemovesTaintKinds   []string       `json:"removesTaintKinds,omitempty"`
	SanitizesCategories []string       `json:"sanitizesCategories,omitempty"`
	WritesToArguments   []int          `json:"writesToArguments,omitempty"`
	CWE                 []string       `json:"cwe,omitempty"`
	Severity            string         `json:"severity,omitempty"`
	Confidence          string         `json:"confidence,omitempty"`
	RuleID              string         `json:"ruleId,omitempty"`
	RuleName            string         `json:"ruleName,omitempty"`
	RiskScore           int            `json:"riskScore,omitempty"`
	Description         string         `json:"description,omitempty"`
	PURL                string         `json:"purl,omitempty"`
}

// AritySpec constrains the number of arguments.
type AritySpec struct {
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"` // 0 = unlimited
}

// ArgumentRole describes the role of a specific argument.
type ArgumentRole struct {
	Index    int    `json:"index"`
	Variadic bool   `json:"variadic,omitempty"`
	Role     string `json:"role,omitempty"`
}

// ArgumentRelevant reports whether the given argument index is relevant
// for this model entry (i.e., taint at this argument reaches the sink).
// QualifiedName renders the symbol a model entry describes.
func (e ModelEntry) QualifiedName() string {
	name := e.Function
	if e.Receiver != "" {
		// A type-shaped entry names a receiver and no function — the
		// *http.Request handed to a handler is the source, not a call on it.
		// Appending an empty function name would leave a trailing dot in a
		// symbol that reaches the report.
		if name == "" {
			name = "(" + e.Receiver + ")"
		} else {
			name = "(" + e.Receiver + ")." + name
		}
	}
	if e.Package != "" && e.Package != "std" {
		return e.Package + "." + name
	}
	return name
}

// ArgumentRelevantAt reports whether the argument at SSA position argIdx of
// this call is relevant, translating SSA positions into the source-level
// positions Arguments is written in.
//
// The two differ by the receiver. SSA passes it as the first argument of a
// static method call — `c.Get(url)` becomes `(*http.Client).Get(c, url)` —
// but not of an interface call, where it travels separately. Comparing a
// declared index against the SSA position directly therefore reads the
// receiver as the first argument of every concrete method: the url of
// (*http.Client).Get was never checked, and the request-supplied URL that
// makes it an SSRF sink went unreported.
//
// The receiver itself is relevant only when the entry says so, or when it
// names no argument roles at all and so claims the whole call.
func (e *ModelEntry) ArgumentRelevantAt(common *ssa.CallCommon, argIdx int) bool {
	offset := 0
	if common != nil && !common.IsInvoke() {
		if callee := common.StaticCallee(); callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil {
			offset = 1
		}
	}
	if argIdx < offset {
		return len(e.Arguments) == 0 || e.ReceiverRelevant
	}
	return e.ArgumentRelevant(argIdx - offset)
}

func (e *ModelEntry) ArgumentRelevant(argIdx int) bool {
	if len(e.Arguments) == 0 {
		// If no argument roles are specified, all arguments are relevant.
		return true
	}
	for _, role := range e.Arguments {
		if role.Index == argIdx {
			return true
		}
		if role.Variadic && argIdx >= role.Index {
			return true
		}
	}
	return false
}

//go:embed stdlib.json
var stdlibJSON []byte

//go:embed thirdparty.json
var thirdpartyJSON []byte

//go:embed native.json
var nativeJSON []byte

// DB is a structured model database keyed by package path and function name.
type DB struct {
	// entries is a flat list of all loaded model entries.
	entries []ModelEntry

	// byPackageFunc maps "packagePath.funcName" → matching entries.
	byPackageFunc map[string][]*ModelEntry

	// byReceiver maps "packagePath.receiverType.methodName" → matching entries.
	byReceiver map[string][]*ModelEntry

	// byName maps "funcName" → matching entries whose package is empty, so a
	// model can describe an interface method (or any function) by name alone
	// — the structured equivalent of the legacy exact-name match. Any entry
	// in here is also indexed by qualified key when its receiver is set.
	byName map[string][]*ModelEntry

	// byNamePrefix lists entries whose Match is "prefix". A callee whose
	// name starts with one of these prefixes matches the entry regardless of
	// package, which is how cgo's generated wrappers (_Cfunc_*) are
	// recognised without enumerating every wrapper.
	byNamePrefix map[string][]*ModelEntry

	// byParameterName holds entries that match a parameter's declared name
	// rather than a call site, with their patterns compiled once.
	byParameterName []compiledParameterSource

	// byConversionType maps "packagePath.TypeName" to entries whose Match is
	// "conversion": the model describes converting a value *to* that named
	// type, not calling a function.
	byConversionType map[string][]*ModelEntry

	// matchedSymbols records which models have matched at least one symbol.
	// Used to audit model coverage.
	matchedSymbols map[string]bool
}

// NewDB creates an empty model database.
func NewDB() *DB {
	return &DB{
		byPackageFunc:    make(map[string][]*ModelEntry),
		byReceiver:       make(map[string][]*ModelEntry),
		byName:           make(map[string][]*ModelEntry),
		byNamePrefix:     make(map[string][]*ModelEntry),
		byConversionType: make(map[string][]*ModelEntry),
		matchedSymbols:   make(map[string]bool),
	}
}

// LoadBuiltins loads the embedded stdlib, third-party and native models.
func (db *DB) LoadBuiltins() error {
	if err := db.LoadJSON(stdlibJSON); err != nil {
		return fmt.Errorf("loading stdlib models: %w", err)
	}
	if err := db.LoadJSON(thirdpartyJSON); err != nil {
		return fmt.Errorf("loading thirdparty models: %w", err)
	}
	if err := db.LoadJSON(nativeJSON); err != nil {
		return fmt.Errorf("loading native models: %w", err)
	}
	return nil
}

// LoadJSON parses model entries from JSON data.
func (db *DB) LoadJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var entries []ModelEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	return db.AddEntries(entries)
}

// AddEntries adds model entries to the database.
func (db *DB) AddEntries(entries []ModelEntry) error {
	db.entries = append(db.entries, entries...)
	for i := range entries {
		e := &db.entries[len(db.entries)-len(entries)+i]
		db.indexEntry(e)
	}
	return nil
}

func (db *DB) indexEntry(e *ModelEntry) {
	pkg := e.Package
	name := e.Function

	// A conversion sink names a type, not a function: html/template.HTML is
	// `type HTML string`, so template.HTML(x) is a conversion and there is no
	// call for a function-keyed index to match. Modelling it as a function is
	// why the commonest Go XSS — marking attacker data as already-safe HTML —
	// went undetected by both engines.
	if strings.EqualFold(e.Match, "conversion") {
		if pkg != "" && name != "" {
			key := pkg + "." + name
			db.byConversionType[key] = append(db.byConversionType[key], e)
		}
		return
	}

	// A parameter-name source matches no call site, so it takes part in none
	// of the call-keyed indexes below.
	if e.ParameterName != "" {
		re, err := regexp.Compile(e.ParameterName)
		if err != nil {
			// A malformed pattern is dropped rather than matching everything.
			// Compiling once here keeps the per-parameter check cheap.
			return
		}
		db.byParameterName = append(db.byParameterName, compiledParameterSource{entry: e, re: re})
		return
	}

	// Receiver-having entries (methods) are indexed only under their
	// qualified receiver keys. Indexing them by bare "package.function"
	// as well would conflate every same-named method in a package: the
	// net/http pair Header.Get (a source) and Client.Get (a sink) are the
	// case that bit us, and the structured matcher exists precisely to
	// avoid that class of confusion.
	if e.Receiver == "" {
		key := pkg + "." + name
		db.byPackageFunc[key] = append(db.byPackageFunc[key], e)
	}

	// A package-less entry matches by function name regardless of where the
	// symbol lives, the way the legacy engine's exact-name match did. This is
	// how an interface method like the error interface's Error() is modelled:
	// the implementation set is open, so the model is keyed on the name
	// every implementation shares.
	if pkg == "" && name != "" {
		switch strings.ToLower(e.Match) {
		case "prefix":
			db.byNamePrefix[name] = append(db.byNamePrefix[name], e)
		default:
			db.byName[name] = append(db.byName[name], e)
		}
	}

	// Index by package.(*receiver).method.
	if e.Receiver != "" {
		recvKey := pkg + "." + e.Receiver + "." + name
		db.byReceiver[recvKey] = append(db.byReceiver[recvKey], e)
		// Also with pointer receiver.
		if !strings.HasPrefix(e.Receiver, "*") {
			ptrKey := pkg + ".(*" + e.Receiver + ")." + name
			db.byReceiver[ptrKey] = append(db.byReceiver[ptrKey], e)
		} else {
			// Without pointer.
			valKey := pkg + "." + strings.TrimPrefix(e.Receiver, "*") + "." + name
			db.byReceiver[valKey] = append(db.byReceiver[valKey], e)
		}
	}
}

// MatchFunction returns all model entries that match a callee function.
// Matching is structural: module path + package path + receiver named type +
// method name + arity.
func (db *DB) MatchFunction(fn *ssa.Function) []ModelEntry {
	if fn == nil {
		return nil
	}
	var results []ModelEntry

	// Get the function's identity.
	pkgPath := ""
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkgPath = fn.Pkg.Pkg.Path()
	}
	name := fn.Name()
	originName := name
	if origin := fn.Origin(); origin != nil {
		originName = origin.Name()
	}

	// Build receiver info.
	var recvTypeName string
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		recvTypeName = receiverTypeName(fn.Signature.Recv().Type())
	}

	// Try multiple keys:
	keys := []string{
		pkgPath + "." + name,
		pkgPath + "." + originName,
	}
	if recvTypeName != "" {
		keys = append(keys,
			pkgPath+"."+recvTypeName+"."+name,
			pkgPath+".(*"+recvTypeName+")."+name,
		)
		// SSA renders methods as (*pkg.Type).Method.
		// Try without the pointer part.
		if strings.HasPrefix(recvTypeName, "*") {
			keys = append(keys, pkgPath+".("+recvTypeName+")."+name)
		} else {
			keys = append(keys, pkgPath+".(*"+recvTypeName+")."+name)
		}
	}

	seen := make(map[string]bool)
	for _, key := range keys {
		// A method is not the package-level function of the same name.
		// math/rand has both a func Int63 and a (*Rand).Int63, and the
		// unqualified "math/rand.Int63" key reaches the first from a call
		// on the second: the call matched two entries and reported the same
		// weak draw twice. byPackageFunc only holds receiver-less entries,
		// so a method's own entry is unaffected — it is indexed, and found,
		// under byReceiver.
		if recvTypeName == "" {
			for _, e := range db.byPackageFunc[key] {
				if seen[e.ID] {
					continue
				}
				seen[e.ID] = true
				if db.matchArity(e, fn) {
					results = append(results, *e)
					db.matchedSymbols[e.ID] = true
				}
			}
		}
		for _, e := range db.byReceiver[key] {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			if db.matchArity(e, fn) {
				results = append(results, *e)
				db.matchedSymbols[e.ID] = true
			}
		}
	}

	// Fall back to name-only matching for package-less entries. This is what
	// makes an interface method model (such as error.Error) match every
	// concrete implementation without listing each one.
	if byNameEntries := db.byName[name]; len(byNameEntries) > 0 {
		for _, e := range byNameEntries {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			if db.matchArity(e, fn) {
				results = append(results, *e)
				db.matchedSymbols[e.ID] = true
			}
		}
	}

	// Prefix-shaped models cover families of generated or similarly-named
	// functions without enumerating each one. The cgo wrappers `_Cfunc_*`
	// are the canonical case: the compiler emits a fresh wrapper per C
	// function called, and a model keyed on the prefix recognises all of
	// them as the boundary-crossing calls they are.
	for prefix, entries := range db.byNamePrefix {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		for _, e := range entries {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			if db.matchArity(e, fn) {
				results = append(results, *e)
				db.matchedSymbols[e.ID] = true
			}
		}
	}

	return results
}

// MatchParameterType returns source models whose receiver type matches a
// parameter's type, which is how a handler's *http.Request is recognised as
// carrying request data.
// compiledParameterSource pairs a parameter-name entry with its compiled
// pattern, so the regexp is built once at load rather than per parameter.
type compiledParameterSource struct {
	entry *ModelEntry
	re    *regexp.Regexp
}

// MatchParameterName returns the source models whose pattern matches a
// parameter's declared name. Names are matched case-insensitively at the
// pattern level, so a model writes its own anchors.
func (db *DB) MatchParameterName(name string) []ModelEntry {
	if name == "" || name == "_" {
		return nil
	}
	lower := strings.ToLower(name)
	var out []ModelEntry
	for _, c := range db.byParameterName {
		if c.re.MatchString(lower) {
			out = append(out, *c.entry)
		}
	}
	return out
}

// MatchConversion returns the sink models describing a conversion to t.
func (db *DB) MatchConversion(t types.Type) []ModelEntry {
	if len(db.byConversionType) == 0 || t == nil {
		return nil
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return nil
	}
	entries := db.byConversionType[named.Obj().Pkg().Path()+"."+named.Obj().Name()]
	out := make([]ModelEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, *e)
	}
	return out
}

func (db *DB) MatchParameterType(t types.Type) []ModelEntry {
	named := namedOf(t)
	if named == nil || named.Obj() == nil {
		return nil
	}
	pkgPath := ""
	if named.Obj().Pkg() != nil {
		pkgPath = named.Obj().Pkg().Path()
	}
	typeName := named.Obj().Name()
	var out []ModelEntry
	for _, entry := range db.entries {
		if entry.Kind != "source" || entry.Receiver == "" || entry.Function != "" {
			continue
		}
		if !packageMatches(entry, pkgPath) {
			continue
		}
		if strings.TrimPrefix(entry.Receiver, "*") == typeName {
			out = append(out, entry)
		}
	}
	return out
}

// namedOf unwraps pointers and aliases to the named type underneath.
func namedOf(t types.Type) *types.Named {
	cur := types.Unalias(t)
	if ptr, ok := cur.(*types.Pointer); ok {
		cur = types.Unalias(ptr.Elem())
	}
	named, _ := cur.(*types.Named)
	return named
}

// packageMatches reports whether an entry's package designation covers a path.
func packageMatches(entry ModelEntry, pkgPath string) bool {
	if entry.Package == "" {
		return true
	}
	if entry.Package == "std" {
		return !strings.Contains(pkgPath, ".")
	}
	return entry.Package == pkgPath
}

// MatchSymbol matches a types.Object (Func) against the model database.
func (db *DB) MatchSymbol(obj types.Object) []ModelEntry {
	if obj == nil {
		return nil
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	var results []ModelEntry

	pkgPath := ""
	if fn.Pkg() != nil {
		pkgPath = fn.Pkg().Path()
	}
	name := fn.Name()

	// Resolve receiver.
	var recvTypeName string
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		recvTypeName = receiverTypeName(sig.Recv().Type())
	}

	keys := []string{pkgPath + "." + name}
	if recvTypeName != "" {
		keys = append(keys,
			pkgPath+"."+recvTypeName+"."+name,
			pkgPath+".(*"+recvTypeName+")."+name,
		)
	}

	seen := make(map[string]bool)
	for _, key := range keys {
		for _, e := range db.byPackageFunc[key] {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			results = append(results, *e)
			db.matchedSymbols[e.ID] = true
		}
		for _, e := range db.byReceiver[key] {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			results = append(results, *e)
			db.matchedSymbols[e.ID] = true
		}
	}
	// Fall back to name-only matching for package-less entries.
	for _, e := range db.byName[name] {
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		results = append(results, *e)
		db.matchedSymbols[e.ID] = true
	}
	// Prefix-shaped models (cgo wrappers and similar).
	for prefix, entries := range db.byNamePrefix {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		for _, e := range entries {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			results = append(results, *e)
			db.matchedSymbols[e.ID] = true
		}
	}

	return results
}

func (db *DB) matchArity(e *ModelEntry, fn *ssa.Function) bool {
	if e.Arity == nil {
		return true
	}
	if fn.Signature == nil {
		return false
	}
	numParams := fn.Signature.Params().Len()
	if fn.Signature.Recv() != nil {
		numParams++ // include receiver
	}
	if e.Arity.Min > 0 && numParams < e.Arity.Min {
		return false
	}
	if e.Arity.Max > 0 && numParams > e.Arity.Max {
		return false
	}
	return true
}

// Entries returns all model entries.
func (db *DB) Entries() []ModelEntry {
	return db.entries
}

// UnmatchedSymbols returns model IDs that have never matched any symbol.
func (db *DB) UnmatchedSymbols() []string {
	var out []string
	for _, e := range db.entries {
		if !db.matchedSymbols[e.ID] {
			out = append(out, e.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Sources returns all source entries.
func (db *DB) Sources() []ModelEntry {
	var out []ModelEntry
	for _, e := range db.entries {
		if e.Kind == "source" {
			out = append(out, e)
		}
	}
	return out
}

// Sinks returns all sink entries.
func (db *DB) Sinks() []ModelEntry {
	var out []ModelEntry
	for _, e := range db.entries {
		if e.Kind == "sink" {
			out = append(out, e)
		}
	}
	return out
}

// Sanitizers returns all sanitizer entries.
func (db *DB) Sanitizers() []ModelEntry {
	var out []ModelEntry
	for _, e := range db.entries {
		if e.Kind == "sanitizer" {
			out = append(out, e)
		}
	}
	return out
}

// Passthroughs returns all passthrough entries.
func (db *DB) Passthroughs() []ModelEntry {
	var out []ModelEntry
	for _, e := range db.entries {
		if e.Kind == "passthrough" {
			out = append(out, e)
		}
	}
	return out
}

// receiverTypeName returns a human-readable name for a receiver type.
func receiverTypeName(t types.Type) string {
	if t == nil {
		return ""
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		elem := types.Unalias(ptr.Elem())
		if named, ok := elem.(*types.Named); ok {
			return "*" + named.Obj().Name()
		}
		return "*" + elem.String()
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name()
	}
	return t.String()
}
