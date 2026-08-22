// Package corpus parses and evaluates the ground-truth annotations embedded in
// golem's test corpus, and is shared by the corpus test driver and the
// benchmark harness so both agree on what a fixture expects.
//
// Grammar (one annotation per comment line):
//
//	// golem:want     flow source=<category> sink=<category> [count=N] [mode=M] [severity=S] [sinkFn=<symbol>] [connected] [known-fail=<defect>]
//	// golem:want-not flow source=<category> sink=<category> [mode=M] [known-fail=<defect>]
//	// golem:want     edge from=<symbol> to=<symbol> [calltype=T] [count=N] [known-fail=<defect>]
//	// golem:want-not edge from=<symbol> to=<symbol> [known-fail=<defect>]
//	// golem:want     reachable symbol=<symbol> [from=<symbol>] [maxdepth=N] [known-fail=<defect>]
//	// golem:want-not reachable symbol=<symbol>
//
// Values match exactly by default. Prefix a value with "~" for a substring
// match. Exact matching is deliberate: substring matching on categories makes
// "http" match http-input, http-response and http-endpoint alike,
// which silently turns precise expectations into vague ones.
//
// A "connected" flow expectation additionally requires the reported slice to
// carry a node and edge list that forms a real path from its source to its sink
// (the edge-connectivity property).
package corpus

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// KnownEngines are the taint engines an expectation can be scoped to, in the
// order they are rendered.
var KnownEngines = []string{"legacy", "seam"}

// DefaultEngine is assumed when a report does not name the engine that produced
// it, which is what older reports and the call-graph-only paths do.
const DefaultEngine = "seam"

// KnownFailFor returns the defect number this expectation is known to fail on
// under the given engine, or zero when it is expected to hold.
func (a Annotation) KnownFailFor(engine string) int {
	if engine == "" {
		engine = DefaultEngine
	}
	if defect, ok := a.KnownFailByEngine[engine]; ok {
		return defect
	}
	return a.KnownFail
}

// Kind enumerates the annotation kinds.
const (
	KindFlow      = "flow"
	KindEdge      = "edge"
	KindReachable = "reachable"
)

// Annotation is one ground-truth expectation attached to a source position.
type Annotation struct {
	Want      bool   // want (true) vs want-not (false)
	Kind      string // KindFlow | KindEdge | KindReachable
	Source    string // flow: source category; edge: caller; reachable: origin root
	Sink      string // flow: sink category; edge: callee
	Symbol    string // reachable: target symbol
	SinkFn    string // flow: optional sink function constraint
	SourceFn  string // flow: optional source function constraint
	CallType  string // edge: optional call type constraint
	Severity  string // flow: optional severity constraint
	Mode      string // optional data-flow mode this expectation applies to ("" = every mode)
	Count     int    // minimum matches required for want (default 1)
	MaxDepth  int    // reachable: maximum permitted depth (0 = unconstrained)
	Connected bool   // flow: require a structurally connected path
	KnownFail int    // non-zero defect number this expectation is known to fail on, for every engine
	// KnownFailByEngine records a defect that is open in one taint engine and
	// closed in another. Two engines now ship, and without this the corpus can
	// only describe a defect as open everywhere or nowhere: removing a marker
	// because the candidate engine passes breaks the build for the default one,
	// and keeping it reports the candidate's progress as an XPASS failure.
	KnownFailByEngine map[string]int
	File              string
	Line              int
}

// String renders an annotation for test and benchmark output.
func (a Annotation) String() string {
	verb := "want"
	if !a.Want {
		verb = "want-not"
	}
	var parts []string
	switch a.Kind {
	case KindFlow:
		parts = append(parts, "source="+a.Source, "sink="+a.Sink)
	case KindEdge:
		parts = append(parts, "from="+a.Source, "to="+a.Sink)
	case KindReachable:
		parts = append(parts, "symbol="+a.Symbol)
		if a.Source != "" {
			parts = append(parts, "from="+a.Source)
		}
	}
	if a.Count > 1 {
		parts = append(parts, "count="+strconv.Itoa(a.Count))
	}
	if a.Mode != "" {
		parts = append(parts, "mode="+a.Mode)
	}
	if a.Connected {
		parts = append(parts, "connected")
	}
	if a.KnownFail != 0 {
		parts = append(parts, "known-fail="+strconv.Itoa(a.KnownFail))
	}
	for _, engine := range KnownEngines {
		if defect, ok := a.KnownFailByEngine[engine]; ok {
			parts = append(parts, "known-fail="+engine+":"+strconv.Itoa(defect))
		}
	}
	return fmt.Sprintf("%s %s %s (%s:%d)", verb, a.Kind, strings.Join(parts, " "), filepath.Base(a.File), a.Line)
}

// AppliesTo reports whether the annotation constrains a run in the given
// data-flow mode.
func (a Annotation) AppliesTo(mode string) bool {
	return a.Mode == "" || strings.EqualFold(a.Mode, mode)
}

// Required returns the minimum number of matches a want annotation needs.
func (a Annotation) Required() int {
	if a.Count > 0 {
		return a.Count
	}
	return 1
}

// Parse walks dir recursively and returns every annotation found, sorted by
// file and line. Unlike a single-directory parse, this picks up expectations in
// nested packages, which multi-package fixtures rely on.
func Parse(dir string) ([]Annotation, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if name := d.Name(); path != dir && (name == "vendor" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var out []Annotation
	fset := token.NewFileSet()
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		annotations, err := parseFileComments(fset, file, path)
		if err != nil {
			return nil, err
		}
		out = append(out, annotations...)
	}
	return out, nil
}

func parseFileComments(fset *token.FileSet, file *ast.File, path string) ([]Annotation, error) {
	var out []Annotation
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for _, line := range commentLines(comment.Text) {
				text, ok := trimAnnotationPrefix(line)
				if !ok {
					continue
				}
				ann, err := parseAnnotation(text)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: %w", path, fset.Position(comment.Pos()).Line, err)
				}
				ann.File = path
				ann.Line = fset.Position(comment.Pos()).Line
				out = append(out, ann)
			}
		}
	}
	return out, nil
}

func commentLines(text string) []string {
	text = strings.TrimPrefix(text, "//")
	text = strings.TrimPrefix(text, "/*")
	text = strings.TrimSuffix(text, "*/")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*"))
	}
	return lines
}

func trimAnnotationPrefix(line string) (string, bool) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "//"))
	if !strings.HasPrefix(line, "golem:") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "golem:")), true
}

func parseAnnotation(text string) (Annotation, error) {
	fields := strings.Fields(text)
	if len(fields) < 2 {
		return Annotation{}, fmt.Errorf("malformed annotation %q: expected \"want|want-not <kind> ...\"", text)
	}
	var ann Annotation
	switch fields[0] {
	case "want":
		ann.Want = true
	case "want-not":
		ann.Want = false
	default:
		return Annotation{}, fmt.Errorf("unknown annotation verb %q (want or want-not)", fields[0])
	}
	switch fields[1] {
	case KindFlow, KindEdge, KindReachable:
		ann.Kind = fields[1]
	default:
		return Annotation{}, fmt.Errorf("unknown annotation kind %q (flow, edge or reachable)", fields[1])
	}
	for _, field := range fields[2:] {
		key, value, hasValue := strings.Cut(field, "=")
		if !hasValue {
			switch key {
			case "connected":
				ann.Connected = true
				continue
			default:
				return Annotation{}, fmt.Errorf("unknown annotation flag %q", key)
			}
		}
		switch key {
		case "source", "from":
			ann.Source = value
		case "sink", "to":
			ann.Sink = value
		case "symbol":
			ann.Symbol = value
		case "sinkFn", "sinkfn":
			ann.SinkFn = value
		case "sourceFn", "sourcefn":
			ann.SourceFn = value
		case "calltype":
			ann.CallType = value
		case "severity":
			ann.Severity = value
		case "mode":
			ann.Mode = value
		case "known-fail":
			// Either `known-fail=<defect>` for every engine, or
			// `known-fail=<engine>:<defect>` for one of them, repeatable.
			engine, number, scoped := strings.Cut(value, ":")
			if !scoped {
				n, err := strconv.Atoi(value)
				if err != nil {
					return Annotation{}, fmt.Errorf("known-fail=%q is neither a defect number nor engine:number", value)
				}
				ann.KnownFail = n
				continue
			}
			if !slices.Contains(KnownEngines, engine) {
				return Annotation{}, fmt.Errorf("known-fail names unknown engine %q (want one of %s)", engine, strings.Join(KnownEngines, ", "))
			}
			n, err := strconv.Atoi(number)
			if err != nil {
				return Annotation{}, fmt.Errorf("known-fail=%s:%q is not an integer defect number", engine, number)
			}
			if ann.KnownFailByEngine == nil {
				ann.KnownFailByEngine = map[string]int{}
			}
			if _, duplicate := ann.KnownFailByEngine[engine]; duplicate {
				return Annotation{}, fmt.Errorf("known-fail names engine %q twice", engine)
			}
			ann.KnownFailByEngine[engine] = n
		case "count", "maxdepth":
			n, err := strconv.Atoi(value)
			if err != nil {
				return Annotation{}, fmt.Errorf("%s=%q is not an integer", key, value)
			}
			switch key {
			case "count":
				ann.Count = n
			case "maxdepth":
				ann.MaxDepth = n
			}
		default:
			return Annotation{}, fmt.Errorf("unknown annotation key %q", key)
		}
	}
	return ann, ann.validate()
}

func (a Annotation) validate() error {
	switch a.Kind {
	case KindFlow:
		if a.Source == "" && a.Sink == "" {
			return fmt.Errorf("flow annotation needs source= or sink=")
		}
		for _, category := range []string{a.Source, a.Sink} {
			if err := validateCategory(category); err != nil {
				return err
			}
		}
	case KindEdge:
		if a.Source == "" && a.Sink == "" {
			return fmt.Errorf("edge annotation needs from= or to=")
		}
	case KindReachable:
		if a.Symbol == "" {
			return fmt.Errorf("reachable annotation needs symbol=")
		}
	}
	if a.Count < 0 {
		return fmt.Errorf("count must not be negative")
	}
	if !a.Want && a.Count > 0 {
		return fmt.Errorf("count= is meaningless on want-not")
	}
	return nil
}

// validateCategory rejects category names golem can never emit. Without this a
// negative expectation such as sink=sql-injection is vacuously satisfied
// forever, which is worse than having no expectation at all because it reads
// like coverage.
func validateCategory(category string) error {
	if category == "" || strings.HasPrefix(category, "~") {
		return nil
	}
	if _, ok := categories[category]; !ok {
		return fmt.Errorf("unknown category %q; add it to internal/corpus.Categories when the analyzer starts emitting it", category)
	}
	return nil
}

// categories is the vocabulary of category names an annotation may use: those
// golem's built-in pattern packs emit today, plus a small reserved set the
// roadmap commits to emitting. internal/analyzer's
// TestCorpusCategoryVocabulary keeps the first group honest.
//
// Reserved names let a fixture state an expectation for a rule family that does
// not exist yet. That is sound for a positive expectation, which fails until the
// family ships; it is not sound for a negative one, so keep negatives on
// categories golem can already emit.
var categories = func() map[string]bool {
	set := map[string]bool{}
	for _, name := range []string{
		// Reserved for rule families the roadmap adds in phase 2.
		"template-injection", "ssrf", "zip-slip", "deserialization",
	} {
		set[name] = true
	}
	for _, name := range []string{
		"cli", "cloud-metadata", "command-execution", "configuration", "conversion", "crypto",
		"crypto-material", "custom-helper", "custom-sanitizer", "data", "dynamic-loading",
		"environment", "external-service", "filesystem", "formatted-output", "framework",
		"framework-context", "html-escaping", "http-endpoint", "http-input",
		"http-response", "insecure-random", "logging", "native-conversion", "native-interop", "panic", "parameter",
		"path", "path-validation", "queue-message", "queue-send", "redirect", "secure-random",
		"sink", "sql-parameterization", "syscall", "unsafe", "url-encoding",
	} {
		set[name] = true
	}
	return set
}()

// Categories returns the known category vocabulary, sorted.
func Categories() []string {
	out := make([]string, 0, len(categories))
	for name := range categories {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Matches reports whether a reported value satisfies an expectation value,
// honouring the "~" substring escape hatch. An empty expectation matches
// anything.
func Matches(expected, actual string) bool {
	if expected == "" {
		return true
	}
	if pattern, ok := strings.CutPrefix(expected, "~"); ok {
		return strings.Contains(strings.ToLower(actual), strings.ToLower(pattern))
	}
	return strings.EqualFold(expected, actual)
}

// DiscoverCases returns the immediate subdirectories of root that contain at
// least one Go file, sorted by name.
func DiscoverCases(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		hasGo := false
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || hasGo {
				return walkErr
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") {
				hasGo = true
			}
			return nil
		})
		if hasGo {
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ParseSidecar reads annotations from a standalone file rather than from Go
// comments.
//
// Remote fixtures are pinned checkouts of somebody else's repository. Ground
// truth for them has to live in this repository, because a comment written into
// a clone is gone the next time the clone is made, and because editing the
// pinned tree would mean the fixture no longer matches its SHA. The two biggest
// real repositories in the manifest are deliberate vulnerability benchmarks
// with published, enumerated vulnerabilities; without somewhere to record that,
// neither engine's behaviour on real code is measured at all.
//
// The grammar is the one used in comments, minus the "golem:" prefix: one
// annotation per line, blank lines and lines beginning with "#" ignored.
func ParseSidecar(path string) ([]Annotation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Annotation
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "golem:")
		ann, err := parseAnnotation(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		ann.File = path
		ann.Line = i + 1
		out = append(out, ann)
	}
	return out, nil
}
