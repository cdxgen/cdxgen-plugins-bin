package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/models"
)

// Two engines ship and each carries its own idea of what the standard library
// does: the legacy engine's built-in pattern pack, written in Go in
// builtinDataFlowPatterns, and the structured model database SEAM reads from
// internal/models/*.json. Both are maintained by hand, and nothing has ever
// compared them.
//
// They drifted, silently and for a long time, in both directions. The model
// database had no log.Fatalf, log.Fatalln, log.Panicf, log.Panicln, fmt.Print,
// fmt.Printf or fmt.Println, so SEAM walked past sinks legacy had always
// caught. In the other direction the same symbol was filed under two different
// categories — the request type was "http-request" to legacy and "http-input"
// to the models — and category is a published field consumers filter on, so
// the answer to "is this flow HTTP-sourced" depended on which engine ran.
//
// Neither class of drift shows up in the corpus: a fixture exercises one engine
// at a time, and a symbol no fixture happens to use is invisible to both. So
// these tests compare the vocabularies directly. They are the cheap, mechanical
// half of keeping the engines interchangeable; the expensive half is agreeing
// on the semantics behind a category, which no test can check.
//
// The end state these tests are a stepping stone toward is one vocabulary
// rather than two agreeing ones: legacy deriving its pattern pack from the
// model database, so drift is impossible by construction rather than merely
// detected. Until then, an intentional difference goes in the allowlists below
// with the reason it is intentional.

// symbolKey identifies a function or method independently of the notation each
// side happens to spell it in. Legacy patterns are normalised to SSA notation,
// "(*net/http.Client).Do"; model entries carry package, receiver and function
// separately and render as "net/http.(*Client).Do". Both denote the same three
// parts, so the comparison is done on the parts.
type symbolKey struct {
	pkg      string
	receiver string // "" for a plain function; pointer marker stripped
	function string
}

func (s symbolKey) String() string {
	if s.receiver == "" {
		return s.pkg + "." + s.function
	}
	return s.pkg + ".(" + s.receiver + ")." + s.function
}

// parseLegacySymbol splits a legacy "function"-kind pattern into its parts.
//
// The pattern pack spells the same method four ways — "(*net/http.Client).Do",
// "net/http.Client.Do", "reflect.Value.Call" and "reflect.Value).Call" all
// appear, the last two deliberately, because a substring match has to cover
// both renderings the SSA printer might produce. Dropping the grouping
// punctuation collapses them onto one form. What remains is
// "pkg[.Receiver].Function", disambiguated by Go's own convention: a receiver
// type is exported, so the segment before the function name is a receiver when
// it begins with an upper-case letter and a package segment otherwise.
//
// ok is false for anything that does not name one concrete symbol: a bare
// package such as "github.com/jackc/pgx", a package prefix such as "syscall.",
// or an unqualified name.
func parseLegacySymbol(pattern string) (symbolKey, bool) {
	pattern = strings.NewReplacer("(", "", ")", "", "*", "").Replace(strings.TrimSpace(pattern))
	dot := strings.LastIndex(pattern, ".")
	if dot <= 0 || dot == len(pattern)-1 {
		return symbolKey{}, false
	}
	prefix, function := pattern[:dot], pattern[dot+1:]
	if strings.Contains(function, "/") || !isExportedName(function) {
		return symbolKey{}, false
	}
	if inner := strings.LastIndex(prefix, "."); inner > 0 {
		if candidate := prefix[inner+1:]; isExportedName(candidate) && !strings.Contains(candidate, "/") {
			return symbolKey{pkg: prefix[:inner], receiver: candidate, function: function}, true
		}
	}
	return symbolKey{pkg: prefix, function: function}, true
}

func isExportedName(s string) bool {
	return s != "" && s[0] >= 'A' && s[0] <= 'Z'
}

// stdlibRoots are the top-level standard-library directories. "no dot in the
// first segment" is the toolchain's rule for a stdlib import path, but it is
// not enough here: legacy writes third-party patterns as short aliases —
// "echo.Context.JSON", "gin.Context.Redirect", "yaml.Unmarshal" — which have no
// dot either and would otherwise be compared as though they were stdlib.
var stdlibRoots = map[string]bool{
	"archive": true, "bufio": true, "builtin": true, "bytes": true, "cmp": true,
	"compress": true, "container": true, "context": true, "crypto": true,
	"database": true, "debug": true, "embed": true, "encoding": true,
	"errors": true, "expvar": true, "flag": true, "fmt": true, "go": true,
	"hash": true, "html": true, "image": true, "index": true, "io": true,
	"iter": true, "log": true, "maps": true, "math": true, "mime": true,
	"net": true, "os": true, "path": true, "plugin": true, "reflect": true,
	"regexp": true, "runtime": true, "slices": true, "sort": true,
	"strconv": true, "strings": true, "structs": true, "sync": true,
	"syscall": true, "testing": true, "text": true, "time": true,
	"unicode": true, "unique": true, "unsafe": true, "weak": true,
}

func isStdlibPath(pkgPath string) bool {
	first, _, _ := strings.Cut(pkgPath, "/")
	return stdlibRoots[first]
}

// stdlibShortNames maps the last segment of a standard-library package path to
// the full path, for the segments where that is unambiguous. Legacy writes
// "http.Error" and "sql.(*DB).Query" where the models write "net/http" and
// "database/sql"; both mean the same package. "template" is deliberately
// absent, since html/template and text/template both end in it and the two are
// not interchangeable — one escapes and the other does not.
func stdlibShortNames(modelPackages map[string]bool) map[string]string {
	byLast := map[string][]string{}
	for pkg := range modelPackages {
		if !isStdlibPath(pkg) || !strings.Contains(pkg, "/") {
			continue
		}
		last := pkg[strings.LastIndex(pkg, "/")+1:]
		byLast[last] = append(byLast[last], pkg)
	}
	out := map[string]string{}
	for last, paths := range byLast {
		if len(paths) == 1 {
			out[last] = paths[0]
		}
	}
	return out
}

// legacyVocabulary indexes the built-in pattern pack by target and symbol.
// Only "function"-kind patterns name a symbol; sources keyed on a type, a
// struct field, a parameter name or a whole package describe a shape rather
// than a symbol and have no counterpart to compare against here.
func legacyVocabulary(shortNames map[string]string) map[string]map[symbolKey]string {
	set := builtinDataFlowPatterns(nil)
	out := map[string]map[symbolKey]string{}
	add := func(target string, patterns []model.DataFlowPattern) {
		bucket := out[target]
		if bucket == nil {
			bucket = map[symbolKey]string{}
			out[target] = bucket
		}
		for _, p := range patterns {
			if p.Kind != "function" {
				continue
			}
			if m := strings.ToLower(p.Match); m != "" && m != "contains" && m != "exact" {
				continue
			}
			key, ok := parseLegacySymbol(normalizeSSASymbolNotation(p.Pattern))
			if !ok {
				continue
			}
			if full, aliased := shortNames[key.pkg]; aliased {
				key.pkg = full
			}
			// An unqualified pattern such as "Header.Get" names no package and
			// cannot be resolved to a symbol either side would agree on.
			if !strings.Contains(key.pkg, "/") && !isStdlibPath(key.pkg) {
				continue
			}
			// First writer wins, matching the engine: patterns are consulted
			// in order and the earliest match decides the category.
			if _, seen := bucket[key]; !seen {
				bucket[key] = p.Category
			}
		}
	}
	add("source", set.Sources)
	add("sink", set.Sinks)
	add("passthrough", set.Passthroughs)
	add("sanitizer", set.Sanitizers)
	return out
}

// modelVocabulary indexes the structured model database the same way. Entries
// that match a parameter name, or a callee by prefix, name no single symbol.
func modelVocabulary(t *testing.T) map[string]map[symbolKey]string {
	t.Helper()
	db := models.NewDB()
	if err := db.LoadBuiltins(); err != nil {
		t.Fatalf("loading models: %v", err)
	}
	out := map[string]map[symbolKey]string{}
	for _, e := range db.Entries() {
		if e.ParameterName != "" || strings.EqualFold(e.Match, "prefix") {
			continue
		}
		// A conversion sink names a named type, not a function. Legacy's
		// pattern pack has no way to express one — that is defect 34, recorded
		// against shiftleft-go-demo's two XSS routes — so there is no function
		// symbol to compare against and listing them here would report a
		// missing capability as a missing model.
		if strings.EqualFold(e.Match, "conversion") {
			continue
		}
		if e.Function == "" || e.Package == "" {
			continue
		}
		target := e.Kind
		bucket := out[target]
		if bucket == nil {
			bucket = map[symbolKey]string{}
			out[target] = bucket
		}
		key := symbolKey{pkg: e.Package, receiver: strings.TrimPrefix(e.Receiver, "*"), function: e.Function}
		if _, seen := bucket[key]; !seen {
			bucket[key] = e.Category
		}
	}
	return out
}

// modelPackages is the set of package paths the model database mentions.
func modelPackages(vocab map[string]map[symbolKey]string) map[string]bool {
	out := map[string]bool{}
	for _, bucket := range vocab {
		for key := range bucket {
			out[key.pkg] = true
		}
	}
	return out
}

// categoryDisagreements lists symbols both vocabularies know but file under
// different categories.
//
// This is the check the "http-request" versus "http-input" split would have
// failed. Category reaches the report, cdxgen's component properties and
// dep-scan's service-tag mapping, so two engines disagreeing about it means a
// consumer's filter silently depends on which engine produced the file.
var categoryDisagreementAllowlist = map[string]string{}

func TestEnginesAgreeOnCategoryForSharedSymbols(t *testing.T) {
	modelsByTarget := modelVocabulary(t)
	legacy := legacyVocabulary(stdlibShortNames(modelPackages(modelsByTarget)))
	var problems []string
	for _, target := range []string{"source", "sink", "passthrough", "sanitizer"} {
		for key, legacyCategory := range legacy[target] {
			modelCategory, ok := modelsByTarget[target][key]
			if !ok {
				continue // coverage is the other test's business
			}
			if legacyCategory == modelCategory {
				continue
			}
			// A passthrough's category is descriptive rather than a
			// classification consumers filter on, and the two sides use it as
			// free-text ("conversion" versus "error-wrapping"). Only source
			// and sink categories reach a finding.
			if target == "passthrough" {
				continue
			}
			id := target + " " + key.String()
			if reason, allowed := categoryDisagreementAllowlist[id]; allowed {
				t.Logf("allowed disagreement on %s: %s", id, reason)
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: legacy says %q, models say %q", id, legacyCategory, modelCategory))
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("the two engines file the same symbol under different categories, so a consumer's\n"+
			"category filter depends on which engine produced the report. Pick one value,\n"+
			"change both sides, and bump SchemaVersion; or record the difference in\n"+
			"categoryDisagreementAllowlist with the reason:\n  %s", strings.Join(problems, "\n  "))
	}
}

// coverageAllowlist records symbols one engine deliberately knows and the other
// does not, with the reason. Anything not listed here is drift.
var coverageAllowlist = map[string]string{
	// Legacy has no template rule family at all — defect 24, also recorded in
	// testdata/seam-parity.json. These are not drift but a missing feature.
	"sink html/template.HTML":               "legacy has no template rule family (defect 24)",
	"sink html/template.JS":                 "legacy has no template rule family (defect 24)",
	"sink html/template.URL":                "legacy has no template rule family (defect 24)",
	"sink html/template.(Template).Execute": "legacy has no template rule family (defect 24)",
	"sink text/template.(Template).Execute": "legacy has no template rule family (defect 24)",

	// Legacy matches these by bare unqualified name — the pattern is literally
	// "FormValue", so it fires on any function so named in any package. The
	// models qualify them. Same symbols, different precision: this entry
	// records a known weakness of the legacy matcher, not a missing model.
	"source net/http.(Request).FormValue":       "legacy matches the bare name \"FormValue\"",
	"source net/http.(Request).PostFormValue":   "legacy matches the bare name \"PostFormValue\"",
	"source net/http.(Request).Cookie":          "legacy matches the bare name \"Cookie\"",
	"source net/http.(Request).FormFile":        "legacy matches the bare name \"FormFile\"",
	"source net/http.(Request).MultipartReader": "legacy matches the bare name \"MultipartReader\"",
	"source net/http.(Request).ParseForm":       "legacy matches the bare name \"ParseForm\"",
	"source net/http.(Header).Get":              "legacy matches the bare names \"Header.Get\" and \"Header).Get\"",

	// Legacy models os.Args with kind \"symbol\" rather than \"function\",
	// because it is a variable and not a call. Only function-kind patterns are
	// compared here.
	"source os.Args": "legacy models it as a symbol, not a call",

	// Disagreements of substance rather than coverage, left as they are until
	// someone decides which reading is right:
	"source net/url.Parse":          "models treat parsing as a source; legacy treats it as propagation only",
	"sink encoding/json.NewDecoder": "legacy models it as a writer (passthrough with argument writes), the models as a sink",
	"sanitizer path/filepath.Dir":   "filepath.Dir strips the final element but not \"..\"; the model entry is unreviewed",
}

// TestEnginesCoverTheSameSymbols compares the two vocabularies symbol by symbol
// over the standard library.
//
// It stops at the standard library on purpose. There the two sides denote a
// symbol the same way, so a difference in the sets is a difference in what the
// engines know. Third-party patterns are not comparable that cheaply: legacy
// matches them as substrings of short aliases — "echo.Context.JSON",
// "gin.Context.Redirect" — while the models carry the full module path,
// "github.com/labstack/echo/v4". Both may be describing the same method, and no
// textual rule decides it. Those are reported as a count so the backlog stays
// visible, and unifying them means giving legacy real package paths, which is
// the same work as having it read the model database directly.
func TestEnginesCoverTheSameSymbols(t *testing.T) {
	modelsByTarget := modelVocabulary(t)
	legacy := legacyVocabulary(stdlibShortNames(modelPackages(modelsByTarget)))
	var legacyOnly, modelOnly []string
	thirdPartyLegacyOnly, thirdPartyModelOnly := 0, 0
	for _, target := range []string{"source", "sink", "sanitizer"} {
		for key := range legacy[target] {
			if _, ok := modelsByTarget[target][key]; ok {
				continue
			}
			if !isStdlibPath(key.pkg) {
				thirdPartyLegacyOnly++
				continue
			}
			if id := target + " " + key.String(); coverageAllowlist[id] == "" {
				legacyOnly = append(legacyOnly, id)
			}
		}
		for key := range modelsByTarget[target] {
			if _, ok := legacy[target][key]; ok {
				continue
			}
			if !isStdlibPath(key.pkg) {
				thirdPartyModelOnly++
				continue
			}
			if id := target + " " + key.String(); coverageAllowlist[id] == "" {
				modelOnly = append(modelOnly, id)
			}
		}
	}
	sort.Strings(legacyOnly)
	sort.Strings(modelOnly)
	if len(legacyOnly) > 0 {
		t.Errorf("%d standard-library symbol(s) the legacy pattern pack knows and the model\n"+
			"database does not, so SEAM walks past them. Add them to internal/models/*.json,\n"+
			"or record why not in coverageAllowlist:\n  %s", len(legacyOnly), strings.Join(legacyOnly, "\n  "))
	}
	if len(modelOnly) > 0 {
		t.Errorf("%d standard-library symbol(s) the model database knows and the legacy pattern\n"+
			"pack does not, so the default engine walks past them. Add them to\n"+
			"builtinDataFlowPatterns, or record why not in coverageAllowlist:\n  %s",
			len(modelOnly), strings.Join(modelOnly, "\n  "))
	}
	t.Logf("third-party symbols not compared: %d legacy-only, %d model-only "+
		"(legacy matches these as substrings of short aliases; the models carry full module paths)",
		thirdPartyLegacyOnly, thirdPartyModelOnly)
}
