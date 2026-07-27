package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// corpusModes are the data-flow modes every corpus case is evaluated under.
//
// Both matter. "security" is what ships and what cdxgen and dep-scan invoke, so
// an expectation that only holds under "all" is a latent gap rather than a fix;
// annotate such cases with mode=all to say so explicitly.
var corpusModes = []string{"security", "all"}

const corpusRoot = "../../testdata/corpus"

func analyzeCorpusCase(t *testing.T, dir, mode string) *model.Report {
	t.Helper()
	report, err := Analyze(Options{
		Dir:                   dir,
		IncludeLocal:          true,
		CallGraphMode:         "rta",
		DataFlowMode:          mode,
		DataFlowCallGraphMode: "rta",
		DataFlowMax:           200,
		ToolVersion:           "test",
	})
	if err != nil {
		t.Fatalf("analyze %s in mode %s: %v", dir, mode, err)
	}
	return report
}

// TestCorpus evaluates every annotated corpus case.
//
// The suite is a ratchet in both directions: an unsatisfied expectation without
// a known-fail marker fails, and a satisfied expectation that still carries one
// fails too, with instructions to remove the marker. Without the second half the
// exception list only ever grows, and a defect that has been fixed keeps being
// reported as a known limitation.
func TestCorpus(t *testing.T) {
	skipIfShort(t, "analyses every corpus case")
	cases, err := corpus.DiscoverCases(corpusRoot)
	if err != nil {
		t.Skipf("corpus not available: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("corpus contains no cases")
	}

	type tally struct {
		pass, xfail, fail, xpass int
	}
	var mu sync.Mutex
	totals := map[string]*tally{}
	for _, mode := range corpusModes {
		totals[mode] = &tally{}
	}
	defects := map[int][]string{}

	for _, dir := range cases {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			annotations, err := corpus.Parse(dir)
			if err != nil {
				t.Fatalf("parsing annotations: %v", err)
			}
			if len(annotations) == 0 {
				t.Fatalf("case %s has no golem: annotations; every case must state what it expects", name)
			}
			for _, mode := range corpusSuiteModes() {
				applicable := 0
				for _, annotation := range annotations {
					if annotation.AppliesTo(mode) {
						applicable++
					}
				}
				if applicable == 0 {
					continue
				}
				t.Run(mode, func(t *testing.T) {
					report := analyzeCorpusCase(t, dir, mode)
					evaluation := corpus.Evaluate(report, annotations, mode)
					mu.Lock()
					defer mu.Unlock()
					for _, outcome := range evaluation.Outcomes {
						status := outcome.Status()
						switch status {
						case "PASS":
							totals[mode].pass++
							t.Logf("PASS  %s: %s", outcome.Annotation, outcome.Detail)
						case "XFAIL":
							totals[mode].xfail++
							defects[outcome.KnownFail()] = append(defects[outcome.KnownFail()], name+"/"+mode)
							t.Logf("XFAIL %s: %s", outcome.Annotation, outcome.Detail)
						case "XPASS":
							totals[mode].xpass++
							t.Errorf("XPASS %s: expectation now holds; remove known-fail=%d\n      %s",
								outcome.Annotation, outcome.KnownFail(), outcome.Detail)
						case "FAIL":
							totals[mode].fail++
							t.Errorf("FAIL  %s: %s", outcome.Annotation, outcome.Detail)
						}
					}
					if connectivity, reasons := corpus.Connectivity(report.DataFlow); connectivity < 1 {
						t.Errorf("edge-connectivity %.3f: reported flows whose node and edge lists do not form a source-to-sink path: %s",
							connectivity, strings.Join(reasons, "; "))
					}
					if violations := reportIntegrityViolations(report); len(violations) > 0 {
						t.Errorf("report integrity: %s", strings.Join(violations, "; "))
					}
				})
			}
		})
	}

	for _, mode := range corpusModes {
		count := totals[mode]
		t.Logf("corpus[%s]: pass=%d xfail=%d fail=%d xpass=%d", mode, count.pass, count.xfail, count.fail, count.xpass)
	}
	numbers := make([]int, 0, len(defects))
	for defect := range defects {
		numbers = append(numbers, defect)
	}
	sort.Ints(numbers)
	for _, defect := range numbers {
		cases := defects[defect]
		sort.Strings(cases)
		t.Logf("defect #%d exercised by %d expectation(s): %s", defect, len(cases), strings.Join(cases, ", "))
	}
}

// TestCorpusAnnotationsAreMeaningful guards the corpus against expectations that
// cannot fail. A want-not on a category golem never emits, or a case with only
// positive expectations, reads like coverage while asserting nothing.
func TestCorpusAnnotationsAreMeaningful(t *testing.T) {
	cases, err := corpus.DiscoverCases(corpusRoot)
	if err != nil {
		t.Skipf("corpus not available: %v", err)
	}
	negatives := 0
	for _, dir := range cases {
		annotations, err := corpus.Parse(dir)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(dir), err)
		}
		for _, annotation := range annotations {
			if !annotation.Want {
				negatives++
			}
			if annotation.Want && annotation.KnownFailFor("") == 0 && annotation.Kind == corpus.KindFlow && annotation.Source == "" && annotation.Sink == "" {
				t.Errorf("%s: unconstrained want flow annotation matches anything", annotation)
			}
		}
	}
	// Precision is unmeasurable without negatives, so require a floor rather
	// than discovering later that every case only asserts a positive.
	if minimum := len(cases) / 5; negatives < minimum {
		t.Errorf("corpus has %d negative expectations across %d cases; want at least %d so precision is measurable", negatives, len(cases), minimum)
	}
}

// TestCorpusCategoryVocabulary keeps internal/corpus's category vocabulary in
// step with the categories the analyzer actually emits, so annotations naming a
// real category are never rejected and annotations naming a fictional one are.
func TestCorpusCategoryVocabulary(t *testing.T) {
	known := map[string]bool{}
	for _, category := range corpus.Categories() {
		known[category] = true
	}
	patterns := builtinDataFlowPatterns(nil)
	var missing []string
	for _, pattern := range allDataFlowPatterns(patterns) {
		if pattern.Category != "" && !known[pattern.Category] {
			missing = append(missing, pattern.Category)
		}
	}
	for _, category := range []string{"panic", "http-endpoint"} {
		if !known[category] {
			missing = append(missing, category)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("categories emitted by the analyzer but absent from internal/corpus.Categories: %v", unique(missing))
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// reportIntegrityViolations lists references to identifiers that the report does
// not define. Consumers cannot render evidence they cannot resolve.
func reportIntegrityViolations(report *model.Report) []string {
	var out []string
	if df := report.DataFlow; df != nil {
		nodes := map[string]bool{}
		for _, node := range df.Nodes {
			nodes[node.ID] = true
		}
		edges := map[string]bool{}
		for _, edge := range df.Edges {
			edges[edge.ID] = true
			if !nodes[edge.SourceID] || !nodes[edge.TargetID] {
				out = append(out, "dataflow edge "+edge.ID+" references an unknown node")
			}
		}
		for _, slice := range df.Slices {
			for _, id := range slice.NodeIDs {
				if !nodes[id] {
					out = append(out, "slice "+slice.ID+" references unknown node "+id)
				}
			}
			for _, id := range slice.EdgeIDs {
				if !edges[id] {
					out = append(out, "slice "+slice.ID+" references unknown edge "+id)
				}
			}
		}
	}
	if cg := report.CallGraph; cg != nil {
		nodes := map[string]bool{}
		for _, node := range cg.Nodes {
			nodes[node.ID] = true
		}
		for _, edge := range cg.Edges {
			if !nodes[edge.SourceID] || !nodes[edge.TargetID] {
				out = append(out, "call-graph edge "+edge.ID+" references an unknown node")
			}
		}
	}
	if len(out) > 8 {
		out = append(out[:8], fmt.Sprintf("and %d more", len(out)-8))
	}
	return out
}

// TestCorpusFixturesAreSelfContained asserts each corpus case is its own module,
// so a case cannot accidentally analyze the golem tree around it.
func TestCorpusFixturesAreSelfContained(t *testing.T) {
	cases, err := corpus.DiscoverCases(corpusRoot)
	if err != nil {
		t.Skipf("corpus not available: %v", err)
	}
	for _, dir := range cases {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
			t.Errorf("%s has no go.mod: %v", filepath.Base(dir), err)
		}
	}
}
