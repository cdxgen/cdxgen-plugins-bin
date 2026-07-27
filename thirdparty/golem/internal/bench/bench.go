// Package bench measures golem against the annotated corpus and against pinned
// upstream repositories, and compares the measurements to a committed baseline.
//
// The metrics exist to make regressions and unearned wins both visible:
//
//   - precision, recall and F1 come from per-annotation outcomes, with every
//     unsanctioned reported flow counted as a false positive;
//   - edgeConnectivity is the fraction of reported slices whose node and edge
//     lists actually form a path from source to sink;
//   - integrityViolations counts slices or edges that reference identifiers
//     absent from the report;
//   - dependencyCrossingSlices counts flows that leave the module under
//     analysis, which is how taint tracking through dependencies is observed.
package bench

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/analyzer"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// Result holds the measurements for one fixture in one configuration.
type Result struct {
	Name   string `json:"name"`
	Config string `json:"config"`
	// TaintEngine records which engine produced the measurement.
	TaintEngine string `json:"taintEngine,omitempty"`

	// Annotated records whether this fixture carries ground truth. Precision,
	// recall and F1 are meaningless without it: an unannotated repository has no
	// sanctioned flows, so every finding would score as a false positive.
	Annotated        bool    `json:"annotated"`
	Precision        float64 `json:"precision"`
	Recall           float64 `json:"recall"`
	F1               float64 `json:"f1"`
	EdgeConnectivity float64 `json:"edgeConnectivity"`

	TruePositives  int `json:"truePositives"`
	FalsePositives int `json:"falsePositives"`
	FalseNegatives int `json:"falseNegatives"`

	Annotations         int `json:"annotations"`
	ExpectedFailures    int `json:"expectedFailures"`
	UnexpectedFailures  int `json:"unexpectedFailures"`
	UnexpectedPasses    int `json:"unexpectedPasses"`
	IntegrityViolations int `json:"integrityViolations"`

	CallGraphNodes    int `json:"callGraphNodes"`
	CallGraphEdges    int `json:"callGraphEdges"`
	Nodes             int `json:"nodes"`
	Edges             int `json:"edges"`
	Slices            int `json:"slices"`
	UniqueFlows       int `json:"uniqueFlows"`
	Summaries         int `json:"summaries"`
	Truncations       int `json:"truncations"`
	DepCrossingSlices int `json:"dependencyCrossingSlices"`
	UnmodeledSinks    int `json:"unmodeledSinks,omitempty"`

	WallClockMs int64 `json:"wallClockMs"`
	PeakRSSMB   int64 `json:"peakRssMb"`

	// Details are human-readable notes: unexpected outcomes and connectivity
	// failure reasons. They are excluded from regression comparison.
	Details []string `json:"details,omitempty"`
}

// Key identifies a result across runs.
func (r Result) Key() string { return r.Name + "/" + r.Config }

// Options configures a benchmark run.
type Options struct {
	ManifestPath string
	CorpusRoot   string
	CacheDir     string
	Tier         string
	Only         []string
	// TaintEngine overrides the engine for every matrix slot that does not
	// name one, so a whole run can be repeated under a candidate engine.
	TaintEngine string
	Log         io.Writer
	// Reports, when non-nil, receives every generated report so callers can
	// derive additional artifacts (SARIF, digests) without a second analysis.
	Reports func(fixture Fixture, slot MatrixSlot, report *model.Report)
}

// Run executes the manifest and returns results sorted deterministically.
// Fixtures that cannot be materialized are skipped with a log line; fixtures
// that fail to analyze are recorded as errors, because a crash is a result.
func Run(options Options) ([]Result, error) {
	manifest, err := LoadManifest(options.ManifestPath)
	if err != nil {
		return nil, err
	}
	corpusRoot := options.CorpusRoot
	if corpusRoot == "" {
		corpusRoot = filepath.Join(filepath.Dir(options.ManifestPath), "..", "corpus")
	}
	cacheDir, err := CacheDir(options.CacheDir)
	if err != nil {
		return nil, err
	}
	tier := options.Tier
	if tier == "" {
		tier = TierQuick
	}

	var results []Result
	var failures []string
	for _, fixture := range manifest.Select(tier, options.Only) {
		dir, err := fixture.Materialize(corpusRoot, cacheDir)
		if err != nil {
			var unavailable errFixtureUnavailable
			if errors.As(err, &unavailable) {
				logf(options.Log, "bench: skipping %s: %s", fixture.Name, unavailable.reason)
				continue
			}
			failures = append(failures, fmt.Sprintf("%s: %v", fixture.Name, err))
			continue
		}
		annotations, err := corpus.Parse(dir)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: parsing annotations: %v", fixture.Name, err))
			continue
		}
		// Ground truth for a remote fixture lives here rather than in the
		// pinned checkout, which cannot carry comments without ceasing to
		// match its SHA. See corpus.ParseSidecar.
		sidecar, err := loadSidecarAnnotations(options.ManifestPath, fixture.Name)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", fixture.Name, err))
			continue
		}
		annotations = append(annotations, sidecar...)
		for _, slot := range fixture.Matrix {
			if slot.TaintEngine == "" {
				slot.TaintEngine = options.TaintEngine
			}
			result, err := runSlot(fixture, slot, dir, annotations, options)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s/%s: %v", fixture.Name, slot.Label, err))
				continue
			}
			logf(options.Log, "bench: %-34s %-9s%s recall=%.2f precision=%.2f connectivity=%.2f slices=%-5d %dms",
				fixture.Name, slot.Label, engineTag(slot.TaintEngine), result.Recall, result.Precision, result.EdgeConnectivity, result.Slices, result.WallClockMs)
			results = append(results, result)
		}
	}
	SortResults(results)
	if len(failures) > 0 {
		return results, fmt.Errorf("%d fixture failure(s):\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
	return results, nil
}

func runSlot(fixture Fixture, slot MatrixSlot, dir string, annotations []corpus.Annotation, options Options) (Result, error) {
	maxSlices := slot.DataFlowMax
	if maxSlices == 0 {
		maxSlices = 1000
	}
	before := readPeakRSSMB()
	started := time.Now()
	report, err := analyzer.Analyze(analyzer.Options{
		Dir:                   dir,
		IncludeLocal:          true,
		IncludeStdlib:         slot.IncludeStdlib,
		CallGraphMode:         slot.CallGraph,
		Roots:                 slot.Roots,
		DataFlowMode:          slot.DataFlow,
		DataFlowCallGraphMode: slot.DFCallGraph,
		DataFlowMax:           maxSlices,
		TaintEngine:           slot.TaintEngine,
		ToolVersion:           "bench",
	})
	elapsed := time.Since(started)
	if err != nil {
		return Result{}, fmt.Errorf("analyze: %w", err)
	}
	if options.Reports != nil {
		options.Reports(fixture, slot, report)
	}
	result := measure(fixture.Name, slot.Label, report, annotations, slot.DataFlow, !fixture.PartialGroundTruth)
	result.TaintEngine = slot.TaintEngine
	result.WallClockMs = elapsed.Milliseconds()
	if peak := readPeakRSSMB(); peak > before {
		result.PeakRSSMB = peak
	} else {
		result.PeakRSSMB = before
	}
	return result, nil
}

func measure(name, config string, report *model.Report, annotations []corpus.Annotation, mode string, exhaustive bool) Result {
	result := Result{Name: name, Config: config}
	evaluation := corpus.EvaluateWithGroundTruth(report, annotations, mode, exhaustive)

	result.Annotations = len(evaluation.Outcomes)
	result.Annotated = result.Annotations > 0
	if result.Annotated {
		result.TruePositives = evaluation.TruePositives
		result.FalsePositives = evaluation.FalsePositives
		result.FalseNegatives = evaluation.FalseNegatives
		result.Precision = round(evaluation.Precision())
		result.Recall = round(evaluation.Recall())
		result.F1 = round(evaluation.F1())
	}
	for _, outcome := range evaluation.Outcomes {
		switch outcome.Status() {
		case "XFAIL":
			result.ExpectedFailures++
		case "FAIL":
			result.UnexpectedFailures++
		case "XPASS":
			result.UnexpectedPasses++
		}
	}
	for _, outcome := range evaluation.Unexpected {
		result.Details = append(result.Details, fmt.Sprintf("%s: %s: %s", outcome.Status(), outcome.Annotation, outcome.Detail))
	}

	if report.CallGraph != nil {
		result.CallGraphNodes = len(report.CallGraph.Nodes)
		result.CallGraphEdges = len(report.CallGraph.Edges)
	}
	if report.DataFlow != nil {
		result.Nodes = len(report.DataFlow.Nodes)
		result.Edges = len(report.DataFlow.Edges)
		result.Slices = len(report.DataFlow.Slices)
		result.Summaries = len(report.DataFlow.Summaries)
		result.UniqueFlows = report.DataFlow.Stats.UniqueFlowCount
		result.Truncations = len(report.DataFlow.Stats.TruncationReasons)
		result.DepCrossingSlices = countDependencyCrossingSlices(report)
		connectivity, reasons := corpus.Connectivity(report.DataFlow)
		result.EdgeConnectivity = round(connectivity)
		for _, reason := range reasons {
			result.Details = append(result.Details, "disconnected: "+reason)
		}
	} else {
		result.EdgeConnectivity = 1
	}
	result.IntegrityViolations = countIntegrityViolations(report)
	sort.Strings(result.Details)
	return result
}

// countDependencyCrossingSlices counts flows whose nodes span more than one
// module, or touch a module that is not the one under analysis. Deriving this
// from module identity rather than from purl text matters: every Go purl starts
// with pkg:golang/, so a string test on the purl prefix silently reports zero.
func countDependencyCrossingSlices(report *model.Report) int {
	if report == nil || report.DataFlow == nil {
		return 0
	}
	nodeModule := map[string]string{}
	nodeExternal := map[string]bool{}
	for _, node := range report.DataFlow.Nodes {
		if node.Module == nil {
			continue
		}
		nodeModule[node.ID] = node.Module.Path
		nodeExternal[node.ID] = !node.Module.Main
	}
	count := 0
	for _, slice := range report.DataFlow.Slices {
		// An engine that knows it crossed a boundary is more reliable than an
		// inference from node attribution, which reports zero whenever module
		// information is missing rather than admitting it does not know.
		if slice.CrossesDependency {
			count++
			continue
		}
		ids := append([]string{slice.SourceID, slice.SinkID}, slice.NodeIDs...)
		modules := map[string]bool{}
		external := false
		for _, id := range ids {
			if path, ok := nodeModule[id]; ok {
				modules[path] = true
			}
			if nodeExternal[id] {
				external = true
			}
		}
		if external || len(modules) > 1 {
			count++
		}
	}
	return count
}

// countIntegrityViolations counts references to identifiers that are not present
// in the report. Any non-zero value means a consumer cannot reconstruct the
// evidence golem claims to have produced.
func countIntegrityViolations(report *model.Report) int {
	violations := 0
	if report.DataFlow != nil {
		nodes := map[string]bool{}
		for _, node := range report.DataFlow.Nodes {
			nodes[node.ID] = true
		}
		edges := map[string]bool{}
		for _, edge := range report.DataFlow.Edges {
			edges[edge.ID] = true
			if !nodes[edge.SourceID] || !nodes[edge.TargetID] {
				violations++
			}
		}
		for _, slice := range report.DataFlow.Slices {
			if !nodes[slice.SourceID] || !nodes[slice.SinkID] {
				violations++
			}
			for _, id := range slice.NodeIDs {
				if !nodes[id] {
					violations++
				}
			}
			for _, id := range slice.EdgeIDs {
				if !edges[id] {
					violations++
				}
			}
		}
	}
	if report.CallGraph != nil {
		nodes := map[string]bool{}
		for _, node := range report.CallGraph.Nodes {
			nodes[node.ID] = true
		}
		for _, edge := range report.CallGraph.Edges {
			if !nodes[edge.SourceID] || !nodes[edge.TargetID] {
				violations++
			}
		}
	}
	return violations
}

func round(value float64) float64 {
	return float64(int64(value*1000+0.5)) / 1000
}

// engineTag labels log lines when a non-default engine produced them.
func engineTag(engine string) string {
	if engine == "" || engine == "legacy" {
		return ""
	}
	return " [" + engine + "]"
}

func logf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}

// loadSidecarAnnotations reads testdata/bench/annotations/<fixture>.golem when
// it exists. A fixture with no sidecar simply has none.
func loadSidecarAnnotations(manifestPath, fixture string) ([]corpus.Annotation, error) {
	if manifestPath == "" || fixture == "" {
		return nil, nil
	}
	path := filepath.Join(filepath.Dir(manifestPath), "annotations", fixture+".golem")
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	annotations, err := corpus.ParseSidecar(path)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return annotations, nil
}
