package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// BaselineVersion is bumped when the metric set changes shape.
const BaselineVersion = "2"

// Baseline is a committed set of measurements to compare a run against.
type Baseline struct {
	Version string   `json:"version"`
	Tier    string   `json:"tier,omitempty"`
	Results []Result `json:"results"`
}

// LoadBaseline reads a baseline file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}
	return &baseline, nil
}

// Save writes a baseline with results in deterministic order. Wall-clock and
// peak-RSS figures are machine-dependent, so they are recorded for information
// but only compared with a generous margin.
func (b *Baseline) Save(path string) error {
	b.Version = BaselineVersion
	SortResults(b.Results)
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Regression describes one way a run is worse than, or diverges from, a baseline.
type Regression struct {
	Key      string `json:"key"`
	Metric   string `json:"metric"`
	Baseline string `json:"baseline"`
	Current  string `json:"current"`
	Message  string `json:"message"`
	// Blocking marks regressions that should fail a build. Non-blocking
	// entries are improvements that need a baseline refresh.
	Blocking bool `json:"blocking"`
}

func (r Regression) String() string {
	prefix := "IMPROVED"
	if r.Blocking {
		prefix = "REGRESSION"
	}
	return fmt.Sprintf("%s %s %s: %s", prefix, r.Key, r.Metric, r.Message)
}

// CompareOptions tunes regression detection.
type CompareOptions struct {
	// MetricTolerance is the amount a ratio may drop before it counts as a
	// regression.
	MetricTolerance float64
	// TimeToleranceFactor is the multiple of the baseline wall-clock time that
	// counts as a slowdown.
	TimeToleranceFactor float64
	// RequireBaselineCoverage reports fixtures that ran but are absent from the
	// baseline, so a new fixture cannot silently escape comparison.
	RequireBaselineCoverage bool
	// Filtered suppresses reporting of baseline fixtures that did not run,
	// which is expected when the run was narrowed with --only or --tier.
	Filtered bool
}

// DefaultCompareOptions returns the settings used by the CLI.
func DefaultCompareOptions() CompareOptions {
	return CompareOptions{MetricTolerance: 0.005, TimeToleranceFactor: 1.5, RequireBaselineCoverage: true}
}

// comparedMetric is one ratio checked against a baseline in both directions.
type comparedMetric struct {
	name              string
	current, baseline float64
}

// Compare reports how current diverges from baseline.
//
// Unlike a plain "did recall drop" check this also flags results that got
// better than the baseline and known failures that started passing: both mean
// the committed baseline no longer describes the engine, and leaving them
// unreported is how a suite stops being a ratchet.
func Compare(current, baseline *Baseline, options CompareOptions) []Regression {
	indexed := map[string]Result{}
	for _, result := range baseline.Results {
		indexed[result.Key()] = result
	}
	var out []Regression
	seen := map[string]bool{}

	for _, result := range current.Results {
		key := result.Key()
		seen[key] = true

		if result.UnexpectedFailures > 0 {
			out = append(out, Regression{Key: key, Metric: "unexpectedFailures", Current: fmt.Sprint(result.UnexpectedFailures), Blocking: true,
				Message: fmt.Sprintf("%d annotation(s) failed without a known-fail marker", result.UnexpectedFailures)})
		}
		if result.IntegrityViolations > 0 {
			out = append(out, Regression{Key: key, Metric: "integrityViolations", Current: fmt.Sprint(result.IntegrityViolations), Blocking: true,
				Message: fmt.Sprintf("%d reference(s) to identifiers absent from the report", result.IntegrityViolations)})
		}
		if result.UnexpectedPasses > 0 {
			out = append(out, Regression{Key: key, Metric: "unexpectedPasses", Current: fmt.Sprint(result.UnexpectedPasses), Blocking: false,
				Message: fmt.Sprintf("%d known-fail annotation(s) now pass; remove the known-fail marker", result.UnexpectedPasses)})
		}

		base, ok := indexed[key]
		if !ok {
			if options.RequireBaselineCoverage {
				out = append(out, Regression{Key: key, Metric: "coverage", Blocking: false,
					Message: "fixture is not in the baseline; regenerate the baseline to start tracking it"})
			}
			continue
		}
		metrics := []comparedMetric{{"edgeConnectivity", result.EdgeConnectivity, base.EdgeConnectivity}}
		// Quality ratios only mean something where there is ground truth to
		// score against.
		if result.Annotated && base.Annotated {
			metrics = append(metrics,
				comparedMetric{"recall", result.Recall, base.Recall},
				comparedMetric{"precision", result.Precision, base.Precision},
				comparedMetric{"f1", result.F1, base.F1})
		}
		for _, metric := range metrics {
			if metric.current < metric.baseline-options.MetricTolerance {
				out = append(out, Regression{Key: key, Metric: metric.name, Baseline: fmt.Sprintf("%.3f", metric.baseline), Current: fmt.Sprintf("%.3f", metric.current), Blocking: true,
					Message: fmt.Sprintf("%.3f -> %.3f", metric.baseline, metric.current)})
			} else if metric.current > metric.baseline+options.MetricTolerance {
				out = append(out, Regression{Key: key, Metric: metric.name, Baseline: fmt.Sprintf("%.3f", metric.baseline), Current: fmt.Sprintf("%.3f", metric.current), Blocking: false,
					Message: fmt.Sprintf("%.3f -> %.3f; refresh the baseline to lock it in", metric.baseline, metric.current)})
			}
		}
		if result.DepCrossingSlices < base.DepCrossingSlices {
			out = append(out, Regression{Key: key, Metric: "dependencyCrossingSlices", Baseline: fmt.Sprint(base.DepCrossingSlices), Current: fmt.Sprint(result.DepCrossingSlices), Blocking: true,
				Message: fmt.Sprintf("%d -> %d dependency-crossing flows", base.DepCrossingSlices, result.DepCrossingSlices)})
		}
		if base.WallClockMs > 0 && options.TimeToleranceFactor > 0 && float64(result.WallClockMs) > float64(base.WallClockMs)*options.TimeToleranceFactor {
			out = append(out, Regression{Key: key, Metric: "wallClockMs", Baseline: fmt.Sprint(base.WallClockMs), Current: fmt.Sprint(result.WallClockMs), Blocking: true,
				Message: fmt.Sprintf("%dms -> %dms (over %.0f%% of baseline)", base.WallClockMs, result.WallClockMs, options.TimeToleranceFactor*100)})
		}
	}

	for _, base := range baseline.Results {
		if options.Filtered {
			break
		}
		if !seen[base.Key()] {
			out = append(out, Regression{Key: base.Key(), Metric: "coverage", Baseline: "present", Blocking: false,
				Message: "baseline fixture did not run (filtered out, or unavailable)"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Blocking != out[j].Blocking {
			return out[i].Blocking
		}
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Metric < out[j].Metric
	})
	return out
}

// Blocking returns only the regressions that should fail a build.
func Blocking(regressions []Regression) []Regression {
	var out []Regression
	for _, regression := range regressions {
		if regression.Blocking {
			out = append(out, regression)
		}
	}
	return out
}

// Summary aggregates a run for a one-line verdict.
type Summary struct {
	Fixtures            int     `json:"fixtures"`
	AnnotatedFixtures   int     `json:"annotatedFixtures"`
	Annotations         int     `json:"annotations"`
	ExpectedFailures    int     `json:"expectedFailures"`
	UnexpectedFailures  int     `json:"unexpectedFailures"`
	UnexpectedPasses    int     `json:"unexpectedPasses"`
	IntegrityViolations int     `json:"integrityViolations"`
	MeanRecall          float64 `json:"meanRecall"`
	MeanPrecision       float64 `json:"meanPrecision"`
	MinConnectivity     float64 `json:"minEdgeConnectivity"`
	DepCrossingSlices   int     `json:"dependencyCrossingSlices"`
	TotalWallClockMs    int64   `json:"totalWallClockMs"`
	PeakRSSMB           int64   `json:"peakRssMb"`
}

// Summarize computes aggregate figures for a set of results.
func Summarize(results []Result) Summary {
	summary := Summary{Fixtures: len(results), MinConnectivity: 1}
	if len(results) == 0 {
		return summary
	}
	var recall, precision float64
	annotated := 0
	for _, result := range results {
		summary.Annotations += result.Annotations
		summary.ExpectedFailures += result.ExpectedFailures
		summary.UnexpectedFailures += result.UnexpectedFailures
		summary.UnexpectedPasses += result.UnexpectedPasses
		summary.IntegrityViolations += result.IntegrityViolations
		summary.DepCrossingSlices += result.DepCrossingSlices
		summary.TotalWallClockMs += result.WallClockMs
		if result.PeakRSSMB > summary.PeakRSSMB {
			summary.PeakRSSMB = result.PeakRSSMB
		}
		if result.EdgeConnectivity < summary.MinConnectivity {
			summary.MinConnectivity = result.EdgeConnectivity
		}
		if !result.Annotated {
			continue
		}
		annotated++
		recall += result.Recall
		precision += result.Precision
	}
	summary.AnnotatedFixtures = annotated
	if annotated > 0 {
		summary.MeanRecall = round(recall / float64(annotated))
		summary.MeanPrecision = round(precision / float64(annotated))
	}
	return summary
}
