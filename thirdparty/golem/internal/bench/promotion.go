package bench

import (
	"fmt"
	"sort"
	"strings"
)

// PromotionCriteria decides when a candidate engine may replace the incumbent
// as the default.
//
// The thresholds exist so the decision is computed rather than argued. A new
// engine is worth switching to when it finds materially more of what is really
// there, invents no more than it did before, reports evidence a consumer can
// actually follow, and costs about the same to run. Each of those is a number
// below.
type PromotionCriteria struct {
	// MinRecallGain is how much mean recall must improve across annotated
	// fixtures for the change to count as noticeable rather than noise.
	MinRecallGain float64
	// MaxPrecisionLoss is the mean precision the candidate may give up. Recall
	// bought with false positives is not an improvement.
	MaxPrecisionLoss float64
	// MinConnectivity is the fraction of reported flows whose node and edge
	// lists must form a real source-to-sink path.
	MinConnectivity float64
	// RequireFewerKnownFailures demands the candidate close known defects rather
	// than merely move them around.
	RequireFewerKnownFailures bool
	// MaxMedianTimeFactor and MaxSingleTimeFactor bound the slowdown, at the
	// median and for the worst single fixture.
	MaxMedianTimeFactor float64
	MaxSingleTimeFactor float64
	// MaxMemoryFactor bounds peak resident memory growth.
	MaxMemoryFactor float64
	// MaxFlowCountLossRatio is the minimum candidate/incumbent flow-count ratio
	// allowed per fixture on the full tier. A candidate that finds materially
	// fewer flows on a real repository (the go-chi recall collapse) fails here
	// even when the quick-tier corpus is green. Measured on the full tier
	// because the quick tier has no real repositories.
	MaxFlowCountLossRatio float64
}

// DefaultPromotionCriteria is the bar for making a new engine the default.
func DefaultPromotionCriteria() PromotionCriteria {
	return PromotionCriteria{
		MinRecallGain:             0.15,
		MaxPrecisionLoss:          0.02,
		MinConnectivity:           1.0,
		RequireFewerKnownFailures: true,
		MaxMedianTimeFactor:       1.20,
		MaxSingleTimeFactor:       1.50,
		MaxMemoryFactor:           1.50,
		MaxFlowCountLossRatio:     0.80,
	}
}

// PromotionCheck is one criterion and how the candidate fared against it.
type PromotionCheck struct {
	Name      string  `json:"name"`
	Passed    bool    `json:"passed"`
	Incumbent string  `json:"incumbent,omitempty"`
	Candidate string  `json:"candidate,omitempty"`
	Threshold string  `json:"threshold,omitempty"`
	Detail    string  `json:"detail,omitempty"`
	Margin    float64 `json:"margin,omitempty"`
}

// PromotionReport is the verdict on whether a candidate engine should become
// the default, with every input to that verdict recorded.
type PromotionReport struct {
	Criteria             PromotionCriteria `json:"criteria"`
	PairedResults        int               `json:"pairedResults"`
	MissingFromCandidate []string          `json:"missingFromCandidate,omitempty"`
	Checks               []PromotionCheck  `json:"checks"`
	Promote              bool              `json:"promote"`
	SlowestFixtures      []string          `json:"slowestFixtures,omitempty"`
}

// EvaluatePromotion compares a candidate engine's measurements against the
// incumbent's. Results are paired by fixture and configuration, so both runs
// must come from the same manifest and tier.
func EvaluatePromotion(candidate, incumbent []Result, criteria PromotionCriteria) PromotionReport {
	report := PromotionReport{Criteria: criteria}
	incumbentByKey := map[string]Result{}
	for _, result := range incumbent {
		incumbentByKey[result.Key()] = result
	}

	type pair struct{ candidate, incumbent Result }
	var pairs []pair
	seen := map[string]bool{}
	for _, result := range candidate {
		seen[result.Key()] = true
		if base, ok := incumbentByKey[result.Key()]; ok {
			pairs = append(pairs, pair{result, base})
		}
	}
	for _, result := range incumbent {
		if !seen[result.Key()] {
			report.MissingFromCandidate = append(report.MissingFromCandidate, result.Key())
		}
	}
	sort.Strings(report.MissingFromCandidate)
	report.PairedResults = len(pairs)

	add := func(check PromotionCheck) { report.Checks = append(report.Checks, check) }

	if len(pairs) == 0 {
		add(PromotionCheck{Name: "paired results", Passed: false,
			Detail: "no fixture ran under both engines; run the same manifest and tier for each"})
		return report
	}
	add(PromotionCheck{Name: "fixture coverage", Passed: len(report.MissingFromCandidate) == 0,
		Incumbent: fmt.Sprint(len(incumbent)), Candidate: fmt.Sprint(len(candidate)),
		Detail: coverageDetail(report.MissingFromCandidate)})

	// Correctness of the evidence itself, measured on the candidate alone.
	var candidateFailures, candidateIntegrity, candidateKnown, incumbentKnown int
	minConnectivity := 1.0
	for _, p := range pairs {
		candidateFailures += p.candidate.UnexpectedFailures
		candidateIntegrity += p.candidate.IntegrityViolations
		candidateKnown += p.candidate.ExpectedFailures
		incumbentKnown += p.incumbent.ExpectedFailures
		if p.candidate.EdgeConnectivity < minConnectivity {
			minConnectivity = p.candidate.EdgeConnectivity
		}
	}
	add(PromotionCheck{Name: "no unexpected failures", Passed: candidateFailures == 0,
		Candidate: fmt.Sprint(candidateFailures), Threshold: "0"})
	add(PromotionCheck{Name: "no integrity violations", Passed: candidateIntegrity == 0,
		Candidate: fmt.Sprint(candidateIntegrity), Threshold: "0"})
	add(PromotionCheck{Name: "edge connectivity", Passed: minConnectivity >= criteria.MinConnectivity,
		Candidate: fmt.Sprintf("%.3f", minConnectivity), Threshold: fmt.Sprintf(">=%.3f", criteria.MinConnectivity),
		Detail: "worst fixture; a flow whose path does not connect is not evidence"})
	if criteria.RequireFewerKnownFailures {
		add(PromotionCheck{Name: "known failures closed", Passed: candidateKnown < incumbentKnown,
			Incumbent: fmt.Sprint(incumbentKnown), Candidate: fmt.Sprint(candidateKnown), Threshold: "fewer"})
	}

	// Quality, over fixtures that carry ground truth in both runs.
	var recallCandidate, recallIncumbent, precisionCandidate, precisionIncumbent float64
	annotated := 0
	for _, p := range pairs {
		if !p.candidate.Annotated || !p.incumbent.Annotated {
			continue
		}
		annotated++
		recallCandidate += p.candidate.Recall
		recallIncumbent += p.incumbent.Recall
		precisionCandidate += p.candidate.Precision
		precisionIncumbent += p.incumbent.Precision
	}
	if annotated == 0 {
		add(PromotionCheck{Name: "recall", Passed: false,
			Detail: "no paired fixture carries ground truth; recall cannot be compared"})
	} else {
		meanRecallCandidate := recallCandidate / float64(annotated)
		meanRecallIncumbent := recallIncumbent / float64(annotated)
		gain := meanRecallCandidate - meanRecallIncumbent
		add(PromotionCheck{Name: "recall gain", Passed: gain >= criteria.MinRecallGain,
			Incumbent: fmt.Sprintf("%.3f", meanRecallIncumbent), Candidate: fmt.Sprintf("%.3f", meanRecallCandidate),
			Threshold: fmt.Sprintf("+%.2f", criteria.MinRecallGain), Margin: round(gain - criteria.MinRecallGain),
			Detail: fmt.Sprintf("mean over %d annotated fixture(s)", annotated)})

		meanPrecisionCandidate := precisionCandidate / float64(annotated)
		meanPrecisionIncumbent := precisionIncumbent / float64(annotated)
		loss := meanPrecisionIncumbent - meanPrecisionCandidate
		add(PromotionCheck{Name: "precision held", Passed: loss <= criteria.MaxPrecisionLoss,
			Incumbent: fmt.Sprintf("%.3f", meanPrecisionIncumbent), Candidate: fmt.Sprintf("%.3f", meanPrecisionCandidate),
			Threshold: fmt.Sprintf("-%.2f at worst", criteria.MaxPrecisionLoss), Margin: round(criteria.MaxPrecisionLoss - loss),
			Detail: "recall bought with false positives is not an improvement"})
	}

	// Reach across dependencies, the property the engine exists to gain.
	var depCandidate, depIncumbent int
	for _, p := range pairs {
		depCandidate += p.candidate.DepCrossingSlices
		depIncumbent += p.incumbent.DepCrossingSlices
	}
	add(PromotionCheck{Name: "dependency-crossing flows", Passed: depCandidate >= depIncumbent,
		Incumbent: fmt.Sprint(depIncumbent), Candidate: fmt.Sprint(depCandidate), Threshold: "not fewer"})

	// Real-repository flow count: on fixtures without annotations (the golden
	// tier — go-chi, gorilla-mux, prometheus, hugo), the candidate must not
	// find materially fewer flows than the incumbent. The corpus on the quick
	// tier cannot see this: every fixture is twenty lines with a handful of
	// functions, so it cannot distinguish an engine that scales from one that
	// does not. This criterion is what would have caught the delivery that
	// reported PROMOTE while SEAM found 1/7 of go-chi's flows.
	if criteria.MaxFlowCountLossRatio > 0 {
		var flowFailures []string
		worstRatio := 1.0
		compared := 0
		for _, p := range pairs {
			if p.candidate.Annotated || p.incumbent.Annotated {
				continue // golden fixtures are unannotated
			}
			if p.incumbent.Slices == 0 {
				continue // nothing to compare
			}
			compared++
			ratio := float64(p.candidate.Slices) / float64(p.incumbent.Slices)
			if ratio < worstRatio {
				worstRatio = ratio
			}
			if ratio < criteria.MaxFlowCountLossRatio {
				flowFailures = append(flowFailures, fmt.Sprintf("%s %d->%d (%.0f%%)", p.candidate.Key(), p.incumbent.Slices, p.candidate.Slices, ratio*100))
			}
		}
		sort.Strings(flowFailures)
		switch {
		case compared == 0:
			// Nothing was measured, so nothing can be concluded. The quick
			// tier is entirely annotated corpus fixtures, so this criterion
			// only has data under --tier full. Reporting "ok" here would be a
			// passing verdict from a check that never ran, which is how the
			// go-chi collapse cleared the gate in the first place.
			add(PromotionCheck{Name: "real-repo flow count", Passed: false,
				Candidate: "not measured", Threshold: fmt.Sprintf(">=%.0f%%", criteria.MaxFlowCountLossRatio*100),
				Detail: "no unannotated fixture pairs in this run; re-run with --tier full, which includes the real repositories"})
		default:
			detail := fmt.Sprintf("per-fixture flow count over %d unannotated (golden) fixture pair(s)", compared)
			if len(flowFailures) > 0 {
				if len(flowFailures) > 5 {
					detail += "; " + strings.Join(flowFailures[:5], ", ") + fmt.Sprintf(", ... (%d total)", len(flowFailures))
				} else {
					detail += "; " + strings.Join(flowFailures, ", ")
				}
			}
			add(PromotionCheck{Name: "real-repo flow count", Passed: len(flowFailures) == 0,
				Candidate: fmt.Sprintf("%.0f%% worst", worstRatio*100), Threshold: fmt.Sprintf(">=%.0f%%", criteria.MaxFlowCountLossRatio*100),
				Detail: detail})
		}
	}

	// Cost.
	var ratios []float64
	worstRatio, worstKey := 0.0, ""
	var slowest []string
	for _, p := range pairs {
		if p.incumbent.WallClockMs <= 0 {
			continue
		}
		ratio := float64(p.candidate.WallClockMs) / float64(p.incumbent.WallClockMs)
		ratios = append(ratios, ratio)
		if ratio > worstRatio {
			worstRatio, worstKey = ratio, p.candidate.Key()
		}
		if ratio > criteria.MaxSingleTimeFactor {
			slowest = append(slowest, fmt.Sprintf("%s %.2fx (%dms -> %dms)", p.candidate.Key(), ratio, p.incumbent.WallClockMs, p.candidate.WallClockMs))
		}
	}
	sort.Strings(slowest)
	report.SlowestFixtures = slowest
	if len(ratios) == 0 {
		add(PromotionCheck{Name: "wall clock", Passed: false, Detail: "no timed pair to compare"})
	} else {
		median := medianOf(ratios)
		add(PromotionCheck{Name: "median wall clock", Passed: median <= criteria.MaxMedianTimeFactor,
			Candidate: fmt.Sprintf("%.2fx", median), Threshold: fmt.Sprintf("<=%.2fx", criteria.MaxMedianTimeFactor),
			Margin: round(criteria.MaxMedianTimeFactor - median)})
		add(PromotionCheck{Name: "worst wall clock", Passed: worstRatio <= criteria.MaxSingleTimeFactor,
			Candidate: fmt.Sprintf("%.2fx", worstRatio), Threshold: fmt.Sprintf("<=%.2fx", criteria.MaxSingleTimeFactor),
			Detail: worstKey})
	}

	var memoryRatio float64
	var candidatePeak, incumbentPeak int64
	for _, p := range pairs {
		if p.candidate.PeakRSSMB > candidatePeak {
			candidatePeak = p.candidate.PeakRSSMB
		}
		if p.incumbent.PeakRSSMB > incumbentPeak {
			incumbentPeak = p.incumbent.PeakRSSMB
		}
	}
	if incumbentPeak > 0 {
		memoryRatio = float64(candidatePeak) / float64(incumbentPeak)
		add(PromotionCheck{Name: "peak memory", Passed: memoryRatio <= criteria.MaxMemoryFactor,
			Incumbent: fmt.Sprintf("%dMB", incumbentPeak), Candidate: fmt.Sprintf("%dMB", candidatePeak),
			Threshold: fmt.Sprintf("<=%.2fx", criteria.MaxMemoryFactor)})
	}

	report.Promote = true
	for _, check := range report.Checks {
		if !check.Passed {
			report.Promote = false
			break
		}
	}
	return report
}

func coverageDetail(missing []string) string {
	if len(missing) == 0 {
		return "candidate ran every fixture the incumbent did"
	}
	if len(missing) > 4 {
		return fmt.Sprintf("%d fixture(s) missing from the candidate run, including %s", len(missing), strings.Join(missing[:4], ", "))
	}
	return "missing from the candidate run: " + strings.Join(missing, ", ")
}

func medianOf(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64{}, values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

// String renders the verdict as a table a human can act on.
func (r PromotionReport) String() string {
	var b strings.Builder
	verdict := "HOLD — candidate does not yet meet the bar to become the default"
	if r.Promote {
		verdict = "PROMOTE — candidate meets every criterion to become the default"
	}
	fmt.Fprintf(&b, "%s\n%d paired result(s)\n\n", verdict, r.PairedResults)
	fmt.Fprintf(&b, "  %-26s %-9s %-11s %-11s %s\n", "criterion", "verdict", "incumbent", "candidate", "threshold")
	for _, check := range r.Checks {
		status := "fail"
		if check.Passed {
			status = "ok"
		}
		fmt.Fprintf(&b, "  %-26s %-9s %-11s %-11s %s\n", check.Name, status, dashIfEmpty(check.Incumbent), dashIfEmpty(check.Candidate), dashIfEmpty(check.Threshold))
		if check.Detail != "" {
			fmt.Fprintf(&b, "  %-26s %s\n", "", check.Detail)
		}
	}
	if len(r.SlowestFixtures) > 0 {
		fmt.Fprintf(&b, "\n  fixtures over the per-fixture time bound:\n")
		for _, entry := range r.SlowestFixtures {
			fmt.Fprintf(&b, "    %s\n", entry)
		}
	}
	return b.String()
}

func dashIfEmpty(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
