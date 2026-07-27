package bench

import (
	"strings"
	"testing"
)

// legacyRun is a stand-in for the incumbent engine: modest recall, perfect
// precision on what little it finds, and paths that do not always connect.
func legacyRun() []Result {
	return []Result{
		{Name: "go-test-bench", Config: "security", Annotated: true, Recall: 0.55, Precision: 0.90, EdgeConnectivity: 0.74, ExpectedFailures: 20, DepCrossingSlices: 2, WallClockMs: 8000, PeakRSSMB: 900},
		{Name: "shiftleft-go-demo", Config: "security", Annotated: true, Recall: 0.50, Precision: 0.90, EdgeConnectivity: 0.43, ExpectedFailures: 18, DepCrossingSlices: 1, WallClockMs: 2000, PeakRSSMB: 600},
		// An unannotated golden fixture, which is what the real-repo
		// flow-count criterion measures. Without a pair like this the
		// criterion abstains and the run cannot be promoted.
		{Name: "go-chi", Config: "security", Annotated: false, Slices: 10, EdgeConnectivity: 1.0, WallClockMs: 1500, PeakRSSMB: 500},
	}
}

// candidateRun is a stand-in for an engine that clears the bar.
func candidateRun() []Result {
	return []Result{
		{Name: "go-test-bench", Config: "security", Annotated: true, Recall: 0.92, Precision: 0.89, EdgeConnectivity: 1.0, ExpectedFailures: 4, DepCrossingSlices: 9, WallClockMs: 9000, PeakRSSMB: 1100},
		{Name: "shiftleft-go-demo", Config: "security", Annotated: true, Recall: 0.90, Precision: 0.90, EdgeConnectivity: 1.0, ExpectedFailures: 3, DepCrossingSlices: 4, WallClockMs: 2200, PeakRSSMB: 700},
		{Name: "go-chi", Config: "security", Annotated: false, Slices: 10, EdgeConnectivity: 1.0, WallClockMs: 1600, PeakRSSMB: 550},
	}
}

func check(t *testing.T, report PromotionReport, name string) PromotionCheck {
	t.Helper()
	for _, entry := range report.Checks {
		if entry.Name == name {
			return entry
		}
	}
	t.Fatalf("no check named %q in %v", name, report.Checks)
	return PromotionCheck{}
}

func TestPromotionAcceptsAClearWin(t *testing.T) {
	report := EvaluatePromotion(candidateRun(), legacyRun(), DefaultPromotionCriteria())
	if !report.Promote {
		t.Fatalf("expected promotion, got:\n%s", report)
	}
	if report.PairedResults != 3 {
		t.Errorf("PairedResults = %d, want 3", report.PairedResults)
	}
	if gain := check(t, report, "recall gain"); gain.Candidate != "0.910" || gain.Incumbent != "0.525" {
		t.Errorf("recall check reported %+v", gain)
	}
}

func TestPromotionRejectsRecallBoughtWithFalsePositives(t *testing.T) {
	candidate := candidateRun()
	candidate[0].Precision = 0.40
	candidate[1].Precision = 0.40
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted an engine that traded precision for recall")
	}
	if entry := check(t, report, "precision held"); entry.Passed {
		t.Errorf("precision check passed at %+v", entry)
	}
}

func TestPromotionRejectsMarginalRecallGain(t *testing.T) {
	candidate := candidateRun()
	candidate[0].Recall = 0.60
	candidate[1].Recall = 0.55
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted an engine whose recall gain is within noise")
	}
	if entry := check(t, report, "recall gain"); entry.Passed {
		t.Errorf("recall check passed at %+v", entry)
	}
}

func TestPromotionRejectsDisconnectedPaths(t *testing.T) {
	candidate := candidateRun()
	candidate[1].EdgeConnectivity = 0.95
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted an engine that still reports paths a consumer cannot follow")
	}
	if entry := check(t, report, "edge connectivity"); entry.Candidate != "0.950" {
		t.Errorf("connectivity check should report the worst fixture, got %+v", entry)
	}
}

func TestPromotionToleratesModestSlowdownButNotLargeOnes(t *testing.T) {
	// Within the bound: noticeably better for a little more time is the trade
	// the criteria are meant to allow.
	candidate := candidateRun()
	candidate[0].WallClockMs = 9600 // 1.20x
	candidate[1].WallClockMs = 2400 // 1.20x
	if report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria()); !report.Promote {
		t.Fatalf("a 1.2x slowdown should be acceptable:\n%s", report)
	}

	candidate[0].WallClockMs = 20000 // 2.5x
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted an engine that is 2.5x slower on a fixture")
	}
	if len(report.SlowestFixtures) != 1 || !strings.Contains(report.SlowestFixtures[0], "go-test-bench") {
		t.Errorf("SlowestFixtures = %v, want the offending fixture named", report.SlowestFixtures)
	}
}

func TestPromotionRejectsMemoryBlowup(t *testing.T) {
	candidate := candidateRun()
	candidate[0].PeakRSSMB = 4000
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted an engine using 4.4x the memory")
	}
}

func TestPromotionRejectsUnexpectedFailuresAndIntegrityViolations(t *testing.T) {
	candidate := candidateRun()
	candidate[0].UnexpectedFailures = 1
	if EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria()).Promote {
		t.Error("promoted an engine with an unexplained corpus failure")
	}

	candidate = candidateRun()
	candidate[1].IntegrityViolations = 3
	if EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria()).Promote {
		t.Error("promoted an engine emitting references to identifiers it does not define")
	}
}

func TestPromotionRequiresKnownFailuresToClose(t *testing.T) {
	candidate := candidateRun()
	candidate[0].ExpectedFailures = 20
	candidate[1].ExpectedFailures = 18
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted an engine that closed no known defect")
	}
	if entry := check(t, report, "known failures closed"); entry.Passed {
		t.Errorf("known-failure check passed at %+v", entry)
	}
}

// TestPromotionRejectsAnIncompleteRun stops a candidate from looking good by
// skipping the fixtures it struggles with.
func TestPromotionRejectsAnIncompleteRun(t *testing.T) {
	// Drop exactly one fixture, by name, so the assertion below stays about a
	// skipped fixture rather than about how the slice happens to be ordered.
	var candidate []Result
	for _, r := range candidateRun() {
		if r.Name != "shiftleft-go-demo" {
			candidate = append(candidate, r)
		}
	}
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted a candidate that skipped a fixture")
	}
	if len(report.MissingFromCandidate) != 1 || report.MissingFromCandidate[0] != "shiftleft-go-demo/security" {
		t.Errorf("MissingFromCandidate = %v", report.MissingFromCandidate)
	}
}

func TestPromotionRequiresGroundTruth(t *testing.T) {
	candidate, incumbent := candidateRun(), legacyRun()
	for i := range candidate {
		candidate[i].Annotated = false
		incumbent[i].Annotated = false
	}
	report := EvaluatePromotion(candidate, incumbent, DefaultPromotionCriteria())
	if report.Promote {
		t.Fatal("promoted on unlabelled fixtures, where recall is not measurable")
	}
	if entry := check(t, report, "recall"); entry.Passed {
		t.Errorf("recall check passed without ground truth: %+v", entry)
	}
}

func TestPromotionReportRendersEveryCriterion(t *testing.T) {
	text := EvaluatePromotion(candidateRun(), legacyRun(), DefaultPromotionCriteria()).String()
	for _, want := range []string{"PROMOTE", "recall gain", "precision held", "edge connectivity", "median wall clock", "peak memory"} {
		if !strings.Contains(text, want) {
			t.Errorf("report is missing %q:\n%s", want, text)
		}
	}
}

// TestPromotionAbstainsWithoutRealRepoEvidence pins the behaviour that a
// criterion with no data must not report a pass. The quick tier is entirely
// annotated corpus fixtures, so the real-repo flow-count check has nothing to
// measure there; reporting "ok" would be a verdict from a check that never
// ran, which is how a candidate finding one seventh of go-chi's flows cleared
// the gate.
func TestPromotionAbstainsWithoutRealRepoEvidence(t *testing.T) {
	var candidate, incumbent []Result
	for _, r := range candidateRun() {
		if r.Annotated {
			candidate = append(candidate, r)
		}
	}
	for _, r := range legacyRun() {
		if r.Annotated {
			incumbent = append(incumbent, r)
		}
	}
	report := EvaluatePromotion(candidate, incumbent, DefaultPromotionCriteria())
	entry := check(t, report, "real-repo flow count")
	if entry.Passed {
		t.Error("real-repo flow count passed with no unannotated fixture to measure")
	}
	if entry.Candidate != "not measured" {
		t.Errorf("Candidate = %q, want %q", entry.Candidate, "not measured")
	}
	if report.Promote {
		t.Error("promoted on quick-tier evidence alone")
	}
}

// TestPromotionCatchesRealRepoFlowCollapse is the regression this criterion
// exists for: a candidate that wins every corpus metric while finding a
// fraction of the flows on a real repository.
func TestPromotionCatchesRealRepoFlowCollapse(t *testing.T) {
	candidate := candidateRun()
	for i := range candidate {
		if candidate[i].Name == "go-chi" {
			candidate[i].Slices = 1 // incumbent finds 10
		}
	}
	report := EvaluatePromotion(candidate, legacyRun(), DefaultPromotionCriteria())
	if report.Promote {
		t.Fatalf("promoted an engine that collapsed on a real repository:\n%s", report)
	}
	if entry := check(t, report, "real-repo flow count"); entry.Passed {
		t.Errorf("flow-count check passed at %+v", entry)
	}
}
