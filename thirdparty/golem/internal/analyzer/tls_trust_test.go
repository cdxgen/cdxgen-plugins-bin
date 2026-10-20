package analyzer

import (
	"maps"
	"path/filepath"
	"testing"
)

// TestAnalyzeTLSTrustCustomisation covers the four trust-customisation
// findings: two positives and one negative per rule in
// testdata/tlstrust. The negatives must not add findings beyond the
// expected counts, and the existing InsecureSkipVerify finding must still
// fire alongside VERIFY-REPLACED.
func TestAnalyzeTLSTrustCustomisation(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "tlstrust"), IncludeLocal: true, CallGraphMode: "none", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Crypto == nil {
		t.Fatal("expected crypto evidence")
	}
	counts := map[string]int{}
	for _, finding := range report.Crypto.Findings {
		counts[finding.RuleID]++
		if finding.Confidence != "type-resolved" {
			t.Fatalf("expected type-resolved confidence for %s, got %q", finding.RuleID, finding.Confidence)
		}
	}
	// Positives (testdata/tlstrust/main.go):
	//   custom roots: customRoots, verifyOptionsCustomRoots, aliasRoots,
	//     assignedAfter;
	//   custom verify: customVerify, verifyReplaced, constSkip, assignedAfter;
	//   verify replaced: verifyReplaced, constSkip, assignedAfter (across
	//     statements);
	//   embedded pool: customRoots, embeddedPool, and the three in
	//     embeddedVariants (string conversion, grouped var, other package).
	// The existing InsecureSkipVerify rule fires for verifyReplaced,
	// insecureOnly, constSkip and the assignment in assignedAfter, and not
	// for the shadowed true in shadowedAndCopied.
	expected := map[string]int{
		"GOLEM-CRYPTO-TLS-CUSTOM-ROOTS":         4,
		"GOLEM-CRYPTO-TLS-CUSTOM-VERIFY":        4,
		"GOLEM-CRYPTO-TLS-VERIFY-REPLACED":      3,
		"GOLEM-CRYPTO-X509-EMBEDDED-POOL":       5,
		"GOLEM-CRYPTO-TLS-INSECURE-SKIP-VERIFY": 4,
	}
	for ruleID, want := range expected {
		if counts[ruleID] != want {
			t.Fatalf("expected %d findings for %s, got %d (all: %#v)", want, ruleID, counts[ruleID], counts)
		}
		delete(counts, ruleID)
	}
	// No unexpected rule IDs beyond the expected set.
	delete(counts, "GOLEM-CRYPTO-LITERAL-MATERIAL")
	if len(counts) != 0 {
		t.Fatalf("unexpected additional findings: %#v", counts)
	}
	// The embedded-pool finding names the variable, and its package when it
	// is another one.
	variables := map[string]int{}
	for _, finding := range report.Crypto.Findings {
		if finding.RuleID == "GOLEM-CRYPTO-X509-EMBEDDED-POOL" {
			variables[finding.Properties["package"]+"."+finding.Properties["variable"]]++
		}
		if finding.RuleID == "GOLEM-CRYPTO-TLS-CUSTOM-ROOTS" {
			if finding.Properties["field"] == "" {
				t.Fatalf("expected the root field name, got %#v", finding.Properties)
			}
		}
	}
	wantVariables := map[string]int{".embeddedPoolBytes": 2, ".embeddedPoolString": 1, ".groupedPoolBytes": 1, "example.com/golem/tlstrust/bundle.PEM": 1}
	if !maps.Equal(variables, wantVariables) {
		t.Fatalf("embedded pool variables = %v, want %v", variables, wantVariables)
	}
}
