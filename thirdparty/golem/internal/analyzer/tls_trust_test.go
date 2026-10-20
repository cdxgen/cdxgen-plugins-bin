package analyzer

import (
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
	// Positives: two custom-roots sites (tls.Config and x509.VerifyOptions),
	// two custom-verify sites (one of which is also VERIFY-REPLACED), one
	// embedded pool.
	expected := map[string]int{
		"GOLEM-CRYPTO-TLS-CUSTOM-ROOTS":    2,
		"GOLEM-CRYPTO-TLS-CUSTOM-VERIFY":   2,
		"GOLEM-CRYPTO-TLS-VERIFY-REPLACED": 1,
		"GOLEM-CRYPTO-X509-EMBEDDED-POOL":  2,
		// The existing critical InsecureSkipVerify finding: one from
		// verifyReplaced and one from the insecureOnly negative.
		"GOLEM-CRYPTO-TLS-INSECURE-SKIP-VERIFY": 2,
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
	// The embedded-pool finding names the variable.
	for _, finding := range report.Crypto.Findings {
		if finding.RuleID == "GOLEM-CRYPTO-X509-EMBEDDED-POOL" {
			if finding.Properties["variable"] != "embeddedPoolBytes" {
				t.Fatalf("expected the embedded variable name, got %#v", finding.Properties)
			}
		}
		if finding.RuleID == "GOLEM-CRYPTO-TLS-CUSTOM-ROOTS" {
			if finding.Properties["field"] == "" {
				t.Fatalf("expected the root field name, got %#v", finding.Properties)
			}
		}
	}
}
