package analyzer

import (
	"flag"
	"testing"
)

// fullCorpus opts the expensive suites into their widest configuration.
//
// Every Analyze call reloads and rebuilds SSA for the whole standard-library
// closure, about a second and a half even for a twelve-line fixture, so the
// corpus suites are dominated by that fixed cost multiplied by the number of
// configurations. The default configuration is the one that catches most
// regressions; CI passes -golem.full for the rest.
var fullCorpus = flag.Bool("golem.full", false, "run the corpus suites over every data-flow mode")

// corpusSuiteModes returns the data-flow modes an expensive suite should cover.
func corpusSuiteModes() []string {
	if *fullCorpus {
		return corpusModes
	}
	return []string{"security"}
}

// skipIfShort skips a suite that cannot run quickly.
func skipIfShort(t *testing.T, cost string) {
	t.Helper()
	if testing.Short() {
		t.Skipf("skipping in -short mode: %s", cost)
	}
}
