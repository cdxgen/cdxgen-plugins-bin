package analyzer

import (
	"flag"
	"os"
	"strconv"
	"testing"
)

// fullCorpus opts the expensive suites into their widest configuration.
//
// Every Analyze call reloads and rebuilds SSA for the whole standard-library
// closure, about a second and a half even for a twelve-line fixture, so the
// corpus suites are dominated by that fixed cost multiplied by the number of
// configurations. The default configuration is the one that catches most
// regressions; CI sets GOLEM_FULL=1 for the rest.
//
// The environment variable is the form that works across the whole module. A
// test flag is registered per test binary, so `go test ./... -golem.full` — the
// command the README documented — fails in every package that does not declare
// it, which is every package but this one. That is how the wide tier went
// unrun: the documented command exited non-zero for a reason that reads like a
// flag typo, and the parity differences it was the only suite to report sat
// unrecorded.
var fullCorpus = flag.Bool("golem.full", envFlag("GOLEM_FULL"), "run the corpus suites over every data-flow mode (or set GOLEM_FULL=1)")

// envFlag reads a boolean environment variable, treating anything unparseable
// as unset rather than as true, so a stray value cannot silently promote the
// slow tier to the default.
func envFlag(name string) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return false
	}
	on, err := strconv.ParseBool(value)
	return err == nil && on
}

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
