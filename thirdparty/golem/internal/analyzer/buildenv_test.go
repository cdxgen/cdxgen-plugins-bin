package analyzer

import (
	"strings"
	"testing"
)

func TestEffectiveLoadEnvRejectsDisallowedKeys(t *testing.T) {
	for _, pair := range []string{"GOFLAGS=-toolexec=/bin/true", "GOENV=/dev/null", "PATH=/usr/bin", "GO111MODULE=off"} {
		if _, err := effectiveLoadEnv([]string{pair}); err == nil {
			t.Errorf("effectiveLoadEnv accepted %q; only build-shape keys may be overridden", pair)
		}
	}
	for _, pair := range []string{"GOEXPERIMENT=simd", "GOARCH=amd64", "GOOS=linux", "GOAMD64=v3", "GOARM64=v8.0"} {
		if _, err := effectiveLoadEnv([]string{pair}); err != nil {
			t.Errorf("effectiveLoadEnv rejected allowlisted %q: %v", pair, err)
		}
	}
	if _, err := effectiveLoadEnv([]string{"NOTAPAIR"}); err == nil {
		t.Error("effectiveLoadEnv accepted an entry without '='")
	}
}

func TestEffectiveLoadEnvOptionWinsOverProcessEnvironment(t *testing.T) {
	t.Setenv("GOEXPERIMENT", "regabi")
	env, err := effectiveLoadEnv([]string{"GOEXPERIMENT=simd"})
	if err != nil {
		t.Fatalf("effectiveLoadEnv: %v", err)
	}
	count := 0
	for _, entry := range env {
		if strings.HasPrefix(entry, "GOEXPERIMENT=") {
			count++
			if entry != "GOEXPERIMENT=simd" {
				t.Errorf("option did not win over the process environment: %q", entry)
			}
		}
	}
	if count != 1 {
		t.Errorf("GOEXPERIMENT appears %d times in the merged environment, want exactly 1", count)
	}
}

func TestEffectiveLoadEnvNilWhenNothingOverridden(t *testing.T) {
	env, err := effectiveLoadEnv(nil)
	if err != nil {
		t.Fatalf("effectiveLoadEnv(nil): %v", err)
	}
	if env != nil {
		t.Errorf("expected nil (process environment) when no override is set, got %d entries", len(env))
	}
}

func TestTargetEnvReportsOverrides(t *testing.T) {
	env, err := effectiveLoadEnv([]string{"GOOS=linux", "GOARCH=amd64", "GOEXPERIMENT=simd"})
	if err != nil {
		t.Fatalf("effectiveLoadEnv: %v", err)
	}
	target, err := targetEnv(".", env)
	if err != nil {
		t.Fatalf("targetEnv: %v", err)
	}
	goos, goarch, goexperiment := target.GOOS, target.GOARCH, target.GOEXPERIMENT
	if target.GOROOT == "" {
		t.Error("targetEnv did not report the toolchain's GOROOT")
	}
	if goos != "linux" || goarch != "amd64" || goexperiment != "simd" {
		t.Errorf("targetEnv = %q/%q/%q, want linux/amd64/simd", goos, goarch, goexperiment)
	}
}

// An override the toolchain rejects must fail the analysis rather than produce
// an empty report that exits 0: a typo in --goexperiment is otherwise
// indistinguishable from a module with no findings.
func TestAnalyzeRejectsUnknownGoexperiment(t *testing.T) {
	_, err := Analyze(Options{Dir: "../../testdata/corpus/direct-flow", Env: []string{"GOEXPERIMENT=smd"}, ToolVersion: "test"})
	if err == nil || !strings.Contains(err.Error(), "unknown GOEXPERIMENT") {
		t.Fatalf("Analyze with GOEXPERIMENT=smd: err = %v, want the toolchain's unknown GOEXPERIMENT error", err)
	}
}
