package analyzer

import (
	"os"
	"strings"
	"testing"
)

func TestEffectiveLoadEnvRejectsDisallowedKeys(t *testing.T) {
	for _, pair := range []string{"GOFLAGS=-toolexec=/bin/true", "GOENV=/dev/null", "PATH=/usr/bin", "GO111MODULE=off", "CGO_ENABLED=1", "CGO_CFLAGS_ALLOW=-.*", "CGO_LDFLAGS=-Wl,--sysroot"} {
		if _, err := effectiveLoadEnv([]string{pair}, ""); err == nil {
			t.Errorf("effectiveLoadEnv accepted %q; only build-shape keys may be overridden", pair)
		}
	}
	for _, pair := range []string{"GOEXPERIMENT=simd", "GOARCH=amd64", "GOOS=linux", "GOAMD64=v3", "GOARM64=v8.0"} {
		if _, err := effectiveLoadEnv([]string{pair}, ""); err != nil {
			t.Errorf("effectiveLoadEnv rejected allowlisted %q: %v", pair, err)
		}
	}
	if _, err := effectiveLoadEnv([]string{"NOTAPAIR"}, ""); err == nil {
		t.Error("effectiveLoadEnv accepted an entry without '='")
	}
}

func TestEffectiveLoadEnvOptionWinsOverProcessEnvironment(t *testing.T) {
	t.Setenv("GOEXPERIMENT", "regabi")
	env, err := effectiveLoadEnv([]string{"GOEXPERIMENT=simd"}, "")
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
	t.Setenv("CGO_ENABLED", "1")
	env, err := effectiveLoadEnv(nil, "")
	if err != nil {
		t.Fatalf("effectiveLoadEnv(nil): %v", err)
	}
	if env != nil {
		t.Errorf("expected nil (process environment) when no override is set and the process states CGO_ENABLED, got %d entries", len(env))
	}
}

// TestEffectiveLoadEnvPinsCgoOff is the load-side half of the cgo hardening:
// with CGO_ENABLED absent from the process environment the load must run with
// it pinned to 0, so that no #cgo directive or .syso file in the analysed
// tree can drive the host C compiler. A value the analyst exported is their
// choice and passes through untouched, and no build-shape option re-enables
// cgo as a side effect.
func TestEffectiveLoadEnvPinsCgoOff(t *testing.T) {
	for _, value := range []string{"0", "1"} {
		t.Setenv("CGO_ENABLED", value)
		env, err := effectiveLoadEnv(nil, "")
		if err != nil {
			t.Fatalf("effectiveLoadEnv with process CGO_ENABLED=%s: %v", value, err)
		}
		if env != nil {
			t.Fatalf("process environment states CGO_ENABLED=%s; the load should inherit it rather than pin a value (got %d entries)", value, len(env))
		}
	}
	os.Unsetenv("CGO_ENABLED")
	env, err := effectiveLoadEnv(nil, "")
	if err != nil {
		t.Fatalf("effectiveLoadEnv(nil) without process CGO_ENABLED: %v", err)
	}
	found := ""
	for _, entry := range env {
		if strings.HasPrefix(entry, "CGO_ENABLED=") {
			found = entry
		}
	}
	if found != "CGO_ENABLED=0" {
		t.Fatalf("load environment pins %q; without an explicit analyst choice the load must run with CGO_ENABLED=0", found)
	}
	// A build-shape option travels in the same environment and must not
	// un-pin the cgo choice.
	env, err = effectiveLoadEnv([]string{"GOOS=linux"}, "")
	if err != nil {
		t.Fatalf("effectiveLoadEnv with a build-shape option: %v", err)
	}
	found = ""
	for _, entry := range env {
		if strings.HasPrefix(entry, "CGO_ENABLED=") {
			found = entry
		}
	}
	if found != "CGO_ENABLED=0" {
		t.Fatalf("load environment with a build-shape option pins %q for CGO_ENABLED, want CGO_ENABLED=0", found)
	}
}

func TestToolchainCarriesCgoFixes(t *testing.T) {
	cases := map[string]bool{
		"go1.27.4":      true,
		"go1.27.5":      true,
		"go1.27.4rc1":   true,
		"go1.28rc1":     true,
		"go1.27.3":      false,
		"go1.27.1":      false,
		"go1.26.11":     true,
		"go1.26.12rc1":  true,
		"go1.26.10":     false,
		"go1.25.6":      false,
		"go1.21.0":      false,
		"devel +a1b2c3": false,
		"xgo1.27.4":     false,
		"":              false,
	}
	for version, want := range cases {
		if got := toolchainCarriesCgoFixes(version); got != want {
			t.Errorf("toolchainCarriesCgoFixes(%q) = %v, want %v", version, got, want)
		}
	}
}

// The overrides a report may name are the ones that widen the toolchain's flag
// checks for every package; DISALLOW narrows and empty values carry nothing,
// so neither belongs in the list, and a value never leaves this function.
func TestCgoEnvOverrideNames(t *testing.T) {
	names := cgoEnvOverrideNames([]string{
		"CGO_CFLAGS=-DFOO=1",
		"CGO_LDFLAGS_ALLOW=-Wl,.*",
		"CGO_LDFLAGS=",
		"CGO_CFLAGS_DISALLOW=-fplugin",
		"PATH=/usr/bin",
	})
	want := "CGO_CFLAGS, CGO_LDFLAGS_ALLOW"
	if got := strings.Join(names, ", "); got != want {
		t.Errorf("cgoEnvOverrideNames = %q, want %q", got, want)
	}
}

func TestTargetEnvReportsOverrides(t *testing.T) {
	env, err := effectiveLoadEnv([]string{"GOOS=linux", "GOARCH=amd64", "GOEXPERIMENT=simd"}, "")
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

// An empty CGO_ENABLED is not a choice: the go command treats it as unset and
// falls back to its default, which turns cgo on whenever a C compiler exists.
func TestEffectiveLoadEnvPinsCgoOffWhenEmpty(t *testing.T) {
	t.Setenv("CGO_ENABLED", "")
	env, err := effectiveLoadEnv(nil, "")
	if err != nil {
		t.Fatalf("effectiveLoadEnv with an empty CGO_ENABLED: %v", err)
	}
	var found []string
	for _, entry := range env {
		if strings.HasPrefix(entry, "CGO_ENABLED=") {
			found = append(found, entry)
		}
	}
	if len(found) != 1 || found[0] != "CGO_ENABLED=0" {
		t.Fatalf("load environment carries %q for CGO_ENABLED; an empty value must be replaced by CGO_ENABLED=0", found)
	}
}
