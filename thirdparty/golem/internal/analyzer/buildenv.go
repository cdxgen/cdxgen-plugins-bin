package analyzer

import (
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
)

// effectiveLoadEnv merges the option's KEY=VALUE build-shape pairs into the
// process environment for every go command the load spawns.
//
// The returned slice is nil when no pair is set, which packages.Load reads as
// "use the process environment" — the default every existing consumer relies
// on. When pairs are set, entries the process already carries for the same key
// are dropped rather than shadowed by ordering: the option wins, deliberately,
// so --goexperiment simd means simd even in a shell that exported a different
// GOEXPERIMENT. Duplicate keys among the pairs themselves resolve to the last
// declaration.
func effectiveLoadEnv(extra []string) ([]string, error) {
	if len(extra) == 0 {
		return nil, nil
	}
	overrides := map[string]bool{}
	for _, pair := range extra {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid environment override %q: want KEY=VALUE", pair)
		}
		if err := corpus.ValidateEnvPair(key, value); err != nil {
			return nil, err
		}
		overrides[key] = true
	}
	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra))
	for _, entry := range base {
		if key, _, _ := strings.Cut(entry, "="); overrides[key] {
			continue
		}
		out = append(out, entry)
	}
	// A key declared twice among the pairs resolves to the last declaration,
	// so earlier occurrences are dropped here rather than left to whatever
	// precedence the child toolchain gives duplicate entries.
	for i, pair := range extra {
		key, _, _ := strings.Cut(pair, "=")
		duplicated := false
		for _, later := range extra[i+1:] {
			if k, _, _ := strings.Cut(later, "="); k == key {
				duplicated = true
				break
			}
		}
		if !duplicated {
			out = append(out, pair)
		}
	}
	return out, nil
}

// targetEnv reports the build shape the given load environment resolves to:
// the effective GOOS, GOARCH and GOEXPERIMENT, from one `go env -json` call
// run under that same environment. Values that arrived from the analyst's
// process environment are captured too, which is the point of asking the
// toolchain rather than reading the options: the report then describes the
// build the packages were actually loaded for, and not golem's own platform
// (which the existing runtime.goos/runtime.goarch fields continue to mean,
// unchanged, for consumers already reading them).
//
// The probe runs in the analysed directory, as the load does, so a go.mod or
// go.work toolchain line is honoured the same way. A failure is returned rather
// than swallowed: Analyze turns it into an error when the analyst asked for an
// override (a typo such as --goexperiment smd must not become an empty report
// that exits 0), and ignores it otherwise, leaving the fields omitted.
//
// The same call answers GOROOT: the root of the go command the packages are
// loaded through, which decides which module-less packages are the standard
// library (see seam.IsStandardLibraryPackage). One probe serves both, so the
// classification and the reported target always describe the same toolchain.
func targetEnv(dir string, loadEnv []string) (target buildTarget, err error) {
	cmd := exec.Command("go", "env", "-json", "GOOS", "GOARCH", "GOEXPERIMENT", "GOROOT")
	cmd.Dir = dir
	if loadEnv != nil {
		cmd.Env = loadEnv
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return buildTarget{}, fmt.Errorf("go env: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := json.Unmarshal(out, &target); err != nil {
		return buildTarget{}, fmt.Errorf("go env: %w", err)
	}
	return target, nil
}

// buildTarget is the toolchain's answer to targetEnv's probe.
type buildTarget struct {
	GOOS         string `json:"GOOS"`
	GOARCH       string `json:"GOARCH"`
	GOEXPERIMENT string `json:"GOEXPERIMENT"`
	GOROOT       string `json:"GOROOT"`
}

// loadGOROOT returns the GOROOT the packages are loaded with: the probed one,
// or build.Default.GOROOT when the probe could not answer. build.Default
// describes the toolchain golem was built with, and a -trimpath release build
// has none, so it is only the fallback.
func loadGOROOT(target buildTarget) string {
	if root := strings.TrimSpace(target.GOROOT); root != "" {
		return root
	}
	return strings.TrimSpace(build.Default.GOROOT)
}
