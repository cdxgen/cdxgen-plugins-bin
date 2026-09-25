package analyzer

import (
	"encoding/json"
	"fmt"
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
func targetEnv(loadEnv []string) (goos, goarch, goexperiment string) {
	cmd := exec.Command("go", "env", "-json", "GOOS", "GOARCH", "GOEXPERIMENT")
	if loadEnv != nil {
		cmd.Env = loadEnv
	}
	out, err := cmd.Output()
	if err != nil {
		// A toolchain that cannot answer should not fail the analysis; the
		// omitted fields say the target is unknown.
		return "", "", ""
	}
	var resolved struct {
		GOOS         string `json:"GOOS"`
		GOARCH       string `json:"GOARCH"`
		GOEXPERIMENT string `json:"GOEXPERIMENT"`
	}
	if err := json.Unmarshal(out, &resolved); err != nil {
		return "", "", ""
	}
	return resolved.GOOS, resolved.GOARCH, resolved.GOEXPERIMENT
}
