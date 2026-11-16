package analyzer

import (
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
)

// effectiveLoadEnv merges the option's KEY=VALUE build-shape pairs into the
// process environment for every go command the load spawns.
//
// The returned slice is nil when no pair is set and the cgo default does not
// apply, which packages.Load reads as "use the process environment" — the
// default every existing consumer relies on. When pairs are set, entries the
// process already carries for the same key are dropped rather than shadowed by
// ordering: the option wins, deliberately, so --goexperiment simd means simd
// even in a shell that exported a different GOEXPERIMENT. Duplicate keys among
// the pairs themselves resolve to the last declaration.
//
// cgoEnabled, when non-empty, is the CGO_ENABLED the load must run with. It is
// the test seam for this package's parallel tests, which cannot touch the
// process environment; every other caller leaves it empty and cgoEnabledFor
// decides from the process environment: unset means the analyst did not ask
// for cgo, and the load runs with CGO_ENABLED=0 so that no #cgo directive,
// .syso file or pkg-config line in the analysed tree can drive the host C
// compiler. A value the analyst exported ("1" to opt in, "0" explicitly) is
// passed through unchanged.
func effectiveLoadEnv(extra []string, cgoEnabled string) ([]string, error) {
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
	if cgoEnabled == "" {
		cgoEnabled = cgoEnabledFor(os.Environ())
	}
	// CGO_ENABLED is never among the validated pairs (the allowlist is the
	// build shape only), so setting it here cannot fight an option.
	if cgoEnabled != "" {
		overrides["CGO_ENABLED"] = true
	}
	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra)+1)
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
	if cgoEnabled != "" {
		out = append(out, "CGO_ENABLED="+cgoEnabled)
	}
	if len(out) == len(base) && len(extra) == 0 {
		// Nothing was overridden and the process environment already states
		// the cgo choice, so the load can inherit it directly.
		return nil, nil
	}
	return out, nil
}

// cgoEnabledFor reports the CGO_ENABLED value the load must pin, or "" when
// the environment already states the analyst's choice and the load may inherit
// it. An unset CGO_ENABLED would otherwise let the toolchain's own default
// (cgo on whenever a C compiler is present) run the host compiler with flags
// any package in the module graph chooses; the fixes are go1.26.11 and
// go1.27.4, and a report cannot assume the host runs one of them.
func cgoEnabledFor(environ []string) string {
	for _, entry := range environ {
		if strings.HasPrefix(entry, "CGO_ENABLED=") {
			return ""
		}
	}
	return "0"
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
// The same call answers GOROOT (which decides which module-less packages are
// the standard library, see seam.IsStandardLibraryPackage), GOVERSION (the
// toolchain the cgo flag checks live in), CGO_ENABLED (the cgo mode the load
// actually ran with) and GOCACHE/GOMODCACHE (which files are build output
// rather than source; see reportableSource). One probe serves all, so every
// consumer describes the same toolchain.
func targetEnv(dir string, loadEnv []string) (target buildTarget, err error) {
	cmd := exec.Command("go", "env", "-json", "GOOS", "GOARCH", "GOEXPERIMENT", "GOROOT", "GOVERSION", "CGO_ENABLED", "GOCACHE", "GOMODCACHE")
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
	GOVERSION    string `json:"GOVERSION"`
	CGOEnabled   string `json:"CGO_ENABLED"`
	GOCACHE      string `json:"GOCACHE"`
	GOMODCACHE   string `json:"GOMODCACHE"`
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

// cgoFixedPatchByMinor maps a Go minor line to the first patch release that
// carries the 2026-11 cgo flag fixes (CVE-2026-97033 through CVE-2026-97043).
// Lines older than 1.26 never received them, and later lines are born with
// them, including their release candidates.
var cgoFixedPatchByMinor = map[int]int{
	26: 11,
	27: 4,
}

// toolchainCarriesCgoFixes reports whether the probed toolchain version refuses
// the cgo flags listed in the go1.26.11 and go1.27.4 release notes. A "devel"
// toolchain cannot be judged, so it counts as unpatched: the analyst then sees
// the warning rather than a false assurance.
func toolchainCarriesCgoFixes(goVersion string) bool {
	minor, patch, ok := parseGoMinorPatch(goVersion)
	if !ok {
		return false
	}
	fixed, known := cgoFixedPatchByMinor[minor]
	if !known {
		// A line later than 1.27 (or a hypothetical newer major) inherits the
		// fixes; a line before 1.26 predates them.
		return minor > 27
	}
	// A release candidate of the fixing patch or later already contains the
	// fixes, so the pre-release suffix does not demote it.
	return patch >= fixed
}

// parseGoMinorPatch reads "go1.27.4", "go1.28rc1" or "go1.26.11rc2" into its
// minor and patch numbers. Development builds report "devel ..." and parse to
// not-ok.
func parseGoMinorPatch(goVersion string) (minor, patch int, ok bool) {
	rest, found := strings.CutPrefix(goVersion, "go1.")
	if !found {
		return 0, 0, false
	}
	if rest == "" || !isDigit(rest[0]) {
		return 0, 0, false
	}
	i := 0
	for i < len(rest) && isDigit(rest[i]) {
		i++
	}
	minor, err := strconv.Atoi(rest[:i])
	if err != nil {
		return 0, 0, false
	}
	rest = rest[i:]
	// Everything after the minor that is not ".<digits>" (rc, beta, devel
	// suffixes) leaves patch at zero.
	if len(rest) > 1 && rest[0] == '.' && isDigit(rest[1]) {
		i = 1
		for i < len(rest) && isDigit(rest[i]) {
			i++
		}
		patch, err = strconv.Atoi(rest[1:i])
		if err != nil {
			return 0, 0, false
		}
	}
	return minor, patch, true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// cgoEnvOverrideNames lists the names, never the values, of the CGO_*_ALLOW and
// CGO_*FLAGS variables set in the load environment. Each of them widens or
// re-opens what the toolchain refuses for EVERY package in the build, so a
// consumer needs to know they were present even though their contents are not
// its business.
func cgoEnvOverrideNames(environ []string) []string {
	var names []string
	for _, entry := range environ {
		key, value, _ := strings.Cut(entry, "=")
		if value == "" {
			continue
		}
		if strings.HasPrefix(key, "CGO_") && (strings.HasSuffix(key, "_ALLOW") || strings.HasSuffix(key, "FLAGS")) {
			names = append(names, key)
		}
	}
	sort.Strings(names)
	return names
}
