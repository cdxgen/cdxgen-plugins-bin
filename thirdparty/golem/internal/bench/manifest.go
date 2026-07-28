package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Manifest lists the fixtures the benchmark harness runs.
type Manifest struct {
	Version  string    `json:"version"`
	Fixtures []Fixture `json:"fixtures"`
}

// Fixture is one benchmark subject: either a directory inside the corpus or a
// pinned upstream repository.
type Fixture struct {
	Name string `json:"name"`
	// Type is "corpus" (a directory under testdata/corpus) or "remote".
	Type string `json:"type"`
	// Tier gates how much work a run does: "quick" fixtures are cheap enough
	// for every commit, "full" fixtures are the medium and large repositories.
	Tier string `json:"tier,omitempty"`
	Dir  string `json:"dir,omitempty"`
	// Repo and Commit pin a remote fixture. Commit must be a full SHA: a
	// benchmark that tracks a moving branch cannot be a baseline.
	Repo   string `json:"repo,omitempty"`
	Commit string `json:"commit,omitempty"`
	// Subdir narrows analysis to a directory inside the repository.
	Subdir string `json:"subdir,omitempty"`
	// Golden marks fixtures whose digests are committed and verified by
	// "golem golden".
	Golden bool `json:"golden,omitempty"`
	// PartialGroundTruth marks a fixture whose annotations cover only some of
	// its real flows — a deliberate vulnerability benchmark, where the declared
	// vulnerabilities are ground truth for recall but the rest of the program
	// is ordinary code nobody has classified. Precision is not computed from an
	// unannotated flow on such a fixture. See corpus.EvaluateWithGroundTruth.
	PartialGroundTruth bool `json:"partialGroundTruth,omitempty"`
	// Notes records why the fixture is interesting.
	Notes  string       `json:"notes,omitempty"`
	Matrix []MatrixSlot `json:"matrix,omitempty"`
}

// MatrixSlot is one analyzer configuration to measure.
type MatrixSlot struct {
	Label       string `json:"label"`
	CallGraph   string `json:"callgraph"`
	DataFlow    string `json:"dataflow"`
	DFCallGraph string `json:"dataflowCallgraph,omitempty"`
	// Roots selects call-graph entry points, matching --roots. Empty uses the
	// analyzer default of main/init plus framework registrations.
	Roots []string `json:"roots,omitempty"`
	// IncludeStdlib and DataFlowMax override the defaults for this slot.
	IncludeStdlib bool `json:"includeStdlib,omitempty"`
	DataFlowMax   int  `json:"dataflowMax,omitempty"`
	// TaintEngine selects the taint engine: "legacy" (default) or "seam".
	TaintEngine string `json:"taintEngine,omitempty"`
	// TimeoutSeconds bounds a single slot; 0 means the harness default.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// Tiers, in increasing cost order.
const (
	TierQuick = "quick"
	TierFull  = "full"
)

// DefaultMatrix measures both the shipping default (security mode, whose
// dependency handling is the thing most likely to regress) and the widest
// setting, so a fix that only works under --dataflow all is visible as such.
func DefaultMatrix() []MatrixSlot {
	return []MatrixSlot{
		{Label: "security", CallGraph: "rta", DataFlow: "security", DFCallGraph: "rta"},
		{Label: "all", CallGraph: "rta", DataFlow: "all", DFCallGraph: "rta"},
	}
}

// LoadManifest reads and validates a manifest.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", path, err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", path, err)
	}
	return &manifest, nil
}

// Validate rejects manifests that cannot produce a stable baseline.
func (m *Manifest) Validate() error {
	if len(m.Fixtures) == 0 {
		return fmt.Errorf("manifest lists no fixtures")
	}
	seen := map[string]bool{}
	for _, fixture := range m.Fixtures {
		if fixture.Name == "" {
			return fmt.Errorf("fixture with empty name")
		}
		if seen[fixture.Name] {
			return fmt.Errorf("duplicate fixture %q", fixture.Name)
		}
		seen[fixture.Name] = true
		switch fixture.Type {
		case "corpus":
		case "remote":
			if fixture.Repo == "" {
				return fmt.Errorf("fixture %q: remote fixtures need repo", fixture.Name)
			}
			if len(fixture.Commit) != 40 {
				return fmt.Errorf("fixture %q: commit must be a full 40-character SHA, got %q", fixture.Name, fixture.Commit)
			}
		default:
			return fmt.Errorf("fixture %q: unknown type %q", fixture.Name, fixture.Type)
		}
		switch fixture.Tier {
		case "", TierQuick, TierFull:
		default:
			return fmt.Errorf("fixture %q: unknown tier %q", fixture.Name, fixture.Tier)
		}
		for _, slot := range fixture.Matrix {
			if slot.Label == "" {
				return fmt.Errorf("fixture %q: matrix slot with empty label", fixture.Name)
			}
		}
	}
	return nil
}

// Select returns the fixtures in the requested tier. TierFull includes
// everything; TierQuick includes only quick fixtures.
func (m *Manifest) Select(tier string, only []string) []Fixture {
	nameFilter := map[string]bool{}
	for _, name := range only {
		if name = strings.TrimSpace(name); name != "" {
			nameFilter[name] = true
		}
	}
	var out []Fixture
	for _, fixture := range m.Fixtures {
		if len(nameFilter) > 0 && !nameFilter[fixture.Name] {
			continue
		}
		fixtureTier := fixture.Tier
		if fixtureTier == "" {
			fixtureTier = TierQuick
		}
		if tier == TierQuick && fixtureTier != TierQuick {
			continue
		}
		if len(fixture.Matrix) == 0 {
			fixture.Matrix = DefaultMatrix()
		}
		out = append(out, fixture)
	}
	return out
}

// CacheDir resolves the fixture cache directory, preferring an explicit
// override, then XDG_CACHE_HOME, then the user cache directory.
func CacheDir(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "golem-bench"), nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving cache dir: %w", err)
	}
	return filepath.Join(dir, "golem-bench"), nil
}

// errFixtureUnavailable marks a fixture that could not be materialized for
// environmental reasons: the run skips it instead of failing.
type errFixtureUnavailable struct{ reason string }

func (e errFixtureUnavailable) Error() string { return e.reason }

// Materialize returns the directory to analyze for a fixture, fetching a pinned
// remote fixture into the cache if necessary.
//
// The fetch deliberately avoids "clone --depth=1 && checkout <sha>", which
// fails whenever the pin is not the branch tip: a shallow clone contains only
// one commit. Fetching the SHA directly keeps the download small and the pin
// exact.
func (f Fixture) Materialize(corpusRoot, cacheDir string) (string, error) {
	if f.Type == "corpus" {
		dir := f.Dir
		if dir == "" {
			dir = filepath.Join(corpusRoot, f.Name)
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("corpus fixture %s: %w", f.Name, err)
		}
		return abs, nil
	}

	git, err := exec.LookPath("git")
	if err != nil {
		return "", errFixtureUnavailable{"git is not on PATH"}
	}
	repoDir := filepath.Join(cacheDir, f.Name)
	if current, err := os.ReadFile(filepath.Join(repoDir, ".golem-commit")); err == nil && strings.TrimSpace(string(current)) == f.Commit {
		return f.analyzeDir(repoDir), nil
	}
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		return "", err
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"remote", "remove", "origin"},
		{"remote", "add", "origin", f.Repo},
		{"fetch", "--quiet", "--depth=1", "origin", f.Commit},
		{"checkout", "--quiet", "--force", "FETCH_HEAD"},
	} {
		cmd := exec.Command(git, append([]string{"-C", repoDir}, args...)...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			// Removing a remote that does not exist is expected on a fresh clone.
			if args[0] == "remote" && args[1] == "remove" {
				continue
			}
			return "", errFixtureUnavailable{fmt.Sprintf("git %s in %s: %v: %s", strings.Join(args, " "), repoDir, err, strings.TrimSpace(stderr.String()))}
		}
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".golem-commit"), []byte(f.Commit), 0o644); err != nil {
		return "", err
	}
	return f.analyzeDir(repoDir), nil
}

func (f Fixture) analyzeDir(repoDir string) string {
	if f.Subdir != "" {
		return filepath.Join(repoDir, f.Subdir)
	}
	return repoDir
}

// SortResults orders results deterministically by fixture then configuration.
func SortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		return results[i].Config < results[j].Config
	})
}
