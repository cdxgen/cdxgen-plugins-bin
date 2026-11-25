package analyzer

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// caseImportsC reports whether a fixture directory holds a .go file that
// imports "C". Corpus and parity cases that do are loaded with cgo through the
// parallel-test option: an annotation inside the analysed tree must never be
// able to turn cgo on, so the driver, which stands in for the analyst, asks.
func caseImportsC(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || found {
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), `import "C"`) {
			found = true
		}
		return nil
	})
	return found
}

// writeCCWrapper installs a CC that records every invocation before handing
// the arguments to the real compiler, and returns the invocation log's path.
// A test then asserts how often the C compiler ran and with which flags. The
// wrapper is a shell script, so Windows hosts skip the tests that need it.
func writeCCWrapper(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the CC invocation wrapper is a shell script; Windows hosts skip the C-compiler-count assertions")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "cc-invocations.log")
	wrapper := filepath.Join(dir, "cc-wrapper.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CC_LOG\"\nexec \"${REAL_CC:-cc}\" \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatalf("writing the CC wrapper: %v", err)
	}
	t.Setenv("CC_LOG", log)
	t.Setenv("CC", wrapper)
	return log
}

// cCompilerAvailable reports whether a host C compiler exists, which the
// cgo-enabled runs need: the load has to actually translate the package.
func cCompilerAvailable() bool {
	for _, name := range []string{"cc", "gcc", "clang"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

// unsetenvCGOEnabled removes CGO_ENABLED for the duration of one test and
// restores whatever was there before. t.Setenv cannot express "absent", and
// absent is the state the default-load tests are about.
func unsetenvCGOEnabled(t *testing.T) {
	t.Helper()
	previous, had := os.LookupEnv("CGO_ENABLED")
	if err := os.Unsetenv("CGO_ENABLED"); err != nil {
		t.Fatalf("unset CGO_ENABLED: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("CGO_ENABLED", previous)
		} else {
			_ = os.Unsetenv("CGO_ENABLED")
		}
	})
}

// A default load must not run the C compiler at all: no #cgo directive in the
// analysed tree may reach the host toolchain unless the analyst exported
// CGO_ENABLED. The package still appears, with its directive, marked as seen
// textually.
func TestCgoDefaultLoadRunsNoCCompiler(t *testing.T) {
	log := writeCCWrapper(t)
	unsetenvCGOEnabled(t)
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "corpus", "cgo-benign"), IncludeLocal: true, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("analyze cgo-benign with the default load: %v", err)
	}
	if invocations := lineCount(t, log); invocations != 0 {
		t.Fatalf("the default load ran the C compiler %d times; without CGO_ENABLED in the environment it must run it 0 times", invocations)
	}
	if report.Cgo == nil {
		t.Fatal("the report has no cgo object")
	}
	if report.Cgo.Mode != "disabled" {
		t.Errorf("cgo mode = %q, want disabled", report.Cgo.Mode)
	}
	if report.Cgo.PackageCount != 1 || report.Cgo.UnloadedPackageCount != 1 {
		t.Errorf("cgo packages = %d (unloaded %d), want 1 package seen only textually", report.Cgo.PackageCount, report.Cgo.UnloadedPackageCount)
	}
	directive := findDirective(report, "cgo", "CFLAGS")
	if directive == nil {
		t.Fatal("the #cgo CFLAGS line of the module's own source is not in the report")
	}
	if got := strings.Join(directive.Flags, ","); got != "-DPROBE_MARKER" {
		t.Errorf("directive flags = %q, want the macro name -DPROBE_MARKER and no value", got)
	}
	if directive.Text != "" {
		t.Errorf("a cgo directive carries raw text %q; only names and categories belong in a report", directive.Text)
	}
	if len(directive.Categories) != 0 {
		t.Errorf("benign directive categorised as %v; -DPROBE_MARKER names a macro and carries no risk", directive.Categories)
	}
	signal := findSignal(report, "native-interop")
	if signal == nil {
		t.Error("no native-interop signal for the textually-read cgo file; the report must still say the package crosses into C")
	} else if signal.Confidence != "textual" {
		t.Errorf("signal confidence = %q, want textual", signal.Confidence)
	}
}

// With the analyst's explicit choice (CGO_ENABLED=1 in the environment) the
// package loads through cgo as it always did, and the compiler runs with the
// package's flags.
func TestCgoEnabledLoadCompilesPreamble(t *testing.T) {
	if !cCompilerAvailable() {
		t.Skip("no C compiler on PATH; the cgo-enabled load cannot translate the package")
	}
	log := writeCCWrapper(t)
	t.Setenv("CGO_ENABLED", "1")
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "corpus", "cgo-benign"), IncludeLocal: true, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("analyze cgo-benign with CGO_ENABLED=1: %v", err)
	}
	if invocations := lineCount(t, log); invocations == 0 {
		t.Fatal("CGO_ENABLED=1 compiled nothing; the cgo load must invoke the C compiler")
	}
	if !strings.Contains(fileContents(t, log), "-DPROBE_MARKER=1") {
		t.Errorf("the compiler ran without the package's flag; invocations: %s", fileContents(t, log))
	}
	if report.Cgo == nil || report.Cgo.Mode != "enabled" {
		t.Fatalf("cgo mode = %v, want enabled", report.Cgo)
	}
	found := false
	for _, pkg := range report.Packages {
		if pkg.PackagePath == "example.com/golem/corpus/cgo-benign" {
			found = true
		}
	}
	if !found {
		t.Error("the cgo package did not load with CGO_ENABLED=1")
	}
	if report.Cgo.UnloadedPackageCount != 0 {
		t.Errorf("unloaded cgo packages = %d, want 0 with cgo on", report.Cgo.UnloadedPackageCount)
	}
	// The directive still names the macro, not the value, and the report
	// carries no build-cache path.
	assertNoCachePaths(t, report)
}

// Every refused-flag family is listed whatever the toolchain does with it:
// with cgo off nothing compiles, and with cgo on (a patched toolchain refuses
// these) the load errors are recorded and the analysis still exits cleanly.
func TestCgoRefusedFlagFamiliesListed(t *testing.T) {
	run := func(t *testing.T, cgo string) *model.Report {
		t.Helper()
		options := Options{Dir: filepath.Join("..", "..", "testdata", "cgo-risk"), IncludeLocal: true, ToolVersion: "test"}
		if cgo != "" {
			options.CgoEnabled = cgo
		} else {
			unsetenvCGOEnabled(t)
		}
		report, err := Analyze(options)
		if err != nil {
			t.Fatalf("analyze cgo-risk (cgo=%q): %v", cgo, err)
		}
		return report
	}
	for _, tc := range []struct {
		name string
		cgo  string
	}{{"disabled", ""}, {"enabled", "1"}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cgo == "1" && !cCompilerAvailable() {
				t.Skip("no C compiler on PATH; the cgo-enabled load cannot run")
			}
			report := run(t, tc.cgo)
			if report.Cgo == nil {
				t.Fatal("the report has no cgo object")
			}
			wantFlags := []string{"--sysroot", "-target", "-gnatO", "-gen-cdb-fragment-path", "-isysroot", "-Wl,-syslibroot", "-L", "-x", "-lazy_library", "-lto_library", "-load_hidden", "-library-path", "-Wl,-rpath", "-library-path", "--with-path", "--personality"}
			for _, flag := range wantFlags {
				if !containsString(report.Cgo.RiskyFlags, flag) {
					t.Errorf("risky flags missing %q; got %v", flag, report.Cgo.RiskyFlags)
				}
			}
			if !containsString(report.Cgo.RiskCategories, "refused-by-go1.27.4") {
				t.Errorf("risk categories = %v, want refused-by-go1.27.4 among them", report.Cgo.RiskCategories)
			}
			if !containsString(report.Cgo.RiskCategories, "path-escape") {
				t.Errorf("risk categories = %v, want path-escape among them", report.Cgo.RiskCategories)
			}
			if tc.cgo == "1" {
				// The patched toolchain refuses the families; the load
				// records those refusals and the report still lists them.
				errors := 0
				for _, pkg := range report.Packages {
					errors += len(pkg.Diagnostics)
				}
				errors += len(report.Diagnostics)
				if errors == 0 {
					t.Error("the cgo load of refused flags recorded no errors; a patched toolchain refuses them")
				}
			}
			assertNoCachePaths(t, report)
			assertNoRawDirectiveText(t, report)
		})
	}
}

// A .syso with random bytes and one with a valid ELF header are classified,
// and the invalid one is counted per module and in total.
func TestCgoSysoClassification(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "cgo-syso"), NoRecurse: false, IncludeLocal: true, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("analyze cgo-syso: %v", err)
	}
	if report.Cgo == nil {
		t.Fatal("the report has no cgo object")
	}
	if report.Cgo.SysoCount != 2 {
		t.Errorf("syso count = %d, want 2", report.Cgo.SysoCount)
	}
	if report.Cgo.SysoInvalidCount != 1 {
		t.Errorf("invalid syso count = %d, want 1", report.Cgo.SysoInvalidCount)
	}
	if !containsString(report.Cgo.RiskCategories, "invalid-object") {
		t.Errorf("risk categories = %v, want invalid-object among them", report.Cgo.RiskCategories)
	}
	// Both files appear as native artifacts; the invalid one says so.
	sysoArtifacts := 0
	invalid := ""
	for _, artifact := range report.NativeArtifacts {
		if artifact.Extension == ".syso" {
			sysoArtifacts++
			if artifact.Properties["objectHeaderValid"] == "false" {
				invalid = artifact.Path
			}
		}
	}
	if sysoArtifacts != 2 {
		t.Errorf("syso native artifacts = %d, want 2", sysoArtifacts)
	}
	if !strings.HasSuffix(invalid, "bad.syso") {
		t.Errorf("the invalid .syso is not marked; marked path = %q", invalid)
	}
}

// //go:cgo_* directives in hand-written source are a finding by themselves,
// and the comma, DLL-path and escaped-quote forms are outright refused.
func TestCgoCompilerDirectivesInSource(t *testing.T) {
	unsetenvCGOEnabled(t)
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "cgo-directive-source"), IncludeLocal: true, ToolVersion: "test"})
	if err != nil {
		t.Fatalf("analyze cgo-directive-source: %v", err)
	}
	if report.Cgo == nil {
		t.Fatal("the report has no cgo object")
	}
	if !containsString(report.Cgo.RiskCategories, "cgo-directive-in-source") {
		t.Errorf("risk categories = %v, want cgo-directive-in-source among them", report.Cgo.RiskCategories)
	}
	for _, name := range []string{"cgo_ldflag", "cgo_import_dynamic", "cgo_export_inline"} {
		if !containsString(report.Cgo.RiskyFlags, name) {
			t.Errorf("risky flags missing %q; got %v", name, report.Cgo.RiskyFlags)
		}
	}
	if !containsString(report.Cgo.RiskCategories, "refused-by-go1.27.4") {
		t.Errorf("the comma and DLL-path forms are refused by the patched toolchain; categories = %v", report.Cgo.RiskCategories)
	}
	assertNoRawDirectiveText(t, report)
}

// A // golem:env annotation may not set CGO_ENABLED or any CGO_* key: the
// analysed repository must never be able to turn cgo on or choose its flags.
func TestCgoEnvAnnotationRejected(t *testing.T) {
	dir := t.TempDir()
	source := "package annotation\n\n// golem:env CGO_ENABLED=1\nfunc F() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(source), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	_, err := corpus.ParseEnvSettings(dir)
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("ParseEnvSettings accepted CGO_ENABLED=1: err = %v, want the allowlist rejection", err)
	}
	for _, pair := range []string{"CGO_CFLAGS=-DFOO", "CGO_LDFLAGS_ALLOW=.*", "CGO_ENABLED=0"} {
		source = "package annotation\n\n// golem:env " + pair + "\nfunc F() {}\n"
		if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(source), 0o644); err != nil {
			t.Fatalf("writing the fixture: %v", err)
		}
		if _, err := corpus.ParseEnvSettings(dir); err == nil {
			t.Errorf("ParseEnvSettings accepted %s", pair)
		}
	}
}

// The build cache never appears in a report: cgo's generated files are
// derived output, and their absolute paths would leak the analyst's home
// directory into an artifact that travels further than the terminal. The
// module cache also lives under the home directory, and dependency source
// there IS reportable, so it is carved out before the check.
func assertNoCachePaths(t *testing.T, report *model.Report) {
	t.Helper()
	if report.Cgo == nil {
		t.Fatal("the report has no cgo object")
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshalling the report: %v", err)
	}
	text := string(data)
	gocache, err := goEnv("GOCACHE")
	if err == nil && gocache != "" && strings.Contains(text, filepath.Clean(gocache)) {
		t.Errorf("the report contains a build-cache path (%s)", filepath.Clean(gocache))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		modcache, _ := goEnv("GOMODCACHE")
		remainder := strings.ReplaceAll(text, modcache, "")
		remainder = strings.ReplaceAll(remainder, filepath.Clean(report.Options.Directory), "")
		if strings.Contains(remainder, home) {
			t.Error("the report contains a path under the analyst's home directory that is neither module-cache source nor the analysed directory")
		}
	}
}

// A cgo or go-cgo directive carries names and categories, never the raw line:
// the raw value is where paths and secrets live.
func assertNoRawDirectiveText(t *testing.T, report *model.Report) {
	t.Helper()
	for _, directive := range report.BuildDirectives {
		if directive.Kind != "cgo" && directive.Kind != "go-cgo" {
			continue
		}
		if directive.Text != "" {
			t.Errorf("a %s directive carries raw text %q", directive.Kind, directive.Text)
		}
		for _, flag := range directive.Flags {
			if strings.ContainsAny(flag, `/\ `) && !strings.HasPrefix(flag, "-Wl,") {
				t.Errorf("directive flag %q looks like a path or a value rather than a name", flag)
			}
			if strings.Contains(flag, "PROBE_MARKER=1") {
				t.Errorf("directive flag %q carries the macro's value", flag)
			}
		}
		if directive.Properties != nil {
			t.Errorf("a %s directive carries properties %v; the variable, constraint, flags and categories are the report", directive.Kind, directive.Properties)
		}
	}
}

func findDirective(report *model.Report, kind, variable string) *model.BuildDirective {
	for i := range report.BuildDirectives {
		d := &report.BuildDirectives[i]
		if d.Kind == kind && d.Variable == variable {
			return d
		}
	}
	return nil
}

func findSignal(report *model.Report, category string) *model.SecuritySignal {
	for i := range report.SecuritySignals {
		s := &report.SecuritySignals[i]
		if s.Category == category {
			return s
		}
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func lineCount(t *testing.T, path string) int {
	t.Helper()
	return strings.Count(fileContents(t, path), "\n")
}

func fileContents(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

func goEnv(key string) (string, error) {
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Merging several child reports must keep every per-package update, including
// ones that arrive after earlier appends have moved the packages slice.
func TestMergeCgoEvidenceKeepsEveryPackageUpdate(t *testing.T) {
	dst := &model.CgoEvidence{Packages: []model.CgoPackageSummary{{PackagePath: "example.com/a", FileCount: 1}}}
	first := &model.CgoEvidence{Packages: []model.CgoPackageSummary{
		{PackagePath: "example.com/b", FileCount: 1},
		{PackagePath: "example.com/c", FileCount: 1},
		{PackagePath: "example.com/d", FileCount: 1},
	}}
	// A new package first, so the append can move the slice before the
	// updates to packages already present.
	second := &model.CgoEvidence{Packages: []model.CgoPackageSummary{
		{PackagePath: "example.com/e", FileCount: 1},
		{PackagePath: "example.com/a", FileCount: 2},
		{PackagePath: "example.com/d", FileCount: 3, RiskyFlags: []string{"--sysroot"}},
	}}
	merged := mergeCgoEvidence(mergeCgoEvidence(dst, first), second)
	counts := map[string]int{}
	for _, summary := range merged.Packages {
		counts[summary.PackagePath] = summary.FileCount
		if summary.PackagePath == "example.com/d" && strings.Join(summary.RiskyFlags, ",") != "--sysroot" {
			t.Errorf("example.com/d lost its risky flags: %v", summary.RiskyFlags)
		}
	}
	want := map[string]int{"example.com/a": 3, "example.com/b": 1, "example.com/c": 1, "example.com/d": 4, "example.com/e": 1}
	for path, count := range want {
		if counts[path] != count {
			t.Errorf("%s file count = %d, want %d (all counts %v)", path, counts[path], count, counts)
		}
	}
}

// A nested module that the load did not include is left to its own run: the
// walk neither reads it nor reports its packages as unloaded.
func TestCgoWalkSkipsNestedModules(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/outer\n\ngo 1.26\n")
	write("main.go", "package main\n\nfunc main() {}\n")
	write("inner/go.mod", "module example.com/inner\n\ngo 1.26\n")
	write("inner/c.go", "package inner\n\n// #cgo CFLAGS: --sysroot=/tmp\nimport \"C\"\n")
	write("vendor/example.com/dep/go.mod", "module example.com/dep\n\ngo 1.26\n")
	write("vendor/example.com/dep/c.go", "package dep\n\n// #cgo LDFLAGS: -lm\nimport \"C\"\n")
	a := &Analyzer{options: Options{Dir: root}}
	collected := a.collectCgoEvidence(nil, root)
	for path := range collected.files {
		if strings.Contains(filepath.ToSlash(path), "/inner/") {
			t.Errorf("the walk read %s from a nested module the load did not include", path)
		}
	}
	vendored := false
	for path := range collected.files {
		if strings.Contains(filepath.ToSlash(path), "/vendor/") {
			vendored = true
		}
	}
	if !vendored {
		t.Error("a vendored dependency's cgo file was skipped; vendored code is part of the build even when a go.mod was copied into it")
	}
}
