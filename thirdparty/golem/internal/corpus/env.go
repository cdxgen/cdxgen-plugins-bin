package corpus

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// AllowedEnvKeys are the environment keys a build-shape override may set, in
// any context: the // golem:env corpus directive, analyzer Options.Env, or the
// --goexperiment flag. The list is the build shape and nothing else.
//
// GOFLAGS is deliberately absent. It accepts -toolexec, which substitutes
// programs the go command runs, so a value that arrived from a corpus
// annotation — or from a consumer's option, which annotations must never be
// able to influence — would become command execution inside the analyst's
// environment. The same reasoning rules out GOENV (which would redirect the
// toolchain's whole configuration), GOCC, and every key that is not a pure
// target description.
var AllowedEnvKeys = []string{"GOEXPERIMENT", "GOOS", "GOARCH", "GOAMD64", "GOARM64"}

// ValidateEnvPair checks one KEY=VALUE build-shape override against the
// allowlist. Everything the loaders do with these pairs goes through here, so
// a key cannot be slipped in through one door when another door rejects it.
func ValidateEnvPair(key, value string) error {
	for _, allowed := range AllowedEnvKeys {
		if key == allowed {
			return nil
		}
	}
	return fmt.Errorf("environment key %q is not allowed (want one of %s); arbitrary keys such as GOFLAGS would let an annotation or an option run commands in the toolchain", key, strings.Join(AllowedEnvKeys, ", "))
}

// ParseEnvSettings walks dir like Parse and returns the KEY=VALUE pairs every
// // golem:env directive requests, in file order, deduplicated on the key with
// the last declaration winning.
//
// A corpus case is a whole module, and the directive belongs to the case
// rather than to a line of code: GOEXPERIMENT=simd decides whether the
// package loads at all, and GOARCH=amd64 lets an amd64-only fixture load for
// its target architecture whatever the CI host is. Cases run in parallel in
// one process, so the settings travel through the load configuration (the
// analyzer's Env option) and never through the process environment.
func ParseEnvSettings(dir string) ([]string, error) {
	files, err := goFilesUnder(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var out []string
	seen := map[string]int{}
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		for _, group := range file.Comments {
			for _, comment := range group.List {
				for _, line := range commentLines(comment.Text) {
					text, ok := trimAnnotationPrefix(line)
					if !ok || !isEnvDirective(text) {
						continue
					}
					for _, field := range strings.Fields(strings.TrimPrefix(text, "env")) {
						key, value, ok := strings.Cut(field, "=")
						if !ok || key == "" || strings.ContainsAny(key, " \t") {
							return nil, fmt.Errorf("%s:%d: malformed golem:env entry %q: want KEY=VALUE", path, fset.Position(comment.Pos()).Line, field)
						}
						if err := ValidateEnvPair(key, value); err != nil {
							return nil, fmt.Errorf("%s:%d: %w", path, fset.Position(comment.Pos()).Line, err)
						}
						if i, dup := seen[key]; dup {
							out[i] = key + "=" + value
							continue
						}
						seen[key] = len(out)
						out = append(out, key+"="+value)
					}
				}
			}
		}
	}
	return out, nil
}

// isEnvDirective reports whether the text after the "golem:" prefix is an env
// directive: `golem:env` alone or `golem:env KEY=VALUE …`.
func isEnvDirective(text string) bool {
	return text == "env" || strings.HasPrefix(text, "env ") || strings.HasPrefix(text, "env\t")
}

// goFilesUnder returns the .go files under dir, sorted, skipping vendor and
// dot directories the way Parse does.
func goFilesUnder(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if name := d.Name(); path != dir && (name == "vendor" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}
