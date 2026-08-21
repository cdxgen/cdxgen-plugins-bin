package analyzer

import (
	"fmt"
	"go/version"
	"runtime"
	"sort"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// languageVersion returns the newest Go language version this build of golem can
// type-check, as a "go1.N" string.
//
// It is the version of the toolchain that compiled golem, not the `go` directive
// in golem's own go.mod and not the `go` command on PATH. go/types applies the
// language rules of the release it was compiled from, so a golem built by Go
// 1.26 rejects Go 1.27 syntax however new the toolchain that loads the packages
// is. Nothing else in the report says this, and it is the single fact that
// explains an otherwise inexplicable empty result.
func languageVersion() string {
	if v := version.Lang(runtime.Version()); v != "" {
		return v
	}
	// A development or vendor build whose runtime.Version() is not a release
	// string. Nothing useful can be said about the ceiling.
	return ""
}

// languageVersionDiagnostics reports every analyzed module whose `go` directive
// asks for a language version this build cannot type-check.
//
// Without this the failure is silent in the way that matters: go/packages
// reports "package requires newer Go version", the type checker then reports a
// cascade of consequences ("undefined: U", "unknown field Cmd in struct literal
// of type Req") that read like defects in the code under analysis, and the
// call graph and data flow come back empty with no explanation. One diagnostic
// naming both versions and the remedy is the difference between a report a
// reader can act on and one that looks like a clean bill of health.
func languageVersionDiagnostics(modules []model.Module) []model.Diagnostic {
	ceiling := languageVersion()
	if ceiling == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []model.Diagnostic
	for _, mod := range modules {
		declared := version.Lang("go" + mod.GoVersion)
		if declared == "" || seen[declared] {
			continue
		}
		if version.Compare(declared, ceiling) <= 0 {
			continue
		}
		seen[declared] = true
		out = append(out, model.Diagnostic{
			Kind: "go-version",
			Message: fmt.Sprintf(
				"module %s declares %s but this golem was built with %s, which cannot type-check it; "+
					"declarations, call graph and data flow for it will be incomplete or empty. "+
					"Rebuild golem with %s or newer.",
				mod.Path, declared, ceiling, declared),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Message < out[j].Message })
	return out
}
