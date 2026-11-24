package analyzer

import (
	"go/ast"
	"go/token"
	"os"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// Pointer checking is a runtime GODEBUG knob the process reads at start-up:
// it is not in internal/godebugs/table.go, so //go:debug and a go.mod godebug
// line cannot set it, and the only way off is the GODEBUG environment
// variable. This file finds, by name and category, the places that turn it
// off where golem can see them: the load environment, and the build and
// runtime configuration files of a module that contains cgo. A GODEBUG line
// in a pure-Go module is not a finding.
//
// The report carries the file, the line and the kind of configuration, never
// the value and never any other content of the file.

// cgoGocheckHit is one location that disables cgo pointer checking.
type cgoGocheckHit struct {
	path   string
	line   int
	source string // dockerfile, yaml, makefile, shell, dotenv or go-setenv
}

// gocheckConfigName reports whether a file name is one of the configuration
// files the scan reads. The list is the one the analysis already walks, plus
// the deployment files that carry environment settings.
func gocheckConfigName(name string) string {
	switch {
	case strings.HasPrefix(name, "Dockerfile"), strings.HasPrefix(name, "Containerfile"):
		return "dockerfile"
	case strings.HasSuffix(name, ".yaml"), strings.HasSuffix(name, ".yml"):
		return "yaml"
	case name == "Makefile", strings.HasPrefix(name, "Makefile."), strings.HasSuffix(name, ".mk"):
		return "makefile"
	case strings.HasPrefix(name, ".env"):
		return "dotenv"
	case strings.HasSuffix(name, ".sh"):
		return "shell"
	}
	return ""
}

// cgoGocheckMaxScan bounds one configuration file's read: environment files
// are small, and anything past this is not worth blocking the walk for.
const cgoGocheckMaxScan = 1 << 20

// scanGocheckConfig reads one configuration file and returns the lines that
// set cgocheck=0 inside a GODEBUG value, if any.
func scanGocheckConfig(path, kind string) []cgoGocheckHit {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > cgoGocheckMaxScan {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var hits []cgoGocheckHit
	switch kind {
	case "yaml":
		// A Kubernetes env entry splits the name and the value across lines:
		//   env:
		//     - name: GODEBUG
		//       value: "cgocheck=0"
		// The hit is reported at the value line, which is where the setting
		// lives.
		for i, line := range lines {
			if !strings.Contains(line, "GODEBUG") || !strings.Contains(line, "name:") {
				continue
			}
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if gocheckValueDisables(lines[j]) {
					hits = append(hits, cgoGocheckHit{path: path, line: j + 1, source: "yaml"})
					break
				}
			}
		}
	default:
		for i, line := range lines {
			if !gocheckLineDisables(line) {
				continue
			}
			hits = append(hits, cgoGocheckHit{path: path, line: i + 1, source: kind})
		}
	}
	return hits
}

// gocheckLineDisables reports whether one line assigns GODEBUG a value that
// contains cgocheck=0. The value may carry other knobs; only the cgocheck
// part decides.
func gocheckLineDisables(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	index := strings.Index(trimmed, "GODEBUG")
	if index < 0 {
		return false
	}
	rest := trimmed[index+len("GODEBUG"):]
	rest = strings.TrimLeft(rest, " \t=:") // ENV GODEBUG=..., export GODEBUG=..., GODEBUG := ...
	return gocheckValueDisables(rest)
}

// gocheckValueDisables reports whether a GODEBUG value string sets cgocheck
// to 0. The value is never reported; only the fact answers here.
func gocheckValueDisables(value string) bool {
	for {
		index := strings.Index(value, "cgocheck=")
		if index < 0 {
			return false
		}
		rest := value[index+len("cgocheck="):]
		digits := 0
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits++
		}
		if digits > 0 && rest[:digits] == "0" {
			return true
		}
		value = rest
	}
}

// scanGocheckSetenv finds os.Setenv calls that set GODEBUG with cgocheck=0
// in one parsed Go file. os.Setenv after start-up does not change the
// running process's cgo check, which the runtime reads once, so such a call
// signals intent rather than effect; the signal's property says so.
func scanGocheckSetenv(fset *token.FileSet, file *ast.File, path string) []cgoGocheckHit {
	var hits []cgoGocheckHit
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Setenv" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "os" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || strings.Trim(literal.Value, "`\"") != "GODEBUG" {
			return true
		}
		if arg, ok := call.Args[1].(*ast.BasicLit); ok && gocheckValueDisables(strings.Trim(arg.Value, "`\"")) {
			line := 0
			if position := fset.Position(call.Pos()); position.IsValid() {
				line = position.Line
			}
			hits = append(hits, cgoGocheckHit{path: path, line: line, source: "go-setenv"})
		}
		return true
	})
	return hits
}

// gocheckDisabledInEnv reports whether the given environment carries a
// GODEBUG that turns cgo checking off. Only the fact is reported.
func gocheckDisabledInEnv(environ []string) bool {
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == "GODEBUG" && gocheckValueDisables(value) {
			return true
		}
	}
	return false
}

// gocheck2EnabledInEnv reports whether the environment asks for the
// cgocheck2 experiment, which turns the stronger whole-program check on.
func gocheck2EnabledInEnv(experiment string, environ []string) bool {
	if strings.TrimSpace(experiment) == "cgocheck2" {
		return true
	}
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == "GOEXPERIMENT" && strings.TrimSpace(value) == "cgocheck2" {
			return true
		}
	}
	return false
}

// cgoReportCategories returns the cgocheck categories a cgo evidence object
// earned, for the report-level rollup.
func cgoReportCategories(evidence *model.CgoEvidence) []string {
	var categories []string
	if evidence.GocheckDisabled {
		categories = append(categories, CgoCategoryGocheckDisabled)
	}
	if evidence.Gocheck2Enabled {
		categories = append(categories, CgoCategoryGocheck2Enabled)
	}
	return categories
}
