package analyzer

import (
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// TestBuiltinPatternsMatchRealSymbols reports built-in data-flow patterns that
// match no symbol anywhere in the loaded program.
//
// A pattern is matched as a substring of the SSA symbol text, and the two are
// written in different notations: a pattern says database/sql.(*DB).Query while
// the symbol reads (*database/sql.DB).Query. A pattern that can never match is
// not a spare — it is a whole class of finding that silently does not exist.
func TestBuiltinPatternsMatchRealSymbols(t *testing.T) {
	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Dir: "../../testdata/corpus/sqli-concatenated"}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Skipf("cannot load fixture: %v", err)
	}
	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	symbols := map[string]bool{}
	for fn := range ssautil.AllFunctions(prog) {
		symbols[fn.String()] = true
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			symbols[fn.Pkg.Pkg.Path()+"."+fn.Name()] = true
		}
	}

	set := builtinDataFlowPatterns(nil)
	regexps, _ := compileDataFlowRegexps(set)
	var dead []string
	for _, p := range allDataFlowPatterns(set) {
		if p.Kind != "function" && p.Kind != "method" && p.Kind != "symbol" {
			continue
		}
		matched := false
		for symbol := range symbols {
			if patternMatches(symbol, p, regexps) {
				matched = true
				break
			}
		}
		if !matched {
			dead = append(dead, p.Target+" "+p.Category+" "+p.Pattern)
		}
	}
	sort.Strings(dead)
	t.Logf("%d of the built-in function patterns match no symbol in a program that imports database/sql, net/http and os/exec:\n  %s",
		len(dead), strings.Join(dead, "\n  "))
}
