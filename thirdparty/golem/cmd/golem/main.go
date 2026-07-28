package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/analyzer"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/exporter"
)

var version = "2.6.0"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "help", "--help", "-h":
			printUsage(stdout)
			return nil
		case "version", "--version":
			_, _ = fmt.Fprintf(stdout, "golem %s\n", version)
			return nil
		case "bench":
			return runBench(args[1:], stdout, stderr)
		case "golden":
			return runGolden(args[1:], stdout, stderr)
		case "analyze":
			args = args[1:]
		}
	}
	flags := flag.NewFlagSet("golem analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", ".", "Go module/workspace directory to analyze")
	noRecurse := flags.Bool("no-recurse", false, "disable recursive child go.mod discovery when --dir has no go.mod/go.work")
	patterns := flags.String("patterns", "./...", "comma-separated go/packages patterns")
	formatValue := flags.String("format", "json", "output format: json, graphml, or gexf")
	outFile := flags.String("out", "", "output file path; defaults to stdout")
	callgraph := flags.String("callgraph", "none", "call graph mode: none, static, cha, rta, vta, or auto")
	callgraphTimeout := flags.Duration("callgraph-timeout", 0, "call-graph construction timeout; 0 disables")
	rootsFlag := flags.String("roots", "", "comma-separated root set specifiers: main, init, exported, tests, handlers, all, symbol:<regex>")
	reachableSymbols := flags.String("reachable-symbols", "", "file containing symbol names to compute reachability paths for")
	maxPathsPerSymbol := flags.Int("max-paths-per-symbol", 3, "maximum witness paths per reachable symbol")
	dataflow := flags.String("dataflow", "none", "data-flow mode: none, security, crypto, or all")
	dataflowPatterns := flags.String("dataflow-patterns", "", "optional JSON file with data-flow sources, sinks, passthroughs, and sanitizers")
	dataflowPacks := flags.String("dataflow-pattern-packs", "all", "comma-separated data-flow pattern packs: all, base, http, frameworks, data, filesystem, process, crypto, native, config, cloud")
	dataflowCallgraph := flags.String("dataflow-callgraph", "static", "call graph mode for data-flow dynamic summary replay: none, static, cha, rta, or vta")
	dataflowMax := flags.Int("dataflow-max-slices", 1000, "maximum data-flow slices to emit")
	dataflowWorkers := flags.Int("dataflow-workers", 0, "data-flow worker count; 0 uses GOMAXPROCS/all available cores")
	dataflowLargeRepoFunctions := flags.Int("dataflow-large-repo-functions", 1000, "function count at which large-repo data-flow materialization safeguards apply; 0 disables")
	dataflowMaxFunctionInstructions := flags.Int("dataflow-max-function-instructions", 200, "skip per-function slice materialization above this SSA instruction count in large repos; 0 disables")
	dataflowMaxTraceNodes := flags.Int("dataflow-max-trace-nodes", 64, "maximum ordered node IDs retained per data-flow trace")
	dataflowMaxTraceEdges := flags.Int("dataflow-max-trace-edges", 128, "maximum ordered edge IDs retained per data-flow trace")
	dataflowSkipGenerated := flags.Bool("dataflow-skip-generated", false, "skip generated files during per-function data-flow slice materialization")
	dataflowSkipTests := flags.Bool("dataflow-skip-tests", false, "skip test/example/benchmark files during per-function data-flow slice materialization")
	taintEngine := flags.String("taint-engine", "seam", "taint engine: seam (default; structured models, SCC-condensation summaries) or legacy (escape hatch)")
	dependencyDetail := flags.String("dependency-detail", "collapse", "call-graph dependency detail: drop, collapse, or full")
	includeAllFlows := flags.Bool("include-all-flows", false, "retain external-only flows/call stacks fully rooted in Go module cache paths (alias for --dependency-detail=full)")
	dataflowGraphFormat := flags.String("dataflow-graph-format", "graphml", "data-flow graph sidecar format: graphml or gexf")
	dataflowGraphOut := flags.String("dataflow-graph-out", "", "optional data-flow graph sidecar output path")
	maxProcs := flags.Int("max-procs", 0, "maximum Go scheduler threads; 0 uses all available CPU cores")
	memoryLimit := flags.String("memory-limit", "", "optional Go soft memory limit such as 4GiB, 800MiB, or 2GB")
	progress := flags.Bool("progress", false, "emit coarse progress logs to stderr during large analyses")
	cpuProfile := flags.String("cpuprofile", "", "write a CPU profile to this path; for diagnosing analysis slowness on large repositories")
	progressInterval := flags.Duration("progress-interval", 5*time.Second, "minimum interval between progress logs")
	tags := flags.String("tags", "", "comma-separated Go build tags")
	tests := flags.Bool("tests", false, "include test variants")
	includeStdlib := flags.Bool("include-stdlib", false, "include standard library usages and call graph nodes")
	includeLocal := flags.Bool("include-local", true, "include current module usages and call graph nodes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	format, err := exporter.ParseFormat(*formatValue)
	if err != nil {
		return err
	}
	mode := strings.ToLower(strings.TrimSpace(*callgraph))
	if mode == "" {
		mode = "none"
	}
	if mode != "none" && mode != "static" && mode != "cha" && mode != "rta" && mode != "vta" && mode != "auto" {
		return fmt.Errorf("unsupported callgraph mode %q: expected none, static, cha, rta, vta, or auto", *callgraph)
	}
	dfMode := strings.ToLower(strings.TrimSpace(*dataflow))
	if dfMode == "" {
		dfMode = "none"
	}
	if dfMode != "none" && dfMode != "security" && dfMode != "crypto" && dfMode != "all" {
		return fmt.Errorf("unsupported dataflow mode %q: expected none, security, crypto, or all", *dataflow)
	}
	dfCallgraphMode := strings.ToLower(strings.TrimSpace(*dataflowCallgraph))
	if dfCallgraphMode == "" {
		dfCallgraphMode = "static"
	}
	if dfCallgraphMode != "none" && dfCallgraphMode != "static" && dfCallgraphMode != "cha" && dfCallgraphMode != "rta" && dfCallgraphMode != "vta" {
		return fmt.Errorf("unsupported dataflow-callgraph mode %q: expected none, static, cha, rta, or vta", *dataflowCallgraph)
	}
	if format != exporter.FormatJSON && mode == "none" {
		return errors.New("graphml and gexf exports require --callgraph static, cha, rta, or vta")
	}
	memoryLimitBytes, err := analyzer.ParseByteSize(*memoryLimit)
	if err != nil {
		return err
	}
	// Resolve dependency-detail with include-all-flows override.
	detail := *dependencyDetail
	if *includeAllFlows {
		detail = "full"
	}
	if detail != "drop" && detail != "collapse" && detail != "full" {
		return fmt.Errorf("unsupported dependency-detail %q: expected drop, collapse, or full", detail)
	}
	te := strings.ToLower(strings.TrimSpace(*taintEngine))
	if te != "legacy" && te != "seam" {
		return fmt.Errorf("unsupported taint-engine %q: expected legacy or seam", *taintEngine)
	}
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			return fmt.Errorf("create cpu profile: %w", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("start cpu profile: %w", err)
		}
		defer pprof.StopCPUProfile()
	}
	report, err := analyzer.Analyze(analyzer.Options{Dir: *dir, NoRecurse: *noRecurse, IncludeAllFlows: *includeAllFlows, Patterns: splitCSV(*patterns), BuildTags: splitCSV(*tags), Tests: *tests, IncludeStdlib: *includeStdlib, IncludeLocal: *includeLocal, CallGraphMode: mode, Roots: splitCSV(*rootsFlag), CallGraphTimeout: *callgraphTimeout, ReachableSymbols: *reachableSymbols, MaxPathsPerSymbol: *maxPathsPerSymbol, DataFlowMode: dfMode, DataFlowPacks: splitCSV(*dataflowPacks), DataFlowConfig: *dataflowPatterns, DataFlowMax: *dataflowMax, DataFlowCallGraphMode: dfCallgraphMode, DataFlowWorkers: *dataflowWorkers, DataFlowLargeRepoFunctions: *dataflowLargeRepoFunctions, DataFlowMaxFunctionInstructions: *dataflowMaxFunctionInstructions, DataFlowMaxTraceNodes: *dataflowMaxTraceNodes, DataFlowMaxTraceEdges: *dataflowMaxTraceEdges, DataFlowSkipGenerated: *dataflowSkipGenerated, DataFlowSkipTests: *dataflowSkipTests, DependencyDetail: detail, TaintEngine: te, MaxProcs: *maxProcs, MemoryLimit: memoryLimitBytes, Progress: *progress, ProgressInterval: *progressInterval, ProgressWriter: stderr, ToolVersion: version})
	if err != nil {
		return err
	}
	if *dataflowGraphOut != "" {
		if report.DataFlow == nil {
			return errors.New("--dataflow-graph-out requires --dataflow security, crypto, or all")
		}
		graphFormat, err := exporter.ParseDataFlowGraphFormat(*dataflowGraphFormat)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*dataflowGraphOut, []byte(exporter.DataFlowGraph(report.DataFlow, graphFormat)), 0o644); err != nil {
			return err
		}
	}
	writer := stdout
	var file *os.File
	if *outFile != "" {
		file, err = os.Create(*outFile)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		writer = file
	}
	return exporter.Write(writer, report, format)
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  golem analyze [options]
  golem bench [options]
  golem golden [options]
  golem version

Commands:
  analyze   Run static analysis on a Go project
  bench     Measure the annotated corpus and pinned upstream fixtures
  golden    Generate or verify report digests for the golden fixtures

analyze Options:
  --dir <path>             Go module/workspace directory to analyze (default: .)
  --no-recurse             Disable recursive child go.mod discovery when root has no go.mod/go.work
  --patterns <patterns>    Comma-separated go/packages patterns (default: ./...)
  --format <format>        json, graphml, or gexf (default: json)
  --out <file>             Output file path (default: stdout)
  --callgraph <mode>       none, static, cha, rta, or vta (default: none)
  --dataflow <mode>        none, security, crypto, or all (default: none)
  --include-all-flows      Keep external-only flows/call stacks rooted in module cache paths
  --dataflow-patterns <f>  Custom data-flow pattern JSON
  --dataflow-pattern-packs Comma-separated packs: all, base, http, frameworks, data, filesystem, process, crypto, native, config, cloud
  --dataflow-callgraph     none, static, cha, rta, or vta for data-flow dynamic summary replay
  --dataflow-max-slices    Maximum source-to-sink slices to emit (default: 1000)
  --dataflow-workers       Data-flow worker count; 0 uses all available cores
  --dataflow-large-repo-functions Function count for large-repo safeguards; 0 disables
  --dataflow-max-function-instructions Skip materialization above this SSA instruction count in large repos; 0 disables
  --dataflow-max-trace-nodes Maximum ordered node IDs retained per trace
  --dataflow-max-trace-edges Maximum ordered edge IDs retained per trace
  --dataflow-skip-generated Skip generated files during slice materialization
  --dataflow-skip-tests     Skip test/example/benchmark files during slice materialization
  --dataflow-graph-format  graphml or gexf for data-flow sidecar (default: graphml)
  --dataflow-graph-out     Optional data-flow graph sidecar path
  --max-procs              Go scheduler CPU threads; 0 uses all available cores
  --memory-limit           Optional Go soft memory limit, e.g. 4GiB or 800MiB
  --progress               Emit coarse progress logs to stderr
  --progress-interval      Minimum interval between progress logs (default: 5s)
  --tags <tags>            Comma-separated Go build tags
  --tests                  Include test variants
  --include-stdlib         Include standard-library usages and call graph nodes
  --include-local          Include current-module usages and graph nodes (default: true)

bench Options:
  --manifest <file>        Fixture manifest (default: testdata/bench/manifest.json)
  --corpus <dir>           Corpus root (default: sibling of the manifest)
  --tier <tier>            quick (corpus only) or full (adds upstream repositories)
  --only <names>           Comma-separated fixture names
  --taint-engine <name>    Run every fixture under this engine: legacy or seam
  --baseline <file>        Compare against this baseline
  --update-baseline <file> Write measurements to this baseline
  --fail-on-regression     Exit non-zero on a blocking regression, unexpected
                           annotation failure, or report integrity violation
  --sarif <dir>            Write per-fixture SARIF findings
  --compare <file>         Results from the incumbent engine; prints a promotion verdict
  --fail-unless-promotable With --compare, exit non-zero unless every criterion is met
  --cache-dir <dir>        Upstream fixture cache (default: $XDG_CACHE_HOME/golem-bench)
  --out <file>             Results JSON path (default: stdout)

golden Options:
  --manifest, --corpus, --tier, --only, --cache-dir as above
  --dir <dir>              Golden digest directory (default: testdata/golden)
  --update                 Write digests instead of comparing them`)
}
