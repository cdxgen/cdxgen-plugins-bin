package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/analyzer"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/exporter"
)

var version = "2.2.0"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
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
			fmt.Fprintf(stdout, "golem %s\n", version)
			return nil
		case "analyze":
			args = args[1:]
		}
	}
	flags := flag.NewFlagSet("golem analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", ".", "Go module/workspace directory to analyze")
	patterns := flags.String("patterns", "./...", "comma-separated go/packages patterns")
	formatValue := flags.String("format", "json", "output format: json, graphml, or gexf")
	outFile := flags.String("out", "", "output file path; defaults to stdout")
	callgraph := flags.String("callgraph", "none", "call graph mode: none, static, cha, rta, vta, or pointer")
	dataflow := flags.String("dataflow", "none", "data-flow mode: none, security, crypto, or all")
	dataflowPatterns := flags.String("dataflow-patterns", "", "optional JSON file with data-flow sources, sinks, passthroughs, and sanitizers")
	dataflowPacks := flags.String("dataflow-pattern-packs", "all", "comma-separated data-flow pattern packs: all, base, http, data, filesystem, process, crypto, native")
	dataflowMax := flags.Int("dataflow-max-slices", 1000, "maximum data-flow slices to emit")
	dataflowGraphFormat := flags.String("dataflow-graph-format", "graphml", "data-flow graph sidecar format: graphml or gexf")
	dataflowGraphOut := flags.String("dataflow-graph-out", "", "optional data-flow graph sidecar output path")
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
	if mode != "none" && mode != "static" && mode != "cha" && mode != "rta" && mode != "vta" && mode != "pointer" {
		return fmt.Errorf("unsupported callgraph mode %q: expected none, static, cha, rta, vta, or pointer", *callgraph)
	}
	dfMode := strings.ToLower(strings.TrimSpace(*dataflow))
	if dfMode == "" {
		dfMode = "none"
	}
	if dfMode != "none" && dfMode != "security" && dfMode != "crypto" && dfMode != "all" {
		return fmt.Errorf("unsupported dataflow mode %q: expected none, security, crypto, or all", *dataflow)
	}
	if format != exporter.FormatJSON && mode == "none" {
		return errors.New("graphml and gexf exports require --callgraph static, rta, or pointer")
	}
	report, err := analyzer.Analyze(analyzer.Options{Dir: *dir, Patterns: splitCSV(*patterns), BuildTags: splitCSV(*tags), Tests: *tests, IncludeStdlib: *includeStdlib, IncludeLocal: *includeLocal, CallGraphMode: mode, DataFlowMode: dfMode, DataFlowPacks: splitCSV(*dataflowPacks), DataFlowConfig: *dataflowPatterns, DataFlowMax: *dataflowMax, ToolVersion: version})
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
		defer file.Close()
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
	fmt.Fprintln(w, `Usage:
  golem analyze [options]
  golem version

Options:
  --dir <path>             Go module/workspace directory to analyze (default: .)
  --patterns <patterns>    Comma-separated go/packages patterns (default: ./...)
  --format <format>        json, graphml, or gexf (default: json)
  --out <file>             Output file path (default: stdout)
  --callgraph <mode>       none, static, cha, rta, vta, or pointer (default: none)
  --dataflow <mode>        none, security, crypto, or all (default: none)
  --dataflow-patterns <f>  Custom data-flow pattern JSON
  --dataflow-pattern-packs Comma-separated packs: all, base, http, data, filesystem, process, crypto, native
  --dataflow-max-slices    Maximum source-to-sink slices to emit (default: 1000)
  --dataflow-graph-format  graphml or gexf for data-flow sidecar (default: graphml)
  --dataflow-graph-out     Optional data-flow graph sidecar path
  --tags <tags>            Comma-separated Go build tags
  --tests                  Include test variants
  --include-stdlib         Include standard-library usages and call graph nodes
  --include-local          Include current-module usages and graph nodes (default: true)`)
}
