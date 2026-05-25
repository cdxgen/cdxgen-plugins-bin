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
	callgraph := flags.String("callgraph", "none", "call graph mode: none, static, rta, or pointer")
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
	if mode != "none" && mode != "static" && mode != "rta" && mode != "pointer" {
		return fmt.Errorf("unsupported callgraph mode %q: expected none, static, rta, or pointer", *callgraph)
	}
	if format != exporter.FormatJSON && mode == "none" {
		return errors.New("graphml and gexf exports require --callgraph static, rta, or pointer")
	}
	report, err := analyzer.Analyze(analyzer.Options{Dir: *dir, Patterns: splitCSV(*patterns), BuildTags: splitCSV(*tags), Tests: *tests, IncludeStdlib: *includeStdlib, IncludeLocal: *includeLocal, CallGraphMode: mode, ToolVersion: version})
	if err != nil {
		return err
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
  --callgraph <mode>       none, static, rta, or pointer (default: none)
  --tags <tags>            Comma-separated Go build tags
  --tests                  Include test variants
  --include-stdlib         Include standard-library usages and call graph nodes
  --include-local          Include current-module usages and graph nodes (default: true)`)
}
