package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/bench"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/exporter"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func runBench(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("golem bench", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", filepath.Join("testdata", "bench", "manifest.json"), "benchmark manifest file")
	corpusRoot := flags.String("corpus", "", "corpus root directory (default: sibling of the manifest)")
	baselinePath := flags.String("baseline", "", "compare results against this baseline file")
	updateBaseline := flags.String("update-baseline", "", "write results to this baseline file")
	failOnRegression := flags.Bool("fail-on-regression", false, "exit non-zero on a blocking regression, unexpected failure or integrity violation")
	tier := flags.String("tier", bench.TierQuick, "fixture tier to run: quick or full")
	only := flags.String("only", "", "comma-separated fixture names to run")
	taintEngine := flags.String("taint-engine", "", "run every fixture under this taint engine: legacy or seam")
	cacheDir := flags.String("cache-dir", "", "remote fixture cache directory; defaults to $XDG_CACHE_HOME/golem-bench")
	outFile := flags.String("out", "", "write the results JSON here instead of stdout")
	sarifDir := flags.String("sarif", "", "write per-fixture SARIF findings to this directory")
	compareTo := flags.String("compare", "", "results file from the incumbent engine; prints a promotion verdict for this run")
	failUnlessPromotable := flags.Bool("fail-unless-promotable", false, "with --compare, exit non-zero unless the candidate meets every promotion criterion; use --tier full to include real-repository flow-count and wall-clock evidence")
	if err := flags.Parse(args); err != nil {
		return err
	}

	options := bench.Options{
		ManifestPath: *manifestPath,
		CorpusRoot:   *corpusRoot,
		CacheDir:     *cacheDir,
		Tier:         *tier,
		Only:         splitCSV(*only),
		TaintEngine:  *taintEngine,
		Log:          stderr,
	}
	if *sarifDir != "" {
		if err := os.MkdirAll(*sarifDir, 0o755); err != nil {
			return fmt.Errorf("creating SARIF directory: %w", err)
		}
		options.Reports = func(fixture bench.Fixture, slot bench.MatrixSlot, report *model.Report) {
			path := filepath.Join(*sarifDir, fixture.Name+"-"+slot.Label+".sarif.json")
			if err := writeSARIFFile(path, report); err != nil {
				fmt.Fprintf(stderr, "bench: writing %s: %v\n", path, err)
			}
		}
	}

	results, runErr := bench.Run(options)
	summary := bench.Summarize(results)
	current := &bench.Baseline{Version: bench.BaselineVersion, Tier: *tier, Results: results}

	if *updateBaseline != "" {
		if err := current.Save(*updateBaseline); err != nil {
			return fmt.Errorf("writing baseline: %w", err)
		}
		fmt.Fprintf(stderr, "bench: wrote baseline %s\n", *updateBaseline)
	}

	var blocking []bench.Regression
	if *baselinePath != "" {
		baseline, err := bench.LoadBaseline(*baselinePath)
		if err != nil {
			return fmt.Errorf("loading baseline: %w", err)
		}
		compareOptions := bench.DefaultCompareOptions()
		compareOptions.Filtered = len(options.Only) > 0 || *tier != baseline.Tier
		regressions := bench.Compare(current, baseline, compareOptions)
		for _, regression := range regressions {
			fmt.Fprintln(stderr, regression.String())
		}
		blocking = bench.Blocking(regressions)
		if len(blocking) == 0 {
			fmt.Fprintln(stderr, "bench: no blocking regressions")
		}
	}

	var promotion *bench.PromotionReport
	if *compareTo != "" {
		incumbent, err := bench.LoadBaseline(*compareTo)
		if err != nil {
			return fmt.Errorf("loading comparison results: %w", err)
		}
		verdict := bench.EvaluatePromotion(results, incumbent.Results, bench.DefaultPromotionCriteria())
		promotion = &verdict
		fmt.Fprintln(stderr, verdict.String())
	}

	payload := map[string]any{"version": bench.BaselineVersion, "tier": *tier, "summary": summary, "results": results}
	if promotion != nil {
		payload["promotion"] = promotion
	}
	if err := writeJSONTo(stdout, *outFile, payload); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "bench: %d result(s) annotations=%d xfail=%d fail=%d xpass=%d integrity=%d meanRecall=%.3f meanPrecision=%.3f minConnectivity=%.3f depCrossing=%d peakRss=%dMB %dms\n",
		summary.Fixtures, summary.Annotations, summary.ExpectedFailures, summary.UnexpectedFailures, summary.UnexpectedPasses,
		summary.IntegrityViolations, summary.MeanRecall, summary.MeanPrecision, summary.MinConnectivity, summary.DepCrossingSlices,
		summary.PeakRSSMB, summary.TotalWallClockMs)

	if runErr != nil {
		return runErr
	}
	if *failUnlessPromotable {
		switch {
		case promotion == nil:
			return fmt.Errorf("--fail-unless-promotable needs --compare")
		case !promotion.Promote:
			return fmt.Errorf("candidate engine does not meet the promotion criteria")
		}
	}
	if !*failOnRegression {
		return nil
	}
	switch {
	case len(blocking) > 0:
		return fmt.Errorf("%d blocking regression(s)", len(blocking))
	case summary.UnexpectedFailures > 0:
		return fmt.Errorf("%d unexpected annotation failure(s)", summary.UnexpectedFailures)
	case summary.IntegrityViolations > 0:
		return fmt.Errorf("%d report integrity violation(s)", summary.IntegrityViolations)
	}
	return nil
}

func writeSARIFFile(path string, report *model.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return exporter.WriteSARIF(file, report, exporter.SARIFOptions{BaseURI: report.Options.Directory, ToolName: "golem", ToolVersion: report.Tool.Version})
}

func writeJSONTo(stdout io.Writer, path string, payload any) error {
	writer := stdout
	if path != "" {
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		writer = file
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}
