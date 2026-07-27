package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/bench"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// runGolden generates or verifies digest goldens for the manifest fixtures that
// opt into them.
//
// The golden artifact is a digest rather than a whole report: see
// internal/bench/digest.go for why a full report is both too large to commit and
// not comparable across machines.
func runGolden(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("golem golden", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", filepath.Join("testdata", "bench", "manifest.json"), "benchmark manifest file")
	corpusRoot := flags.String("corpus", "", "corpus root directory (default: sibling of the manifest)")
	goldenDir := flags.String("dir", filepath.Join("testdata", "golden"), "golden digest directory")
	cacheDir := flags.String("cache-dir", "", "remote fixture cache directory; defaults to $XDG_CACHE_HOME/golem-bench")
	tier := flags.String("tier", bench.TierFull, "fixture tier to consider: quick or full")
	only := flags.String("only", "", "comma-separated fixture names")
	update := flags.Bool("update", false, "write digests instead of comparing them")
	if err := flags.Parse(args); err != nil {
		return err
	}

	type generated struct {
		fixture bench.Fixture
		slot    bench.MatrixSlot
		digest  *bench.Digest
	}
	var digests []generated

	_, runErr := bench.Run(bench.Options{
		ManifestPath: *manifestPath,
		CorpusRoot:   *corpusRoot,
		CacheDir:     *cacheDir,
		Tier:         *tier,
		Only:         splitCSV(*only),
		Log:          stderr,
		Reports: func(fixture bench.Fixture, slot bench.MatrixSlot, report *model.Report) {
			if !fixture.Golden {
				return
			}
			digests = append(digests, generated{fixture, slot, bench.BuildDigest(fixture.Name, fixture.Commit, slot.Label, report.Options.Directory, report)})
		},
	})
	if runErr != nil {
		return runErr
	}
	if len(digests) == 0 {
		fmt.Fprintln(stderr, "golden: no golden fixtures ran; nothing to do")
		return nil
	}

	var mismatches []string
	for _, entry := range digests {
		path := filepath.Join(*goldenDir, entry.fixture.Name+"-"+entry.slot.Label+".digest.json")
		if *update {
			if err := bench.SaveDigest(path, entry.digest); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
			fmt.Fprintf(stderr, "golden: wrote %s\n", path)
			continue
		}
		golden, err := bench.LoadDigest(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w (run \"golem golden -update\" to create it)", path, err)
		}
		if diff := entry.digest.Diff(golden); len(diff) > 0 {
			mismatches = append(mismatches, fmt.Sprintf("%s:\n    %s", path, strings.Join(diff, "\n    ")))
			continue
		}
		fmt.Fprintf(stderr, "golden: %s matches\n", path)
	}
	if len(mismatches) > 0 {
		fmt.Fprintf(stdout, "golden mismatches:\n  %s\n", strings.Join(mismatches, "\n  "))
		return fmt.Errorf("%d golden digest(s) differ", len(mismatches))
	}
	return nil
}
