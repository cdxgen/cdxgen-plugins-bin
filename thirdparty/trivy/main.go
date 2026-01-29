package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "modernc.org/sqlite" // Required: sqlite driver for RPM DB and Java DB
)

var version = "2.0.1"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	globalFlags := flag.NewGlobalFlagGroup()
	cacheFlags := flag.NewCacheFlagGroup()
	dbFlags := flag.NewDBFlagGroup()
	reportFlags := flag.NewReportFlagGroup()
	scanFlags := flag.NewScanFlagGroup()

	cacheFlags.CacheBackend.Default = string(cache.TypeMemory)

	allFlags := flag.Flags{
		globalFlags,
		cacheFlags,
		dbFlags,
		reportFlags,
		scanFlags,
	}

	cmd := &cobra.Command{
		Use:          "trivy-cdxgen [flags] ROOTDIR",
		Short:        "Minimal rootfs scanner for cdxgen",
		Version:      version,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.InitLogger(false, true)

			opts, err := allFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			opts.Format = types.FormatCycloneDX
			opts.ReportFormat = "all"

			opts.Scanners = []types.Scanner{}

			opts.OfflineScan = true

			opts.DisableTelemetry = true

			if output, _ := cmd.Flags().GetString("output"); output != "" {
				opts.Output = output
			}

			return artifact.Run(cmd.Context(), opts, artifact.TargetRootfs)
		},
	}

	cmd.Flags().StringP("output", "o", "", "output file name")

	return cmd.Execute()
}