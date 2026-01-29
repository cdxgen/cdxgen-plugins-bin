package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/applier"

	_ "modernc.org/sqlite" // Required: sqlite driver for RPM DB and Java DB
)

var version = "2.0.2"

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
	pkgFlags := flag.NewPackageFlagGroup()
	scanFlags := flag.NewScanFlagGroup()

	cacheFlags.CacheBackend.Default = string(cache.TypeMemory)

	allFlags := flag.Flags{
		globalFlags,
		cacheFlags,
		dbFlags,
		flag.NewLicenseFlagGroup(),
		reportFlags,
		pkgFlags,
		scanFlags,
	}

	cmd := &cobra.Command{
		Use:          "trivy-cdxgen [flags] ROOTDIR",
		Short:        "Minimal rootfs scanner for cdxgen",
		Version:      version,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.InitLogger(true, false)

			opts, err := allFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			opts.Format = types.FormatCycloneDX
			opts.ReportFormat = "all"
            opts.PkgTypes = []string{types.PkgTypeLibrary, types.PkgTypeOS}
			opts.Scanners = types.Scanners{
				types.SBOMScanner,
				types.LicenseScanner,
			}

			opts.ListAllPkgs = true
			opts.OfflineScan = true
			opts.SkipDBUpdate = true
			opts.DisableTelemetry = true
			opts.Timeout = 5 * time.Minute
			opts.SkipFiles = []string{"**/*.jar", "**/*.war", "**/*.par", "**/*.ear"}

			if output, _ := cmd.Flags().GetString("output"); output != "" {
				opts.Output = output
			}

			return artifact.Run(cmd.Context(), opts, artifact.TargetRootfs)
		},
	}
	cmd.Flags().StringP("output", "o", "", "output file name")
	return cmd.Execute()
}