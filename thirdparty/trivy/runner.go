package main

// The scan pipeline the wrapper runs for rootfs targets.
//
// Upstream Trivy reaches the same pipeline through pkg/commands and
// pkg/commands/artifact, which also wire in every other subcommand, client/
// server mode, the vulnerability and Java DB downloads, misconfiguration
// scanning, WASM modules, result filtering and every report format. Importing
// those packages links all of it, and none of it can run here: the wrapper
// forces an offline, SBOM-only, CycloneDX scan. The functions below keep the
// parts of github.com/aquasecurity/trivy/pkg/commands (Apache-2.0) that do run
// for a rootfs target, in the same order and with the same options, so the
// binary no longer carries the rest.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	artlocal "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/app"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

type targetKind string

const targetRootfs targetKind = "rootfs"

// newRootCommand mirrors commands.NewRootCommand: global flags, config file
// loading, logger initialisation and the `--version` printer.
func newRootCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Args: cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.Version = app.Version()

			// viper.BindPFlag cannot be called in init().
			if err := globalFlags.Bind(cmd); err != nil {
				return fmt.Errorf("flag bind error: %w", err)
			}

			// The config path is needed for config initialization, before ToOptions().
			configPath := viper.GetString(flag.ConfigFileFlag.ConfigName)
			if err := initConfig(configPath, cmd.Flags().Changed(flag.ConfigFileFlag.ConfigName)); err != nil {
				return err
			}

			flags := flag.Flags{globalFlags}
			opts, err := flags.ToOptions(args)
			if err != nil {
				return err
			}
			log.InitLogger(opts.Debug, opts.Quiet)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := flag.Flags{globalFlags}
			opts, err := flags.ToOptions(args)
			if err != nil {
				return err
			}
			if opts.ShowVersion {
				return showVersion(versionFormat, cmd.OutOrStdout())
			}
			return cmd.Help()
		},
	}
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag.Name, flag.FormatFlag.Shorthand, "", "version format (json)")
	globalFlags.AddFlags(cmd)
	return cmd
}

func newVersionCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Use:     "version [flags]",
		Short:   "Print the version",
		GroupID: groupUtility,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := flag.Flags{globalFlags}
			if _, err := flags.ToOptions(args); err != nil {
				return err
			}
			return showVersion(versionFormat, cmd.OutOrStdout())
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag.Name, flag.FormatFlag.Shorthand, "", "version format (json)")
	return cmd
}

// showVersion prints the wrapper's Trivy version. Upstream also lists the
// vulnerability DB, Java DB and checks bundle found in the cache directory;
// the wrapper never reads any of them, so it has nothing to report there.
func showVersion(outputFormat string, w io.Writer) error {
	versionInfo := trivytypes.VersionInfo{Version: app.Version()}
	if outputFormat == "json" {
		if err := json.NewEncoder(w).Encode(versionInfo); err != nil {
			return fmt.Errorf("json encode error: %w", err)
		}
		return nil
	}
	_, err := fmt.Fprint(w, versionInfo.String())
	return err
}

func initConfig(configFile string, pathChanged bool) error {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) && !pathChanged {
			log.Debugf("Default config file %q not found, using built in values", log.FilePath(configFile))
			return nil
		}
		return fmt.Errorf("config file %q loading error: %s", configFile, err)
	}
	log.Info("Loaded", log.FilePath(configFile))
	return nil
}

// checkSupportedModes rejects the options that select a code path this wrapper
// does not carry, instead of silently scanning some other way.
func checkSupportedModes(opts flag.Options) error {
	switch {
	case opts.ServerAddr != "":
		return errors.New("client/server mode (--server) is not supported by trivy-cdxgen")
	case cache.NewType(opts.CacheBackend) == cache.TypeRedis:
		return errors.New("the redis cache backend is not supported by trivy-cdxgen")
	case len(opts.SBOMSources) > 0:
		return errors.New("remote SBOM sources (--sbom-sources) are not supported by trivy-cdxgen")
	case strings.HasPrefix(opts.Output, "plugin="):
		return errors.New("output plugins (--output plugin=...) are not supported by trivy-cdxgen")
	case opts.DownloadJavaDBOnly:
		// Upstream updates the Java DB and skips the scan; the wrapper never
		// downloads it (--skip-java-db-update is forced).
		return errors.New("--download-java-db-only is not supported by trivy-cdxgen")
	}
	return nil
}

func runTarget(ctx context.Context, opts flag.Options, target string) error {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	if err := checkSupportedModes(opts); err != nil {
		return err
	}

	// Upstream also sets the default HTTP transport and initialises the Java
	// DB client here. A rootfs scan makes no HTTP requests, and the jar
	// analyzer, the Java DB's only user, is disabled with the other language
	// analyzers.
	opts.DisabledAnalyzers = rootfsDisabledAnalyzers(opts)

	report, err := scanRootfs(ctx, opts)
	if err != nil {
		return fmt.Errorf("%s scan error: %w", targetRootfs, err)
	}

	if err = enrichReportBOM(&report, target, targetRootfs, loadEnrichmentOptions()); err != nil {
		return fmt.Errorf("bom enrichment error: %w", err)
	}

	if err = writeReport(ctx, opts, report); err != nil {
		return fmt.Errorf("report error: %w", err)
	}
	return nil
}

// rootfsDisabledAnalyzers mirrors the runner's ScanRootfs.
func rootfsDisabledAnalyzers(opts flag.Options) []analyzer.Type {
	return append(opts.DisabledAnalyzers, analyzer.TypeLockfiles...)
}

func scanRootfs(ctx context.Context, opts flag.Options) (trivytypes.Report, error) {
	artifactOpt, scanOptions := initScannerConfig(opts)

	c, cleanupCache, err := cache.New(opts.CacheOpts())
	if err != nil {
		return trivytypes.Report{}, fmt.Errorf("unable to initialize cache: %w", err)
	}
	defer cleanupCache()

	art, err := artlocal.NewArtifact(opts.Target, c, walker.NewFS(), artifactOpt)
	if err != nil {
		return trivytypes.Report{}, fmt.Errorf("unable to initialize filesystem artifact: %w", err)
	}

	service := local.NewService(applier.NewApplier(c), ospkg.NewScanner(), langpkg.NewScanner(), vulnerability.NewClient(db.Config{}))
	report, err := scan.NewService(service, art).ScanArtifact(ctx, scanOptions)
	if err != nil {
		return trivytypes.Report{}, fmt.Errorf("scan failed: %w", err)
	}
	return report, nil
}

// initScannerConfig mirrors the runner's initScannerConfig for an SBOM-only,
// CycloneDX scan: misconfiguration, secret and license scanning are off, so
// their scanner options stay empty.
func initScannerConfig(opts flag.Options) (artifact.Option, trivytypes.ScanOptions) {
	scanOptions := opts.ScanOpts()
	logger := log.WithPrefix(log.PrefixPackage)
	logger.Debug("Package types", log.Any("types", scanOptions.PkgTypes))
	logger.Debug("Package relationships", log.Any("relationships", scanOptions.PkgRelationships))

	// Disable the post handler for filtering system file when detection priority is comprehensive.
	disabledHandlers := lo.Ternary(opts.DetectionPriority == ftypes.PriorityComprehensive,
		[]ftypes.HandlerType{ftypes.SystemFileFilteringPostHandler}, nil)

	return artifact.Option{
		DisabledAnalyzers: disabledAnalyzers(opts),
		DisabledHandlers:  disabledHandlers,
		FilePatterns:      opts.FilePatterns,
		Parallel:          opts.Parallel,
		Offline:           opts.OfflineScan,
		NoProgress:        opts.NoProgress || opts.Quiet,
		Insecure:          opts.Insecure,
		SBOMSources:       opts.SBOMSources,
		RekorURL:          opts.RekorURL,
		AWSRegion:         opts.Region,
		AWSEndpoint:       opts.Endpoint,
		// CycloneDX needs digests for package files.
		FileChecksum:      true,
		DetectionPriority: opts.DetectionPriority,
		MavenMirrors:      opts.MavenMirrors,
		WalkerOption: walker.Option{
			SkipFiles: opts.SkipFiles,
			SkipDirs:  opts.SkipDirs,
		},
	}, scanOptions
}

// disabledAnalyzers mirrors the runner's disabledAnalyzers for the options
// applyCDXGenDefaults forces: SBOM scanner only, CycloneDX format, OS and
// library package types.
func disabledAnalyzers(opts flag.Options) []analyzer.Type {
	analyzers := opts.DisabledAnalyzers
	if !opts.ScanRemovedPkgs {
		analyzers = append(analyzers, analyzer.TypeApkCommand)
	}
	if !slices.Contains(opts.PkgTypes, trivytypes.PkgTypeLibrary) {
		analyzers = append(analyzers, analyzer.TypeLanguages...)
	}
	analyzers = append(analyzers, analyzer.TypeSecret)
	analyzers = append(analyzers, analyzer.TypeConfigFiles...)
	analyzers = append(analyzers, analyzer.TypeLicenseFile)
	analyzers = append(analyzers, analyzer.TypeHistoryDockerfile)
	// Executable digests are only looked up in Rekor, and --sbom-sources is rejected.
	analyzers = append(analyzers, analyzer.TypeExecutable)
	if os.Getenv("TRIVY_EXPERIMENTAL_RPM_ARCHIVE") == "" {
		analyzers = append(analyzers, analyzer.TypeRpmArchive)
	}
	return analyzers
}

func writeReport(ctx context.Context, opts flag.Options, report trivytypes.Report) (err error) {
	var output io.Writer = os.Stdout
	if opts.Output != "" {
		f, err := os.Create(opts.Output)
		if err != nil {
			return fmt.Errorf("failed to create a file: %w", err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}()
		output = f
	}
	if err = cyclonedx.NewWriter(output, opts.AppVersion).Write(ctx, report); err != nil {
		return fmt.Errorf("failed to write results: %w", err)
	}
	return nil
}
