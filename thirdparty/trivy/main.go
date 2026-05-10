package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	debversion "github.com/knqyf263/go-deb-version"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

const (
	groupScanning = "scanning"
	groupUtility  = "utility"

	propertyInstalledFile         = "InstalledFile"
	propertyInstalledFileCount    = "InstalledFileCount"
	propertyInstalledCommand      = "InstalledCommand"
	propertyInstalledCommandPath  = "InstalledCommandPath"
	propertyInstalledCommandCount = "InstalledCommandCount"
	propertyCapability            = "Capability"
	propertyCapabilityCount       = "CapabilityCount"
	propertyPackageArchitecture   = "PackageArchitecture"
	propertyPackageMaintainer     = "PackageMaintainer"
	propertyPackageOrigin         = "PackageOrigin"
	propertyPackageSource         = "PackageSource"
	propertyPackageStatus         = "PackageStatus"
	propertyPackageVendor         = "PackageVendor"
	propertyOSFamily              = "OSFamily"
	propertyOSName                = "OSName"
	propertyOSEOL                 = "OSEOL"
	propertyOSExtended            = "OSExtendedSupport"
)

type enrichmentOptions struct {
	includeCapabilities   bool
	includeInstalledFiles bool
	includeInstalledCmds  bool
}

type packageDecoration struct {
	capabilities          []string
	installedFiles        []string
	installedCommands     []string
	installedCommandPaths []string
	architecture          string
	maintainer            string
	origin                string
	source                string
	status                string
	vendor                string
}

func main() {
	os.Setenv("TRIVY_OFFLINE_SCAN", "true")
	os.Setenv("TRIVY_DISABLE_TELEMETRY", "true")
	os.Setenv("TRIVY_SKIP_VERSION_CHECK", "true")
	os.Exit(run())
}

func run() int {
	globalFlags := flag.NewGlobalFlagGroup()
	app := commands.NewRootCommand(globalFlags)
	app.Use = "trivy-cdxgen [global flags] command [flags] target"
	app.Short = "cdxgen-focused Trivy wrapper"
	app.Long = "Trivy wrapper tailored for cdxgen rootfs/image SBOM generation"
	app.Example = `  # Generate a CycloneDX SBOM from an image
  $ trivy-cdxgen image --output image.cdx ubuntu:24.04

  # Generate a CycloneDX SBOM from an unpacked root filesystem
  $ trivy-cdxgen rootfs --output rootfs.cdx /tmp/rootfs`
	app.AddGroup(
		&cobra.Group{ID: groupScanning, Title: "Scanning Commands"},
		&cobra.Group{ID: groupUtility, Title: "Utility Commands"},
	)
	app.SetCompletionCommandGroupID(groupUtility)
	app.SetHelpCommandGroupID(groupUtility)
	app.AddCommand(
		newImageCommand(globalFlags),
		newRootfsCommand(globalFlags),
		commands.NewVersionCommand(globalFlags),
	)
	if err := app.Execute(); err != nil {
		return 1
	}
	return 0
}

func newImageCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	cacheFlagGroup := flag.NewCacheFlagGroup()
	cacheFlagGroup.CacheBackend.Default = string(cache.TypeMemory)

	reportFlagGroup := flag.NewReportFlagGroup()
	packageFlagGroup := flag.NewPackageFlagGroup()
	packageFlagGroup.IncludeDevDeps = nil

	imageFlags := flag.Flags{
		globalFlags,
		cacheFlagGroup,
		flag.NewDBFlagGroup(),
		flag.NewLicenseFlagGroup(),
		flag.NewMisconfFlagGroup(),
		flag.NewModuleFlagGroup(),
		packageFlagGroup,
		flag.NewClientFlags(),
		flag.NewRegistryFlagGroup(),
		flag.NewRegoFlagGroup(),
		reportFlagGroup,
		flag.NewScanFlagGroup(),
		flag.NewSecretFlagGroup(),
		flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "image [flags] IMAGE_NAME",
		Aliases: []string{"i"},
		GroupID: groupScanning,
		Short:   "Generate an OS-package CycloneDX SBOM from a container image",
		Example: `  # Generate a CycloneDX SBOM for a container image
  $ trivy-cdxgen image --output result.cdx alpine:3.20`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := imageFlags.Bind(cmd); err != nil {
				return fmt.Errorf("flag bind error: %w", err)
			}
			return validateSingleTarget(args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := imageFlags.ToOptions(args)
			if err != nil {
				return fmt.Errorf("flag error: %w", err)
			}
			applyCDXGenDefaults(&options)
			return runTarget(cmd.Context(), options, args[0], artifact.TargetContainerImage)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	imageFlags.AddFlags(cmd)
	return cmd
}

func newRootfsCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.ReportFormat = nil
	reportFlagGroup.Compliance = nil

	packageFlagGroup := flag.NewPackageFlagGroup()
	packageFlagGroup.IncludeDevDeps = nil

	cacheFlagGroup := flag.NewCacheFlagGroup()
	cacheFlagGroup.CacheBackend.Default = string(cache.TypeMemory)

	rootfsFlags := flag.Flags{
		globalFlags,
		cacheFlagGroup,
		flag.NewDBFlagGroup(),
		flag.NewLicenseFlagGroup(),
		flag.NewMisconfFlagGroup(),
		flag.NewModuleFlagGroup(),
		packageFlagGroup,
		flag.NewClientFlags(),
		flag.NewRegistryFlagGroup(),
		flag.NewRegoFlagGroup(),
		reportFlagGroup,
		flag.NewScanFlagGroup(),
		flag.NewSecretFlagGroup(),
		flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "rootfs [flags] ROOTDIR",
		GroupID: groupScanning,
		Short:   "Generate an OS-package CycloneDX SBOM from an unpacked root filesystem",
		Example: `  # Generate a CycloneDX SBOM for an unpacked root filesystem
  $ trivy-cdxgen rootfs --output result.cdx /tmp/rootfs`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := rootfsFlags.Bind(cmd); err != nil {
				return fmt.Errorf("flag bind error: %w", err)
			}
			return validateSingleTarget(args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := rootfsFlags.ToOptions(args)
			if err != nil {
				return fmt.Errorf("flag error: %w", err)
			}
			applyCDXGenDefaults(&options)
			return runTarget(cmd.Context(), options, args[0], artifact.TargetRootfs)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	rootfsFlags.AddFlags(cmd)
	return cmd
}

func validateSingleTarget(args []string) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("requires exactly one target path or image reference")
	}
	return nil
}

func applyCDXGenDefaults(opts *flag.Options) {
	opts.DisableTelemetry = true
	opts.ExitCode = 0
	opts.Format = trivytypes.FormatCycloneDX
	opts.NoProgress = true
	opts.OfflineScan = true
	opts.PkgTypes = []string{trivytypes.PkgTypeOS}
	opts.Quiet = !opts.Debug
	opts.Scanners = trivytypes.Scanners{trivytypes.SBOMScanner}
	opts.SkipDBUpdate = true
	opts.SkipFiles = append(opts.SkipFiles, "**/*.jar,**/*.war,**/*.par,**/*.ear")
	opts.SkipJavaDBUpdate = true
	opts.SkipVersionCheck = true
}

func runTarget(ctx context.Context, opts flag.Options, target string, targetKind artifact.TargetKind) error {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	r, err := artifact.NewRunner(ctx, opts, targetKind)
	if err != nil {
		if errors.Is(err, artifact.SkipScan) {
			return nil
		}
		return fmt.Errorf("init error: %w", err)
	}
	defer func() {
		if closeErr := r.Close(ctx); closeErr != nil {
			log.ErrorContext(ctx, "failed to close runner: %s", closeErr)
		}
	}()

	var report trivytypes.Report
	switch targetKind {
	case artifact.TargetContainerImage:
		report, err = r.ScanImage(ctx, opts)
	case artifact.TargetRootfs:
		report, err = r.ScanRootfs(ctx, opts)
	default:
		return fmt.Errorf("unsupported target kind: %s", targetKind)
	}
	if err != nil {
		return fmt.Errorf("%s scan error: %w", targetKind, err)
	}

	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return fmt.Errorf("filter error: %w", err)
	}

	if err = enrichReportBOM(&report, target, targetKind, loadEnrichmentOptions()); err != nil {
		return fmt.Errorf("bom enrichment error: %w", err)
	}

	if err = r.Report(ctx, opts, report); err != nil {
		return fmt.Errorf("report error: %w", err)
	}

	return operation.Exit(opts, report.Results.Failed(), report.Metadata)
}

func loadEnrichmentOptions() enrichmentOptions {
	return enrichmentOptions{
		includeCapabilities:   envBool("TRIVY_CDXGEN_INCLUDE_OS_CAPABILITIES", true),
		includeInstalledFiles: envBool("TRIVY_CDXGEN_INCLUDE_OS_FILES", true),
		includeInstalledCmds:  envBool("TRIVY_CDXGEN_INCLUDE_OS_COMMANDS", true),
	}
}

func envBool(name string, defaultValue bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func enrichReportBOM(report *trivytypes.Report, target string, targetKind artifact.TargetKind, opts enrichmentOptions) error {
	if report == nil || report.ArtifactName == "" && len(report.Results) == 0 {
		return nil
	}
	bom, err := sbomio.NewEncoder(sbomio.WithBOMRef()).Encode(*report)
	if err != nil {
		return err
	}

	decorations := collectPackageDecorations(report.Results, target, targetKind, opts)
	for _, component := range bom.Components() {
		if component.Type == core.TypeOS && report.Metadata.OS != nil {
			component.Properties = appendProperties(component.Properties,
				core.Property{Name: propertyOSFamily, Value: string(report.Metadata.OS.Family)},
				core.Property{Name: propertyOSName, Value: report.Metadata.OS.Name},
				core.Property{Name: propertyOSEOL, Value: strconv.FormatBool(report.Metadata.OS.Eosl)},
				core.Property{Name: propertyOSExtended, Value: strconv.FormatBool(report.Metadata.OS.Extended)},
			)
		}

		pkgID := propertyValue(component.Properties, core.PropertyPkgID)
		if pkgID == "" {
			continue
		}
		decoration, ok := decorations[pkgID]
		if !ok {
			continue
		}
		component.Properties = appendPackageProperties(component.Properties, decoration, opts)
	}

	report.BOM = bom
	return nil
}

func collectPackageDecorations(results trivytypes.Results, target string, targetKind artifact.TargetKind, opts enrichmentOptions) map[string]packageDecoration {
	decorations := make(map[string]packageDecoration)
	rootfsTarget := ""
	capabilitiesByPackage := make(map[string][]string)
	trustMetadataByPackage := make(map[string]packageDecoration)
	if targetKind == artifact.TargetRootfs {
		rootfsTarget = target
		if opts.includeCapabilities {
			capabilitiesByPackage = collectPackageCapabilities(target)
		}
		trustMetadataByPackage = collectPackageTrustMetadata(target)
	}
	for _, result := range results {
		if result.Class != trivytypes.ClassOSPkg {
			continue
		}
		for _, pkg := range result.Packages {
			pkgID := normalizePkgID(pkg)
			decoration := decorations[pkgID]
			if opts.includeCapabilities {
				decoration.capabilities = append(decoration.capabilities, capabilitiesByPackage[pkgID]...)
			}
			if opts.includeInstalledFiles {
				decoration.installedFiles = append(decoration.installedFiles, pkg.InstalledFiles...)
			}
			if opts.includeInstalledCmds {
				paths, commands := extractInstalledCommands(rootfsTarget, pkg.InstalledFiles)
				decoration.installedCommandPaths = append(decoration.installedCommandPaths, paths...)
				decoration.installedCommands = append(decoration.installedCommands, commands...)
			}
			if trustDecoration, ok := trustMetadataByPackage[pkgID]; ok {
				decoration.architecture = firstNonEmpty(trustDecoration.architecture, decoration.architecture)
				decoration.maintainer = firstNonEmpty(trustDecoration.maintainer, decoration.maintainer)
				decoration.origin = firstNonEmpty(trustDecoration.origin, decoration.origin)
				decoration.source = firstNonEmpty(trustDecoration.source, decoration.source)
				decoration.status = firstNonEmpty(trustDecoration.status, decoration.status)
				decoration.vendor = firstNonEmpty(trustDecoration.vendor, decoration.vendor)
			}
			decorations[pkgID] = packageDecoration{
				capabilities:          uniqueSorted(decoration.capabilities),
				installedFiles:        uniqueSorted(decoration.installedFiles),
				installedCommands:     uniqueSorted(decoration.installedCommands),
				installedCommandPaths: uniqueSorted(decoration.installedCommandPaths),
				architecture:          decoration.architecture,
				maintainer:            decoration.maintainer,
				origin:                decoration.origin,
				source:                decoration.source,
				status:                decoration.status,
				vendor:                decoration.vendor,
			}
		}
	}
	return decorations
}

func normalizePkgID(pkg ftypes.Package) string {
	if pkg.ID != "" {
		return pkg.ID
	}
	return fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
}

func extractInstalledCommands(rootfsTarget string, installedFiles []string) ([]string, []string) {
	var commandPaths []string
	var commands []string
	for _, installedFile := range uniqueSorted(installedFiles) {
		if !looksLikeCommandPath(installedFile) {
			continue
		}
		if rootfsTarget != "" && !isExecutableOnDisk(rootfsTarget, installedFile) {
			continue
		}
		commandPaths = append(commandPaths, installedFile)
		commands = append(commands, path.Base(installedFile))
	}
	return uniqueSorted(commandPaths), uniqueSorted(commands)
}

func looksLikeCommandPath(installedFile string) bool {
	cleanPath := path.Clean(installedFile)
	if cleanPath == "." || cleanPath == "/" || strings.HasSuffix(cleanPath, "/") {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(segments) < 2 {
		return false
	}
	for _, segment := range segments[:len(segments)-1] {
		switch segment {
		case "bin", "sbin", "libexec":
			return true
		}
	}
	return false
}

func isExecutableOnDisk(rootfsTarget, installedFile string) bool {
	resolvedPath := filepath.Join(rootfsTarget, filepath.FromSlash(strings.TrimPrefix(installedFile, "/")))
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return true
	}
	if info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

func appendPackageProperties(properties core.Properties, decoration packageDecoration, opts enrichmentOptions) core.Properties {
	if len(decoration.capabilities) == 0 && len(decoration.installedFiles) == 0 && len(decoration.installedCommands) == 0 && len(decoration.installedCommandPaths) == 0 {
		return properties
	}
	properties = appendProperties(properties,
		core.Property{Name: propertyCapabilityCount, Value: strconv.Itoa(len(decoration.capabilities))},
		core.Property{Name: propertyInstalledFileCount, Value: strconv.Itoa(len(decoration.installedFiles))},
		core.Property{Name: propertyInstalledCommandCount, Value: strconv.Itoa(len(decoration.installedCommands))},
		core.Property{Name: propertyPackageArchitecture, Value: decoration.architecture},
		core.Property{Name: propertyPackageMaintainer, Value: decoration.maintainer},
		core.Property{Name: propertyPackageOrigin, Value: decoration.origin},
		core.Property{Name: propertyPackageSource, Value: decoration.source},
		core.Property{Name: propertyPackageStatus, Value: decoration.status},
		core.Property{Name: propertyPackageVendor, Value: decoration.vendor},
	)
	if opts.includeCapabilities {
		for _, capability := range decoration.capabilities {
			properties = appendProperties(properties, core.Property{Name: propertyCapability, Value: capability})
		}
	}
	if opts.includeInstalledFiles {
		for _, installedFile := range decoration.installedFiles {
			properties = appendProperties(properties, core.Property{Name: propertyInstalledFile, Value: installedFile})
		}
	}
	if opts.includeInstalledCmds {
		for _, commandPath := range decoration.installedCommandPaths {
			properties = appendProperties(properties, core.Property{Name: propertyInstalledCommandPath, Value: commandPath})
		}
		for _, command := range decoration.installedCommands {
			properties = appendProperties(properties, core.Property{Name: propertyInstalledCommand, Value: command})
		}
	}
	sort.Sort(properties)
	return properties
}

func appendProperties(properties core.Properties, additions ...core.Property) core.Properties {
	seen := make(map[string]struct{}, len(properties)+len(additions))
	for _, property := range properties {
		seen[property.Name+"\x00"+property.Value] = struct{}{}
	}
	for _, property := range additions {
		if property.Value == "" {
			continue
		}
		key := property.Name + "\x00" + property.Value
		if _, ok := seen[key]; ok {
			continue
		}
		properties = append(properties, property)
		seen[key] = struct{}{}
	}
	return properties
}

func propertyValue(properties core.Properties, name string) string {
	for _, property := range properties {
		if property.Name == name {
			return property.Value
		}
	}
	return ""
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	uniqueValues := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		uniqueValues = append(uniqueValues, trimmed)
	}
	sort.Strings(uniqueValues)
	if len(uniqueValues) == 0 {
		return nil
	}
	return uniqueValues
}

func collectPackageCapabilities(rootfsTarget string) map[string][]string {
	capabilitiesByPackage := make(map[string][]string)
	mergePackageCapabilities(capabilitiesByPackage, parseAPKCapabilities(rootfsTarget))
	mergePackageCapabilities(capabilitiesByPackage, parseDPKGCapabilities(rootfsTarget))
	mergePackageCapabilities(capabilitiesByPackage, parseRPMCapabilities(rootfsTarget))
	for pkgID, capabilities := range capabilitiesByPackage {
		capabilitiesByPackage[pkgID] = uniqueSorted(capabilities)
	}
	return capabilitiesByPackage
}

func collectPackageTrustMetadata(rootfsTarget string) map[string]packageDecoration {
	trustMetadataByPackage := make(map[string]packageDecoration)
	mergePackageTrustMetadata(trustMetadataByPackage, parseAPKPackageTrust(rootfsTarget))
	mergePackageTrustMetadata(trustMetadataByPackage, parseDPKGPackageTrust(rootfsTarget))
	mergePackageTrustMetadata(trustMetadataByPackage, parseRPMPackageTrust(rootfsTarget))
	return trustMetadataByPackage
}

func mergePackageTrustMetadata(dst map[string]packageDecoration, src map[string]packageDecoration) {
	for pkgID, trustMetadata := range src {
		existing := dst[pkgID]
		existing.architecture = firstNonEmpty(existing.architecture, trustMetadata.architecture)
		existing.maintainer = firstNonEmpty(existing.maintainer, trustMetadata.maintainer)
		existing.origin = firstNonEmpty(existing.origin, trustMetadata.origin)
		existing.source = firstNonEmpty(existing.source, trustMetadata.source)
		existing.status = firstNonEmpty(existing.status, trustMetadata.status)
		existing.vendor = firstNonEmpty(existing.vendor, trustMetadata.vendor)
		dst[pkgID] = existing
	}
}

func mergePackageCapabilities(dst map[string][]string, src map[string][]string) {
	for pkgID, capabilities := range src {
		dst[pkgID] = append(dst[pkgID], capabilities...)
	}
}

func parseAPKCapabilities(rootfsTarget string) map[string][]string {
	for _, dbPath := range []string{
		filepath.Join(rootfsTarget, "lib", "apk", "db", "installed"),
		filepath.Join(rootfsTarget, "usr", "lib", "apk", "db", "installed"),
	} {
		data, err := os.ReadFile(dbPath)
		if err != nil {
			continue
		}
		capabilitiesByPackage := make(map[string][]string)
		var currentName string
		var currentVersion string
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			if len(line) < 2 {
				currentName = ""
				currentVersion = ""
				continue
			}
			switch {
			case strings.HasPrefix(line, "P:"):
				currentName = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "V:"):
				currentVersion = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "p:") && currentName != "" && currentVersion != "":
				pkgID := fmt.Sprintf("%s@%s", currentName, currentVersion)
				for _, capability := range strings.Fields(line[2:]) {
					capability = trimVersionRequirement(capability)
					if capability != "" && capability != currentName {
						capabilitiesByPackage[pkgID] = append(capabilitiesByPackage[pkgID], capability)
					}
				}
			}
		}
		if len(capabilitiesByPackage) > 0 {
			return capabilitiesByPackage
		}
	}
	return map[string][]string{}
}

func parseAPKPackageTrust(rootfsTarget string) map[string]packageDecoration {
	for _, dbPath := range []string{
		filepath.Join(rootfsTarget, "lib", "apk", "db", "installed"),
		filepath.Join(rootfsTarget, "usr", "lib", "apk", "db", "installed"),
	} {
		data, err := os.ReadFile(dbPath)
		if err != nil {
			continue
		}
		trustMetadataByPackage := make(map[string]packageDecoration)
		var currentName string
		var currentVersion string
		var current packageDecoration
		flush := func() {
			if currentName == "" || currentVersion == "" {
				return
			}
			trustMetadataByPackage[fmt.Sprintf("%s@%s", currentName, currentVersion)] = current
		}
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			if len(line) < 2 {
				flush()
				currentName = ""
				currentVersion = ""
				current = packageDecoration{}
				continue
			}
			switch {
			case strings.HasPrefix(line, "P:"):
				currentName = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "V:"):
				currentVersion = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "A:"):
				current.architecture = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "m:"):
				current.maintainer = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "o:"):
				current.origin = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "S:"):
				current.source = strings.TrimSpace(line[2:])
			case strings.HasPrefix(line, "s:"):
				current.status = strings.TrimSpace(line[2:])
			}
		}
		flush()
		if len(trustMetadataByPackage) > 0 {
			return trustMetadataByPackage
		}
	}
	return map[string]packageDecoration{}
}

func parseDPKGCapabilities(rootfsTarget string) map[string][]string {
	capabilitiesByPackage := make(map[string][]string)
	for _, statusPath := range dpkgStatusPaths(rootfsTarget) {
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		for _, header := range parseDebianControlHeaders(data) {
			status := header.Get("Status")
			if strings.Contains(status, "deinstall") || strings.Contains(status, "purge") {
				continue
			}
			name := header.Get("Package")
			version := header.Get("Version")
			if name == "" || version == "" {
				continue
			}
			debVersion, err := debversion.NewVersion(version)
			if err != nil {
				continue
			}
			pkgID := fmt.Sprintf("%s@%s", name, debVersion.Version())
			provides := splitDebianCapabilities(header.Get("Provides"))
			if len(provides) == 0 {
				continue
			}
			for _, capability := range provides {
				if capability != name {
					capabilitiesByPackage[pkgID] = append(capabilitiesByPackage[pkgID], capability)
				}
			}
		}
	}
	return capabilitiesByPackage
}

func parseDPKGPackageTrust(rootfsTarget string) map[string]packageDecoration {
	trustMetadataByPackage := make(map[string]packageDecoration)
	for _, statusPath := range dpkgStatusPaths(rootfsTarget) {
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		for _, header := range parseDebianControlHeaders(data) {
			name := header.Get("Package")
			version := header.Get("Version")
			if name == "" || version == "" {
				continue
			}
			debVersion, err := debversion.NewVersion(version)
			if err != nil {
				continue
			}
			trustMetadataByPackage[fmt.Sprintf("%s@%s", name, debVersion.Version())] = packageDecoration{
				architecture: header.Get("Architecture"),
				maintainer:   header.Get("Maintainer"),
				origin:       header.Get("Origin"),
				source:       header.Get("Source"),
				status:       header.Get("Status"),
			}
		}
	}
	return trustMetadataByPackage
}

func dpkgStatusPaths(rootfsTarget string) []string {
	paths := []string{filepath.Join(rootfsTarget, "var", "lib", "dpkg", "status")}
	statusDir := filepath.Join(rootfsTarget, "var", "lib", "dpkg", "status.d")
	entries, err := os.ReadDir(statusDir)
	if err != nil {
		return paths
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(statusDir, entry.Name()))
	}
	sort.Strings(paths)
	return paths
}

func parseDebianControlHeaders(data []byte) []textproto.MIMEHeader {
	sections := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(data), "\r\n", "\n")), "\n\n")
	headers := make([]textproto.MIMEHeader, 0, len(sections))
	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}
		header, err := textproto.NewReader(bufio.NewReader(strings.NewReader(section + "\n\n"))).ReadMIMEHeader()
		if err != nil {
			continue
		}
		headers = append(headers, header)
	}
	return headers
}

func splitDebianCapabilities(provides string) []string {
	var capabilities []string
	for _, part := range strings.Split(provides, ",") {
		for _, alt := range strings.Split(part, "|") {
			capability := trimVersionRequirement(strings.TrimSpace(alt))
			if capability != "" {
				capabilities = append(capabilities, capability)
			}
		}
	}
	return capabilities
}

func parseRPMCapabilities(rootfsTarget string) map[string][]string {
	for _, dbPath := range []string{
		filepath.Join(rootfsTarget, "usr", "lib", "sysimage", "rpm", "Packages"),
		filepath.Join(rootfsTarget, "var", "lib", "rpm", "Packages"),
		filepath.Join(rootfsTarget, "usr", "lib", "sysimage", "rpm", "Packages.db"),
		filepath.Join(rootfsTarget, "var", "lib", "rpm", "Packages.db"),
		filepath.Join(rootfsTarget, "usr", "lib", "sysimage", "rpm", "rpmdb.sqlite"),
		filepath.Join(rootfsTarget, "var", "lib", "rpm", "rpmdb.sqlite"),
		filepath.Join(rootfsTarget, "usr", "share", "rpm", "rpmdb.sqlite"),
	} {
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		db, err := rpmdb.Open(dbPath)
		if err != nil {
			continue
		}
		pkgList, err := db.ListPackages()
		_ = db.Close()
		if err != nil {
			continue
		}
		capabilitiesByPackage := make(map[string][]string)
		for _, pkg := range pkgList {
			arch := pkg.Arch
			if arch == "" {
				arch = "None"
			}
			pkgID := fmt.Sprintf("%s@%s-%s.%s", pkg.Name, pkg.Version, pkg.Release, arch)
			for _, capability := range pkg.Provides {
				capability = strings.TrimSpace(capability)
				if capability == "" || capability == pkg.Name || strings.HasPrefix(capability, "rpmlib(") {
					continue
				}
				capabilitiesByPackage[pkgID] = append(capabilitiesByPackage[pkgID], capability)
			}
		}
		if len(capabilitiesByPackage) > 0 {
			return capabilitiesByPackage
		}
	}
	return map[string][]string{}
}

func parseRPMPackageTrust(rootfsTarget string) map[string]packageDecoration {
	for _, dbPath := range []string{
		filepath.Join(rootfsTarget, "usr", "lib", "sysimage", "rpm", "Packages"),
		filepath.Join(rootfsTarget, "var", "lib", "rpm", "Packages"),
		filepath.Join(rootfsTarget, "usr", "lib", "sysimage", "rpm", "Packages.db"),
		filepath.Join(rootfsTarget, "var", "lib", "rpm", "Packages.db"),
		filepath.Join(rootfsTarget, "usr", "lib", "sysimage", "rpm", "rpmdb.sqlite"),
		filepath.Join(rootfsTarget, "var", "lib", "rpm", "rpmdb.sqlite"),
		filepath.Join(rootfsTarget, "usr", "share", "rpm", "rpmdb.sqlite"),
	} {
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		db, err := rpmdb.Open(dbPath)
		if err != nil {
			continue
		}
		pkgList, err := db.ListPackages()
		_ = db.Close()
		if err != nil {
			continue
		}
		trustMetadataByPackage := make(map[string]packageDecoration)
		for _, pkg := range pkgList {
			arch := pkg.Arch
			if arch == "" {
				arch = "None"
			}
			trustMetadataByPackage[fmt.Sprintf("%s@%s-%s.%s", pkg.Name, pkg.Version, pkg.Release, arch)] = packageDecoration{
				architecture: arch,
				source:       pkg.SourceRpm,
				vendor:       pkg.Vendor,
			}
		}
		if len(trustMetadataByPackage) > 0 {
			return trustMetadataByPackage
		}
	}
	return map[string]packageDecoration{}
}

func trimVersionRequirement(value string) string {
	if idx := strings.Index(value, " ("); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.IndexAny(value, "<>="); idx >= 0 {
		value = value[:idx]
	}
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, "(")
	value = strings.TrimSuffix(value, ")")
	return strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
