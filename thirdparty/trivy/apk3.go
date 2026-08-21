package main

// apk-tools 3.x support.
//
// Alpine and its apk-tools 2.x derivatives keep the installed-package database
// at lib/apk/db/installed (or usr/lib/apk/db/installed), the two paths Trivy's
// own apk analyzer looks at. apk-tools 3.x, used by BellSoft Alpaquita Linux,
// moved the database to var/lib/apk/db/installed while keeping the same
// paragraph text format, so neither the packages nor the OS of such an image
// are detected by Trivy. The analyzers below add that path and the Alpaquita
// os-release ID.
//
// The database parser follows the same field handling as
// github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk (Apache-2.0), whose
// parser is unexported.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	apkVersion "github.com/knqyf263/go-apk-version"
	"github.com/package-url/packageurl-go"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

const (
	analyzerTypeAPK3          = analyzer.Type("apk3-pkg")
	analyzerTypeAlpaquitaOS   = analyzer.Type("alpaquita-os")
	analyzerVersionAPK3       = 1
	analyzerVersionAlpaquita  = 1
	osFamilyAlpaquita         = ftypes.OSType("alpaquita")
	alpaquitaReleaseFile      = "etc/alpaquita-release"
	apk3InstalledDatabasePath = "var/lib/apk/db/installed"
)

func init() {
	analyzer.RegisterAnalyzer(apk3PkgAnalyzer{})
	analyzer.RegisterAnalyzer(alpaquitaOSAnalyzer{})
}

// apkDBPaths returns the installed-package database locations of every apk-tools
// generation, in the order they should be tried.
func apkDBPaths(rootfsTarget string) []string {
	return []string{
		filepath.Join(rootfsTarget, "lib", "apk", "db", "installed"),
		filepath.Join(rootfsTarget, "usr", "lib", "apk", "db", "installed"),
		filepath.Join(rootfsTarget, "var", "lib", "apk", "db", "installed"),
	}
}

type apk3PkgAnalyzer struct{}

func (a apk3PkgAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	ctx = log.WithContextPrefix(ctx, "apk3")
	pkgs, installedFiles := parseAPKInstalledDB(ctx, input.Content)
	return &analyzer.AnalysisResult{
		PackageInfos: []ftypes.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: pkgs,
			},
		},
		SystemInstalledFiles: installedFiles,
	}, nil
}

func (a apk3PkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filePath == apk3InstalledDatabasePath
}

func (a apk3PkgAnalyzer) Type() analyzer.Type { return analyzerTypeAPK3 }

func (a apk3PkgAnalyzer) Version() int { return analyzerVersionAPK3 }

func (a apk3PkgAnalyzer) StaticPaths() []string { return []string{apk3InstalledDatabasePath} }

type alpaquitaOSAnalyzer struct{}

func (a alpaquitaOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	data, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, err
	}
	// The file holds the release channel on a single line, e.g. "stream" or
	// "24.4.0", matching VERSION_ID in os-release.
	version := strings.TrimSpace(string(data))
	if version == "" {
		return nil, nil
	}
	return &analyzer.AnalysisResult{
		OS: ftypes.OS{
			Family: osFamilyAlpaquita,
			Name:   version,
		},
	}, nil
}

func (a alpaquitaOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filePath == alpaquitaReleaseFile
}

func (a alpaquitaOSAnalyzer) Type() analyzer.Type { return analyzerTypeAlpaquitaOS }

func (a alpaquitaOSAnalyzer) Version() int { return analyzerVersionAlpaquita }

func (a alpaquitaOSAnalyzer) StaticPaths() []string { return []string{alpaquitaReleaseFile} }

// normalizeAlpaquitaPurl rewrites the purl of an Alpaquita component to the apk
// purl type. Trivy maps only its own built-in apk families to `pkg:apk`, so a
// family it does not know becomes the purl type itself (`pkg:alpaquita/curl`);
// the packages are apk packages published by BellSoft, so they belong under
// `pkg:apk/alpaquita/curl@...?distro=alpaquita-stream`, the spelling every other apk
// distro (alpine, wolfi, chainguard) already uses. The `distro` qualifier is
// added here for the same reason: Trivy stamps it only for the apk families it
// knows.
func normalizeAlpaquitaPurl(component *core.Component, osName string) {
	purl := component.PkgIdentifier.PURL
	if purl == nil || purl.Type != string(osFamilyAlpaquita) {
		return
	}
	purl.Type = packageurl.TypeApk
	purl.Namespace = string(osFamilyAlpaquita)
	component.Group = purl.Namespace
	if osName != "" && purl.Qualifiers.Map()["distro"] == "" {
		purl.Qualifiers = append(purl.Qualifiers, packageurl.Qualifier{
			Key:   "distro",
			Value: fmt.Sprintf("%s-%s", osFamilyAlpaquita, osName),
		})
		sort.Slice(purl.Qualifiers, func(i, j int) bool {
			return purl.Qualifiers[i].Key < purl.Qualifiers[j].Key
		})
	}
	if component.PkgIdentifier.BOMRef != "" {
		component.PkgIdentifier.BOMRef = purl.String()
	}
}

// parseAPKInstalledDB parses an apk installed database and returns its packages
// along with every file they own.
func parseAPKInstalledDB(ctx context.Context, r io.Reader) ([]ftypes.Package, []string) {
	var (
		pkgs           []ftypes.Package
		pkg            ftypes.Package
		version        string
		dir            string
		installedFiles []string
		provides       = make(map[string]string) // provided name -> package ID
	)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// An empty line ends a package paragraph.
		if len(line) < 2 {
			if !pkg.Empty() {
				pkgs = append(pkgs, pkg)
			}
			pkg = ftypes.Package{}
			continue
		}

		// ref. https://wiki.alpinelinux.org/wiki/Apk_spec
		switch line[:2] {
		case "P:":
			pkg.Name = line[2:]
		case "V:":
			version = line[2:]
			if !apkVersion.Valid(version) {
				log.WarnContext(ctx, "Invalid version found",
					log.String("name", pkg.Name), log.String("version", version))
				continue
			}
			pkg.Version = version
		case "o:":
			pkg.SrcName = line[2:]
			pkg.SrcVersion = version
		case "L:":
			pkg.Licenses = licensing.LaxSplitLicenses(line[2:])
		case "F:":
			dir = line[2:]
		case "R:":
			absPath := path.Join(dir, line[2:])
			pkg.InstalledFiles = append(pkg.InstalledFiles, absPath)
			installedFiles = append(installedFiles, absPath)
		case "p:": // provides, space separated
			for _, p := range strings.Fields(line[2:]) {
				provides[trimVersionRequirement(p)] = pkg.ID
			}
		case "D:": // dependencies, space separated
			pkg.DependsOn = parseAPKDependencies(line[2:])
		case "A:":
			pkg.Arch = line[2:]
		case "C:":
			if d := decodeAPKChecksum(ctx, line[2:]); d != "" {
				pkg.Digest = d
			}
		case "m:":
			pkg.Maintainer = line[2:]
		}

		if pkg.Name != "" && pkg.Version != "" {
			pkg.ID = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
			// A dependency may name either a package or a provide, so package
			// names are recorded as provides too.
			provides[pkg.Name] = pkg.ID
		}
	}
	if !pkg.Empty() {
		pkgs = append(pkgs, pkg)
	}

	pkgs = uniqueAPKPkgs(pkgs)
	resolveAPKDependencies(pkgs, provides)
	return pkgs, installedFiles
}

func parseAPKDependencies(line string) []string {
	var dependsOn []string
	for _, d := range strings.Fields(line) {
		// e.g. D:!uclibc-utils scanelf musl=1.1.14-r10 so:libc.musl-x86_64.so.1
		if strings.HasPrefix(d, "!") {
			continue
		}
		dependsOn = append(dependsOn, trimVersionRequirement(d))
	}
	return dependsOn
}

// resolveAPKDependencies replaces dependency names and provides with the IDs of
// the packages satisfying them, dropping the ones nothing installed provides.
func resolveAPKDependencies(pkgs []ftypes.Package, provides map[string]string) {
	for i := range pkgs {
		var resolved []string
		for _, d := range pkgs[i].DependsOn {
			if pkgID, ok := provides[d]; ok {
				resolved = append(resolved, pkgID)
			}
		}
		sort.Strings(resolved)
		resolved = slices.Compact(resolved)
		if len(resolved) == 0 {
			resolved = nil
		}
		pkgs[i].DependsOn = resolved
	}
}

func uniqueAPKPkgs(pkgs []ftypes.Package) []ftypes.Package {
	var uniqPkgs []ftypes.Package
	seen := make(map[string]struct{}, len(pkgs))
	for _, pkg := range pkgs {
		if _, ok := seen[pkg.Name]; ok {
			continue
		}
		seen[pkg.Name] = struct{}{}
		uniqPkgs = append(uniqPkgs, pkg)
	}
	return uniqPkgs
}

// decodeAPKChecksum decodes the base64 package checksum field.
// ref. https://wiki.alpinelinux.org/wiki/Apk_spec#Package_Checksum_Field
func decodeAPKChecksum(ctx context.Context, value string) digest.Digest {
	alg := digest.MD5
	if strings.HasPrefix(value, "Q1") {
		alg = digest.SHA1
		value = value[2:]
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		log.DebugContext(ctx, "Unable to decode digest", log.Err(err))
		return ""
	}
	return digest.NewDigestFromString(alg, hex.EncodeToString(decoded))
}
