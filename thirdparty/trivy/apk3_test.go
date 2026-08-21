package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/package-url/packageurl-go"
)

func analysisInput(filePath, content string) analyzer.AnalysisInput {
	return analyzer.AnalysisInput{
		FilePath: filePath,
		Content:  strings.NewReader(content),
	}
}

const apk3InstalledDBFixture = `C:Q1ZsZhf8Z2Wia3nVtv4nnCaAvFcnU=
P:musl
V:1.2.5-r10
A:aarch64
L:MIT
o:musl
m:BellSoft <info@bell-sw.com>
p:so:libc.musl-aarch64.so.1=1
F:lib
R:libc.musl-aarch64.so.1

P:busybox
V:1.38.0-r2
A:aarch64
L:GPL-2.0-only
o:busybox
D:so:libc.musl-aarch64.so.1 !busybox-extras
p:cmd:sh
F:bin
R:busybox
`

func TestAPK3AnalyzerParsesApkToolsThreeDatabase(t *testing.T) {
	result, err := apk3PkgAnalyzer{}.Analyze(context.Background(), analysisInput(apk3InstalledDatabasePath, apk3InstalledDBFixture))
	if err != nil {
		t.Fatalf("analyze apk3 db: %v", err)
	}
	if len(result.PackageInfos) != 1 {
		t.Fatalf("unexpected package infos: %#v", result.PackageInfos)
	}
	if got := result.PackageInfos[0].FilePath; got != apk3InstalledDatabasePath {
		t.Fatalf("unexpected file path: %s", got)
	}
	pkgs := result.PackageInfos[0].Packages
	if len(pkgs) != 2 {
		t.Fatalf("unexpected packages: %#v", pkgs)
	}

	musl := pkgs[0]
	if musl.ID != "musl@1.2.5-r10" || musl.Name != "musl" || musl.Version != "1.2.5-r10" {
		t.Fatalf("unexpected musl identity: %#v", musl)
	}
	if musl.Arch != "aarch64" || musl.SrcName != "musl" || musl.SrcVersion != "1.2.5-r10" {
		t.Fatalf("unexpected musl metadata: %#v", musl)
	}
	if musl.Maintainer != "BellSoft <info@bell-sw.com>" {
		t.Fatalf("unexpected musl maintainer: %s", musl.Maintainer)
	}
	if !slices.Equal(musl.Licenses, []string{"MIT"}) {
		t.Fatalf("unexpected musl licenses: %#v", musl.Licenses)
	}
	if !slices.Equal(musl.InstalledFiles, []string{"lib/libc.musl-aarch64.so.1"}) {
		t.Fatalf("unexpected musl installed files: %#v", musl.InstalledFiles)
	}
	if musl.Digest == "" || !strings.HasPrefix(string(musl.Digest), "sha1:") {
		t.Fatalf("unexpected musl digest: %s", musl.Digest)
	}

	busybox := pkgs[1]
	// so:libc.musl-aarch64.so.1 resolves to the package providing it, while the
	// negated busybox-extras dependency is dropped.
	if !slices.Equal(busybox.DependsOn, []string{"musl@1.2.5-r10"}) {
		t.Fatalf("unexpected busybox dependencies: %#v", busybox.DependsOn)
	}

	if !slices.Equal(result.SystemInstalledFiles, []string{"lib/libc.musl-aarch64.so.1", "bin/busybox"}) {
		t.Fatalf("unexpected system installed files: %#v", result.SystemInstalledFiles)
	}
}

func TestAPK3AnalyzerRequiresOnlyTheApkToolsThreePath(t *testing.T) {
	analyzer := apk3PkgAnalyzer{}
	if !analyzer.Required(apk3InstalledDatabasePath, nil) {
		t.Fatalf("expected %s to be required", apk3InstalledDatabasePath)
	}
	// The apk-tools 2.x paths stay with Trivy's own analyzer, so the database is
	// never parsed twice.
	for _, filePath := range []string{"lib/apk/db/installed", "usr/lib/apk/db/installed"} {
		if analyzer.Required(filePath, nil) {
			t.Fatalf("expected %s not to be required", filePath)
		}
	}
}

func TestAlpaquitaOSAnalyzerDetectsReleaseChannel(t *testing.T) {
	result, err := alpaquitaOSAnalyzer{}.Analyze(context.Background(), analysisInput(alpaquitaReleaseFile, "stream\n"))
	if err != nil {
		t.Fatalf("analyze alpaquita release: %v", err)
	}
	if result.OS.Family != osFamilyAlpaquita || result.OS.Name != "stream" {
		t.Fatalf("unexpected OS: %#v", result.OS)
	}
}

func TestAlpaquitaOSAnalyzerIgnoresEmptyReleaseFile(t *testing.T) {
	result, err := alpaquitaOSAnalyzer{}.Analyze(context.Background(), analysisInput(alpaquitaReleaseFile, "\n"))
	if err != nil {
		t.Fatalf("analyze alpaquita release: %v", err)
	}
	if result != nil {
		t.Fatalf("unexpected analysis result: %#v", result)
	}
}

func TestNormalizeAlpaquitaPurlRewritesToApkType(t *testing.T) {
	purl := &packageurl.PackageURL{
		Type:       string(osFamilyAlpaquita),
		Name:       "busybox",
		Version:    "1.38.0-r2",
		Qualifiers: packageurl.Qualifiers{{Key: "arch", Value: "aarch64"}},
	}
	component := &core.Component{
		Name: "busybox",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL:   purl,
			BOMRef: purl.String(),
		},
	}

	normalizeAlpaquitaPurl(component, "stream")

	want := "pkg:apk/alpaquita/busybox@1.38.0-r2?arch=aarch64&distro=alpaquita-stream"
	if got := purl.String(); got != want {
		t.Fatalf("unexpected purl: %s", got)
	}
	if component.PkgIdentifier.BOMRef != want {
		t.Fatalf("unexpected bom-ref: %s", component.PkgIdentifier.BOMRef)
	}
	if component.Group != string(osFamilyAlpaquita) {
		t.Fatalf("unexpected group: %s", component.Group)
	}
}

func TestNormalizeAlpaquitaPurlLeavesOtherTypesAlone(t *testing.T) {
	purl := &packageurl.PackageURL{
		Type:      packageurl.TypeApk,
		Namespace: "alpine",
		Name:      "busybox",
		Version:   "1.37.0-r0",
	}
	component := &core.Component{PkgIdentifier: ftypes.PkgIdentifier{PURL: purl, BOMRef: purl.String()}}

	normalizeAlpaquitaPurl(component, "3.22.5")

	if got := purl.String(); got != "pkg:apk/alpine/busybox@1.37.0-r0" {
		t.Fatalf("unexpected purl: %s", got)
	}
}

func TestParseAPKCapabilitiesReadsApkToolsThreeDatabase(t *testing.T) {
	rootfs := t.TempDir()
	apkDBPath := filepath.Join(rootfs, "var", "lib", "apk", "db", "installed")
	if err := os.MkdirAll(filepath.Dir(apkDBPath), 0o755); err != nil {
		t.Fatalf("mkdir apk db dir: %v", err)
	}
	if err := os.WriteFile(apkDBPath, []byte(apk3InstalledDBFixture), 0o644); err != nil {
		t.Fatalf("write apk db: %v", err)
	}

	capabilities := parseAPKCapabilities(rootfs)
	if got := capabilities["busybox@1.38.0-r2"]; !slices.Equal(got, []string{"cmd:sh"}) {
		t.Fatalf("unexpected apk capabilities: %#v", got)
	}

	trustMetadata := parseAPKPackageTrust(rootfs)
	if got := trustMetadata["musl@1.2.5-r10"]; got.architecture != "aarch64" || got.maintainer != "BellSoft <info@bell-sw.com>" {
		t.Fatalf("unexpected apk trust metadata: %#v", got)
	}
}
