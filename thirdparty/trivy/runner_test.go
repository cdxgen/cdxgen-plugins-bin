package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/flag"
)

// wantEnabledAnalyzers is every analyzer and post analyzer cdxgen's options
// leave enabled on a rootfs scan. `make test` checks it twice: against
// upstream Trivy, whose pkg/fanal/analyzer/all registers every analyzer, and
// against the patched build, which registers only analyzers.go. Passing both
// means analyzers.go registers exactly what upstream would run. When a Trivy
// upgrade changes the upstream set, add the new analyzer to analyzers.go and
// here.
var wantEnabledAnalyzers = []string{
	// The wrapper's own apk-tools 3.x and Alpaquita analyzers.
	"alpaquita-libc", "alpaquita-os", "apk3-pkg",
	"alma", "alpine", "amazon", "apk", "apk-repo", "bottlerocket-inventory",
	"centos", "debian", "dpkg", "dpkg-license", "fedora", "gobinary", "oracle",
	"os-release", "rapidfort-curated", "redhat", "redhat-content-manifest",
	"redhat-dockerfile", "rocky", "rpm", "rpmqa", "ubuntu", "ubuntu-esm",
}

func TestEnabledAnalyzersMatchUpstream(t *testing.T) {
	var opts flag.Options
	applyCDXGenDefaults(&opts)
	opts.DisabledAnalyzers = rootfsDisabledAnalyzers(opts)
	group, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		DisabledAnalyzers: disabledAnalyzers(opts),
	})
	if err != nil {
		t.Fatal(err)
	}
	versions := group.AnalyzerVersions()
	var got []string
	for name := range versions.Analyzers {
		got = append(got, name)
	}
	for name := range versions.PostAnalyzers {
		got = append(got, name)
	}
	slices.Sort(got)
	want := slices.Sorted(slices.Values(wantEnabledAnalyzers))
	if !slices.Equal(got, want) {
		t.Errorf("enabled analyzers differ\n got: %s\nwant: %s", strings.Join(got, " "), strings.Join(want, " "))
	}
}

func TestCheckSupportedModesRejectsUnlinkedPaths(t *testing.T) {
	for name, opts := range map[string]flag.Options{
		"server":       {RemoteOptions: flag.RemoteOptions{ServerAddr: "http://localhost:4954"}},
		"redis":        {CacheOptions: flag.CacheOptions{CacheBackend: "redis://localhost:6379"}},
		"sbom sources": {ScanOptions: flag.ScanOptions{SBOMSources: []string{"oci"}}},
		"plugin":       {ReportOptions: flag.ReportOptions{Output: "plugin=scp"}},
		"java db only": {DBOptions: flag.DBOptions{DownloadJavaDBOnly: true}},
	} {
		if err := checkSupportedModes(opts); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := checkSupportedModes(flag.Options{CacheOptions: flag.CacheOptions{CacheBackend: "fs"}}); err != nil {
		t.Errorf("fs cache: %v", err)
	}
}
