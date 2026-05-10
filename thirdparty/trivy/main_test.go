package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
)

func TestExtractInstalledCommandsUsesExecutableBitsForRootfs(t *testing.T) {
	rootfs := t.TempDir()
	execPath := filepath.Join(rootfs, "usr", "bin", "bash")
	nonExecPath := filepath.Join(rootfs, "usr", "bin", "README")
	if err := os.MkdirAll(filepath.Dir(execPath), 0o755); err != nil {
		t.Fatalf("mkdir exec dir: %v", err)
	}
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write exec file: %v", err)
	}
	if err := os.WriteFile(nonExecPath, []byte("docs"), 0o644); err != nil {
		t.Fatalf("write non-exec file: %v", err)
	}

	paths, commands := extractInstalledCommands(rootfs, []string{"/usr/bin/bash", "/usr/bin/README", "/usr/share/doc/bash/README"})
	if len(paths) != 1 || paths[0] != "/usr/bin/bash" {
		t.Fatalf("unexpected command paths: %#v", paths)
	}
	if len(commands) != 1 || commands[0] != "bash" {
		t.Fatalf("unexpected commands: %#v", commands)
	}
}

func TestEnrichReportBOMAddsOSPackageMetadata(t *testing.T) {
	rootfs := t.TempDir()
	execPath := filepath.Join(rootfs, "usr", "bin", "bash")
	docPath := filepath.Join(rootfs, "usr", "share", "doc", "bash", "README")
	statusPath := filepath.Join(rootfs, "var", "lib", "dpkg", "status")
	if err := os.MkdirAll(filepath.Dir(execPath), 0o755); err != nil {
		t.Fatalf("mkdir exec dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(docPath), 0o755); err != nil {
		t.Fatalf("mkdir doc dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(statusPath), 0o755); err != nil {
		t.Fatalf("mkdir status dir: %v", err)
	}
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write exec file: %v", err)
	}
	if err := os.WriteFile(docPath, []byte("docs"), 0o644); err != nil {
		t.Fatalf("write doc file: %v", err)
	}
	if err := os.WriteFile(statusPath, []byte("Package: bash\nVersion: 1.0-1\nStatus: install ok installed\nArchitecture: amd64\nMaintainer: Debian Bash Maintainers <bash@example.test>\nSource: bash-src\nProvides: shell-interpreter\n\n"), 0o644); err != nil {
		t.Fatalf("write status file: %v", err)
	}

	report := trivytypes.Report{
		ArtifactName: "rootfs",
		ArtifactType: ftypes.TypeFilesystem,
		Metadata: trivytypes.Metadata{
			OS: &ftypes.OS{Family: ftypes.Debian, Name: "12", Extended: true},
		},
		Results: trivytypes.Results{
			{
				Target: "debian",
				Class:  trivytypes.ClassOSPkg,
				Type:   ftypes.TargetType("deb"),
				Packages: []ftypes.Package{
					{
						ID:             "bash@1.0",
						Name:           "bash",
						Version:        "1.0",
						InstalledFiles: []string{"/usr/bin/bash", "/usr/share/doc/bash/README"},
					},
				},
			},
		},
	}

	if err := enrichReportBOM(&report, rootfs, artifact.TargetRootfs, enrichmentOptions{
		includeCapabilities:   true,
		includeInstalledFiles: true,
		includeInstalledCmds:  true,
	}); err != nil {
		t.Fatalf("enrich report bom: %v", err)
	}
	if report.BOM == nil {
		t.Fatal("expected BOM to be generated")
	}

	pkgComponent := findComponentByProperty(report.BOM, core.PropertyPkgID, "bash@1.0")
	if pkgComponent == nil {
		t.Fatal("expected package component to be present")
	}
	assertHasProperty(t, pkgComponent.Properties, propertyInstalledFileCount, "2")
	assertHasProperty(t, pkgComponent.Properties, propertyInstalledCommandCount, "1")
	assertHasProperty(t, pkgComponent.Properties, propertyCapabilityCount, "1")
	assertHasProperty(t, pkgComponent.Properties, propertyCapability, "shell-interpreter")
	assertHasProperty(t, pkgComponent.Properties, propertyInstalledCommand, "bash")
	assertHasProperty(t, pkgComponent.Properties, propertyInstalledCommandPath, "/usr/bin/bash")
	assertHasProperty(t, pkgComponent.Properties, propertyInstalledFile, "/usr/share/doc/bash/README")
	assertHasProperty(t, pkgComponent.Properties, propertyPackageArchitecture, "amd64")
	assertHasProperty(t, pkgComponent.Properties, propertyPackageSource, "bash-src")
	assertHasProperty(t, pkgComponent.Properties, propertyPackageStatus, "install ok installed")
	if pkgComponent.Supplier != "Debian Bash Maintainers <bash@example.test>" {
		t.Fatalf("unexpected package supplier: %#v", pkgComponent.Supplier)
	}
	assertMissingProperty(t, pkgComponent.Properties, "PackageMaintainer")

	osComponent := findComponentByType(report.BOM, core.TypeOS)
	if osComponent == nil {
		t.Fatal("expected OS component to be present")
	}
	assertHasProperty(t, osComponent.Properties, propertyOSFamily, string(ftypes.Debian))
	assertHasProperty(t, osComponent.Properties, propertyOSName, "12")
	assertHasProperty(t, osComponent.Properties, propertyOSExtended, "true")
}

func TestParseAPKCapabilities(t *testing.T) {
	rootfs := t.TempDir()
	apkDbPath := filepath.Join(rootfs, "lib", "apk", "db", "installed")
	if err := os.MkdirAll(filepath.Dir(apkDbPath), 0o755); err != nil {
		t.Fatalf("mkdir apk db dir: %v", err)
	}
	content := strings.Join([]string{
		"P:busybox",
		"V:1.36.1-r2",
		"p:cmd:sh so:libc.musl-x86_64.so.1 busybox=1.36.1-r2",
		"",
	}, "\n")
	if err := os.WriteFile(apkDbPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write apk db: %v", err)
	}
	capabilities := parseAPKCapabilities(rootfs)
	if got := capabilities["busybox@1.36.1-r2"]; len(got) != 2 || got[0] != "cmd:sh" || got[1] != "so:libc.musl-x86_64.so.1" {
		t.Fatalf("unexpected apk capabilities: %#v", got)
	}
}

func TestParseDPKGCapabilities(t *testing.T) {
	rootfs := t.TempDir()
	statusPath := filepath.Join(rootfs, "var", "lib", "dpkg", "status")
	if err := os.MkdirAll(filepath.Dir(statusPath), 0o755); err != nil {
		t.Fatalf("mkdir status dir: %v", err)
	}
	content := strings.Join([]string{
		"Package: mawk",
		"Version: 1.3.4.20240123-1",
		"Status: install ok installed",
		"Provides: awk, editor | text-editor (>= 1)",
		"",
	}, "\n")
	if err := os.WriteFile(statusPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write status file: %v", err)
	}
	capabilities := parseDPKGCapabilities(rootfs)
	got := capabilities["mawk@1.3.4.20240123"]
	if len(got) != 3 || got[0] != "awk" || got[1] != "editor" || got[2] != "text-editor" {
		t.Fatalf("unexpected dpkg capabilities: %#v", got)
	}
}

func TestParseDPKGPackageTrust(t *testing.T) {
	rootfs := t.TempDir()
	statusPath := filepath.Join(rootfs, "var", "lib", "dpkg", "status")
	if err := os.MkdirAll(filepath.Dir(statusPath), 0o755); err != nil {
		t.Fatalf("mkdir status dir: %v", err)
	}
	content := strings.Join([]string{
		"Package: mawk",
		"Version: 1.3.4.20240123-1",
		"Status: install ok installed",
		"Architecture: amd64",
		"Maintainer: Debian QA Group <packages@example.test>",
		"Origin: Debian",
		"Source: mawk-src",
		"",
	}, "\n")
	if err := os.WriteFile(statusPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write status file: %v", err)
	}
	trustMetadata := parseDPKGPackageTrust(rootfs)["mawk@1.3.4.20240123"]
	if trustMetadata.architecture != "amd64" || trustMetadata.maintainer != "Debian QA Group <packages@example.test>" || trustMetadata.origin != "Debian" || trustMetadata.source != "mawk-src" || trustMetadata.status != "install ok installed" {
		t.Fatalf("unexpected dpkg trust metadata: %#v", trustMetadata)
	}
}

func TestParseAPKPackageTrust(t *testing.T) {
	rootfs := t.TempDir()
	apkDbPath := filepath.Join(rootfs, "lib", "apk", "db", "installed")
	if err := os.MkdirAll(filepath.Dir(apkDbPath), 0o755); err != nil {
		t.Fatalf("mkdir apk db dir: %v", err)
	}
	content := strings.Join([]string{
		"P:busybox",
		"V:1.36.1-r2",
		"A:x86_64",
		"m:Busybox Maintainers <busybox@example.test>",
		"o:busybox",
		"S:busybox-src",
		"s:trusted",
		"",
	}, "\n")
	if err := os.WriteFile(apkDbPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write apk db: %v", err)
	}
	trustMetadata := parseAPKPackageTrust(rootfs)["busybox@1.36.1-r2"]
	if trustMetadata.architecture != "x86_64" || trustMetadata.maintainer != "Busybox Maintainers <busybox@example.test>" || trustMetadata.origin != "busybox" || trustMetadata.source != "busybox-src" || trustMetadata.status != "trusted" {
		t.Fatalf("unexpected apk trust metadata: %#v", trustMetadata)
	}
}

func findComponentByProperty(bom *core.BOM, name, value string) *core.Component {
	for _, component := range bom.Components() {
		for _, property := range component.Properties {
			if property.Name == name && property.Value == value {
				return component
			}
		}
	}
	return nil
}

func findComponentByType(bom *core.BOM, componentType core.ComponentType) *core.Component {
	for _, component := range bom.Components() {
		if component.Type == componentType {
			return component
		}
	}
	return nil
}

func assertHasProperty(t *testing.T, properties core.Properties, name, value string) {
	t.Helper()
	for _, property := range properties {
		if property.Name == name && property.Value == value {
			return
		}
	}
	t.Fatalf("missing property %s=%s in %#v", name, value, properties)
}

func assertMissingProperty(t *testing.T, properties core.Properties, name string) {
	t.Helper()
	for _, property := range properties {
		if property.Name == name {
			t.Fatalf("unexpected property %s in %#v", name, properties)
		}
	}
}
