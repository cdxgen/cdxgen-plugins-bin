package main

// The analyzers and post handlers the wrapper registers.
//
// Upstream registers every analyzer through pkg/fanal/analyzer/all, which the
// local scan service imports. Most of them never run here: applyCDXGenDefaults
// and the runner disable secret, license-file, misconfiguration, executable and
// image-history analysis, and rootfs scans keep only the Go binary analyzer
// among the language analyzers. Registering only the analyzers that can be
// enabled keeps the others, and the scanners they pull in, out of the binary.
// TestRegisteredAnalyzersMatchUpstream pins this list against the analyzers
// upstream would enable for the same options.

import (
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/buildinfo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/release"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/bottlerocket_inventory"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/rpm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/rapidfort"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/repo/apk"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"

	// Image scans inherit Trivy's image defaults, which disable only the lock
	// file analyzers, so the individual package analyzers stay enabled there.
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/conda/meta"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/deps"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/nuget"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/packagesprops"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/jar"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/julia/pkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/packaging"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/gemspec"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/cargo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/sbom"

	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)
