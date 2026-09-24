package main

// The analyzers and post handlers the wrapper registers.
//
// Upstream registers every analyzer through pkg/fanal/analyzer/all, which the
// local scan service imports. Most of them never run here: applyCDXGenDefaults
// and the runner disable secret, license-file, misconfiguration, executable
// and image-history analysis, and keep only the Go binary analyzer among the
// language analyzers. Registering only the analyzers that can be enabled keeps
// the others, and the scanners they pull in, out of the binary.
// TestEnabledAnalyzersMatchUpstream pins this list against the analyzers
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

	// Of the two post handlers, only the system file filter can act: the
	// unpackaged handler looks up executable digests in Rekor, and the
	// executable analyzer that produces them is disabled.
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)
