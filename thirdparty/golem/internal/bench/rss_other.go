//go:build !unix

package bench

// readPeakRSSMB has no portable implementation outside unix; peak RSS is
// reported as zero rather than as a misleading heap figure.
func readPeakRSSMB() int64 { return 0 }
