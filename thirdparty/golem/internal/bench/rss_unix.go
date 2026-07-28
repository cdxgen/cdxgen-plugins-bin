//go:build unix

package bench

import "syscall"

// readPeakRSSMB returns the process high-water resident set size in MiB.
//
// This is the maximum for the whole process, so within one run it is monotonic
// and results reflect the largest fixture measured so far rather than each
// fixture in isolation. That is still far more useful than reporting the Go
// heap's current allocation, which says nothing about the memory a user needs.
func readPeakRSSMB() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return int64(usage.Maxrss) / rssDivisor
}
