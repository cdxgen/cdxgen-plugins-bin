//go:build unix && !darwin && !linux

package bench

// The BSDs report ru_maxrss in kilobytes.
const rssDivisor = 1024
