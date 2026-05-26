package analyzer

import (
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const defaultProgressInterval = 5 * time.Second

type progressLogger struct {
	enabled  bool
	writer   io.Writer
	interval time.Duration
	start    time.Time
	last     time.Time
}

type runtimeLimitState struct {
	previousProcs       int
	previousMemoryLimit int64
	memoryLimitChanged  bool
}

func newProgressLogger(options Options) *progressLogger {
	interval := options.ProgressInterval
	if interval <= 0 {
		interval = defaultProgressInterval
	}
	writer := options.ProgressWriter
	if writer == nil {
		writer = os.Stderr
	}
	now := time.Now()
	return &progressLogger{enabled: options.Progress, writer: writer, interval: interval, start: now, last: now}
}

func (p *progressLogger) Logf(format string, args ...any) {
	if p == nil || !p.enabled || p.writer == nil {
		return
	}
	p.last = time.Now()
	_, _ = fmt.Fprintf(p.writer, "golem: "+format+"\n", args...)
}

func (p *progressLogger) MaybeLogf(format string, args ...any) {
	if p == nil || !p.enabled || p.writer == nil {
		return
	}
	if time.Since(p.last) < p.interval {
		return
	}
	p.Logf(format, args...)
}

func (p *progressLogger) Memoryf(format string, args ...any) {
	if p == nil || !p.enabled || p.writer == nil {
		return
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	msg := fmt.Sprintf(format, args...)
	p.Logf("%s (alloc=%s heap=%s sys=%s elapsed=%s)", msg, formatBytes(int64(m.Alloc)), formatBytes(int64(m.HeapInuse)), formatBytes(int64(m.Sys)), time.Since(p.start).Round(time.Millisecond))
}

func normalizePerformanceOptions(options *Options) {
	if options.MaxProcs < 0 {
		options.MaxProcs = 0
	}
	if options.DataFlowWorkers < 0 {
		options.DataFlowWorkers = 0
	}
	if options.DataFlowLargeRepoFunctions < 0 {
		options.DataFlowLargeRepoFunctions = 0
	}
	if options.DataFlowMaxFunctionInstructions < 0 {
		options.DataFlowMaxFunctionInstructions = 0
	}
	if options.DataFlowMaxTraceNodes < 0 {
		options.DataFlowMaxTraceNodes = 0
	}
	if options.DataFlowMaxTraceEdges < 0 {
		options.DataFlowMaxTraceEdges = 0
	}
	if options.ProgressInterval <= 0 {
		options.ProgressInterval = defaultProgressInterval
	}
}

func applyRuntimeLimits(options Options) runtimeLimitState {
	state := runtimeLimitState{previousProcs: runtime.GOMAXPROCS(0)}
	procs := options.MaxProcs
	if procs == 0 {
		procs = runtime.NumCPU()
	}
	if procs > 0 {
		runtime.GOMAXPROCS(procs)
	}
	if options.MemoryLimit > 0 {
		state.previousMemoryLimit = debug.SetMemoryLimit(options.MemoryLimit)
		state.memoryLimitChanged = true
	}
	return state
}

func restoreRuntimeLimits(state runtimeLimitState) {
	runtime.GOMAXPROCS(state.previousProcs)
	if state.memoryLimitChanged {
		debug.SetMemoryLimit(state.previousMemoryLimit)
	}
}

func dataFlowWorkerCount(options Options, total int) int {
	workers := options.DataFlowWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}
	if total > 0 && workers > total {
		workers = total
	}
	return workers
}

func ParseByteSize(value string) (int64, error) {
	text := strings.TrimSpace(value)
	if text == "" || text == "0" {
		return 0, nil
	}
	text = strings.ReplaceAll(text, "_", "")
	lower := strings.ToLower(text)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"gib", 1 << 30}, {"gb", 1000 * 1000 * 1000}, {"g", 1 << 30},
		{"mib", 1 << 20}, {"mb", 1000 * 1000}, {"m", 1 << 20},
		{"kib", 1 << 10}, {"kb", 1000}, {"k", 1 << 10},
		{"b", 1},
	}
	mult := int64(1)
	for _, unit := range units {
		if strings.HasSuffix(lower, unit.suffix) {
			mult = unit.mult
			lower = strings.TrimSpace(strings.TrimSuffix(lower, unit.suffix))
			break
		}
	}
	if lower == "" {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}
	n, err := strconv.ParseFloat(lower, 64)
	if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}
	bytes := n * float64(mult)
	if math.IsInf(bytes, 0) || bytes >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}
	return int64(bytes), nil
}

func formatBytes(n int64) string {
	if n < 0 {
		return "unknown"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit && exp < 4; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
