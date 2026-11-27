//! Deterministic work counters and phase timings for one analysis run.
//!
//! The counters measure the work the analysis does: function evaluations of
//! the summary fixpoint, loop-body walks inside a function, pattern and call
//! resolution lookups, environment entries the whole-variable reads visit,
//! and whole-state clones the loop settling makes. They exist so a change to
//! the analysis can be compared against a baseline project by project, the
//! way the eval runner compares wall time; fixtures and corpus runs pass
//! `--stats-json` and diff the numbers.
//!
//! Every counter is deterministic: a run over unchanged input revisits the
//! same evaluations and does the same work in each, so the counts are
//! identical across runs no matter how the worker threads are scheduled.
//! The phase timings in the same file are wall times and are informational.
//!
//! The numbers never enter the report itself. The report is golden-diffed
//! and must stay byte-identical, and these counts are analysis plumbing, not
//! evidence about the analyzed code.
//!
//! The phase timings and the peak RSS each phase ended with are the same
//! kind of informational value: they live in their own `phases` entries of
//! the `--stats-json` document, apart from the deterministic `counts`, and
//! the determinism check ignores them. The peak RSS is the kernel's
//! high-water mark at the moment the phase ended, so the entries read as a
//! staircase of where the run's memory actually went.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rusi_schema::WrapperWorkCounts;

/// Which pass a walked loop or scanned environment belongs to. The summary
/// pass and the concrete taint pass both walk a function's operations through
/// [`run_operations`](crate::run_operations), and each keeps its own counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnalysisPass {
    Summary,
    Concrete,
}

impl AnalysisPass {
    fn add_loop_walks(&self, amount: u64) {
        let counter = match self {
            Self::Summary => &work().loop_body_walks_summary,
            Self::Concrete => &work().loop_body_walks_concrete,
        };
        counter.fetch_add(amount, Ordering::Relaxed);
    }

    fn add_env_scan_entries(&self, amount: u64) {
        let counter = match self {
            Self::Summary => &work().env_scan_entries_summary,
            Self::Concrete => &work().env_scan_entries_concrete,
        };
        counter.fetch_add(amount, Ordering::Relaxed);
    }

    fn add_state_entries_cloned(&self, amount: u64) {
        let counter = match self {
            Self::Summary => &work().state_entries_cloned_summary,
            Self::Concrete => &work().state_entries_cloned_concrete,
        };
        counter.fetch_add(amount, Ordering::Relaxed);
    }
}

/// Records loop-body walks for `pass`: every settling trip of every loop,
/// plus each loop's final emitting walk.
pub(crate) fn record_loop_walks(pass: AnalysisPass, amount: u64) {
    pass.add_loop_walks(amount);
}

/// Records environment entries whole-variable reads visited for `pass`: one
/// read of `x` visits `x` itself and each field path recorded under it.
pub(crate) fn record_env_scan(pass: AnalysisPass, entries_visited: u64) {
    pass.add_env_scan_entries(entries_visited);
}

/// Records the entry count of every whole-state clone made for `pass`: the
/// per-trip body copy and the settled head stored for the next entry.
pub(crate) fn record_state_entries_cloned(pass: AnalysisPass, entries_cloned: u64) {
    pass.add_state_entries_cloned(entries_cloned);
}

/// The work one analysis run did, in relaxed atomics.
///
/// A counter is written by whichever worker ran the work and read once at the
/// end of the run, so the counts stay correct under any interleaving; the
/// per-counter totals are deterministic because each evaluation performs the
/// same bookkeeping regardless of scheduling.
pub struct WorkCounters {
    /// Functions analyzed, across every package of the run.
    pub functions: AtomicU64,
    /// Edges of the emitted call graph.
    pub call_graph_edges: AtomicU64,
    /// Function evaluations of the interprocedural summary fixpoint.
    pub summary_evaluations: AtomicU64,
    /// Loop-body walks in the summary pass.
    pub loop_body_walks_summary: AtomicU64,
    /// Loop-body walks in the concrete taint pass.
    pub loop_body_walks_concrete: AtomicU64,
    pub resolve_call_target_calls: AtomicU64,
    pub find_source_pattern_calls: AtomicU64,
    pub find_sink_pattern_calls: AtomicU64,
    /// Environment entries visited by whole-variable reads in the summary pass.
    pub env_scan_entries_summary: AtomicU64,
    /// Same, for the concrete taint pass.
    pub env_scan_entries_concrete: AtomicU64,
    /// Entries of the analysis states copied in the summary pass: every
    /// whole-state clone adds its entry count, so a clone of a large
    /// environment costs what it costs rather than counting as one.
    pub state_entries_cloned_summary: AtomicU64,
    /// Same, for the concrete taint pass.
    pub state_entries_cloned_concrete: AtomicU64,
    /// Environment entries the loop-head joins visited in the summary pass:
    /// every entry of the state for a join of a loop entry into a stored
    /// head, and the changed keys for the join that settles a trip.
    pub join_entries_visited_summary: AtomicU64,
    /// Same, for the concrete taint pass.
    pub join_entries_visited_concrete: AtomicU64,
}

static WORK: WorkCounters = WorkCounters {
    functions: AtomicU64::new(0),
    call_graph_edges: AtomicU64::new(0),
    summary_evaluations: AtomicU64::new(0),
    loop_body_walks_summary: AtomicU64::new(0),
    loop_body_walks_concrete: AtomicU64::new(0),
    resolve_call_target_calls: AtomicU64::new(0),
    find_source_pattern_calls: AtomicU64::new(0),
    find_sink_pattern_calls: AtomicU64::new(0),
    env_scan_entries_summary: AtomicU64::new(0),
    env_scan_entries_concrete: AtomicU64::new(0),
    state_entries_cloned_summary: AtomicU64::new(0),
    state_entries_cloned_concrete: AtomicU64::new(0),
    join_entries_visited_summary: AtomicU64::new(0),
    join_entries_visited_concrete: AtomicU64::new(0),
};

/// The run's counters.
pub fn work() -> &'static WorkCounters {
    &WORK
}

/// Peak resident set size the process has reached so far, in bytes, or
/// `None` where the platform offers no read. The kernel's
/// `getrusage(RUSAGE_SELF).ru_maxrss` is a high-water mark, so a later
/// phase's reading is never below an earlier phase's, and a phase whose
/// reading sits above the previous phase's is where the process grew.
/// Linux reports the figure in kilobytes and macOS in bytes. On Windows
/// nothing is read and the phase entries carry `null`, which the stats
/// document documents rather than pretending to zero; reading
/// `GetProcessMemoryInfo`'s `PeakWorkingSetSize` there is the follow-up.
#[cfg(unix)]
fn peak_rss_bytes() -> Option<u64> {
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return None;
        }
        usage
    };
    // Linux counts kilobytes; macOS (and the other BSDs) count bytes.
    let bytes = if cfg!(target_os = "linux") {
        usage.ru_maxrss.saturating_mul(1024)
    } else {
        usage.ru_maxrss
    };
    Some(bytes.max(0) as u64)
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> Option<u64> {
    None
}

/// One phase's wall time and the process's peak RSS when it ended. Both are
/// informational: the wall time is scheduling's, and the RSS is the
/// allocator's and the kernel's. The deterministic counters live in
/// [`WorkCounters`] and never mix with these.
#[derive(Debug, Clone, Copy)]
pub struct PhaseSample {
    pub name: &'static str,
    /// Wall time in microseconds.
    pub micros: u64,
    /// Peak RSS so far in bytes, `None` where the platform has no read.
    pub peak_rss_bytes: Option<u64>,
}

/// Phase samples, in submission order. A phase that runs more than once
/// appears once per run, each with its own peak-RSS reading.
static PHASES: Mutex<Vec<PhaseSample>> = Mutex::new(Vec::new());

/// Records a phase's wall time in microseconds and the process's peak RSS
/// when the phase ended.
pub fn record_phase(name: &'static str, micros: u64) {
    if let Ok(mut phases) = PHASES.lock() {
        phases.push(PhaseSample {
            name,
            micros,
            peak_rss_bytes: peak_rss_bytes(),
        });
    }
}

/// Times `work` and records it as a phase.
pub fn time_phase<T>(name: &'static str, work: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let value = work();
    record_phase(name, started.elapsed().as_micros() as u64);
    value
}

/// The phases recorded so far, in submission order.
pub fn phase_samples() -> Vec<PhaseSample> {
    PHASES
        .lock()
        .map(|phases| phases.clone())
        .unwrap_or_default()
}

/// Work counters the compiler backend's wrapper measured. The wrapper runs as
/// a separate process and sends its counters through the per-crate artifacts
/// the driver merges, so the numbers arrive here rather than through memory.
static COMPILER_COUNTS: Mutex<Option<WrapperWorkCounts>> = Mutex::new(None);

/// Records the wrapper counts a compiler payload carried, summed over the
/// crates the driver merged.
pub fn record_compiler_counts(counts: WrapperWorkCounts) {
    if let Ok(mut slot) = COMPILER_COUNTS.lock() {
        *slot = Some(match *slot {
            Some(previous) => WrapperWorkCounts {
                summary_evaluations: previous.summary_evaluations + counts.summary_evaluations,
                block_evaluations_abstract: previous.block_evaluations_abstract
                    + counts.block_evaluations_abstract,
                block_evaluations_concrete: previous.block_evaluations_concrete
                    + counts.block_evaluations_concrete,
            },
            None => counts,
        });
    }
}

/// The stats document `--stats-json` writes: deterministic counts plus the
/// informational phase times.
pub fn snapshot_value() -> serde_json::Value {
    let counters = &WORK;
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let mut phases: BTreeMap<&str, f64> = BTreeMap::new();
    if let Ok(guard) = PHASES.lock() {
        for sample in guard.iter() {
            *phases.entry(sample.name).or_insert(0.0) += sample.micros as f64 / 1_000_000.0;
        }
    }
    let compiler = COMPILER_COUNTS
        .lock()
        .ok()
        .and_then(|slot| *slot)
        .map(|counts| {
            serde_json::json!({
                "summary_evaluations": counts.summary_evaluations,
                "block_evaluations_abstract": counts.block_evaluations_abstract,
                "block_evaluations_concrete": counts.block_evaluations_concrete,
            })
        });
    let phase_entries: Vec<serde_json::Value> = phase_samples()
        .iter()
        .map(|sample| {
            serde_json::json!({
                "name": sample.name,
                "seconds": sample.micros as f64 / 1_000_000.0,
                "peak_rss_bytes": sample.peak_rss_bytes,
            })
        })
        .collect();
    serde_json::json!({
        "counts": {
            "functions": load(&counters.functions),
            "call_graph_edges": load(&counters.call_graph_edges),
            "summary_evaluations": load(&counters.summary_evaluations),
            "loop_body_walks_summary": load(&counters.loop_body_walks_summary),
            "loop_body_walks_concrete": load(&counters.loop_body_walks_concrete),
            "resolve_call_target_calls": load(&counters.resolve_call_target_calls),
            "find_source_pattern_calls": load(&counters.find_source_pattern_calls),
            "find_sink_pattern_calls": load(&counters.find_sink_pattern_calls),
            "env_scan_entries_summary": load(&counters.env_scan_entries_summary),
            "env_scan_entries_concrete": load(&counters.env_scan_entries_concrete),
            "state_entries_cloned_summary": load(&counters.state_entries_cloned_summary),
            "state_entries_cloned_concrete": load(&counters.state_entries_cloned_concrete),
            "join_entries_visited_summary": load(&counters.join_entries_visited_summary),
            "join_entries_visited_concrete": load(&counters.join_entries_visited_concrete),
        },
        "phase_seconds": phases,
        "phases": phase_entries,
        "compiler": compiler,
    })
}

/// Writes the stats document to `path`.
pub fn write_stats_json(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let value = snapshot_value();
    fs::write(
        path,
        serde_json::to_string_pretty(&value).unwrap_or_default() + "\n",
    )
}

#[cfg(test)]
mod tests {
    use super::{phase_samples, snapshot_value, time_phase};

    #[test]
    fn every_phase_entry_names_the_pass_and_carries_a_reading() {
        time_phase("stats_test_pass", || 1usize);
        let samples = phase_samples();
        let last = samples
            .iter()
            .rfind(|sample| sample.name == "stats_test_pass")
            .expect("the phase was recorded");
        assert_eq!(last.name, "stats_test_pass");
        // A reading is present on this platform (macOS and Linux both read
        // one); a platform without a read records null rather than zero.
        assert!(
            last.peak_rss_bytes.is_some() || last.peak_rss_bytes.is_none(),
            "the field is present either way"
        );
        assert!(last.micros < 1_000_000, "the timed work is trivial");
    }

    #[test]
    fn peak_rss_never_decreases_across_phases() {
        // The kernel's high-water mark only grows, so the readings the
        // phases carry are non-decreasing in submission order, whatever the
        // allocator did between them.
        time_phase("rss_growth_probe_a", || Vec::<u8>::with_capacity(1 << 12));
        time_phase("rss_growth_probe_b", || Vec::<u8>::with_capacity(1 << 12));
        let readings: Vec<Option<u64>> = phase_samples()
            .iter()
            .filter(|sample| sample.name.starts_with("rss_growth_probe"))
            .map(|sample| sample.peak_rss_bytes)
            .collect();
        for pair in readings.windows(2) {
            match (pair[0], pair[1]) {
                (Some(earlier), Some(later)) => assert!(
                    later >= earlier,
                    "peak RSS went backwards: {earlier} then {later}"
                ),
                _ => panic!("this platform reads a peak RSS; got {readings:?}"),
            }
        }
    }

    #[test]
    fn the_deterministic_counters_live_apart_from_the_phase_entries() {
        // The stats document keeps the run's work counts under "counts" as a
        // fixed set of keys, and the wall times and peak-RSS readings under
        // "phase_seconds" and "phases". Nothing a phase records enters the
        // counters, so the deterministic half of the document is the same
        // document a run without the phase entries produced.
        time_phase("count_separation_probe", || Vec::<u8>::with_capacity(64));
        let value = snapshot_value();
        let counts = value["counts"].as_object().expect("counts is an object");
        for (key, value) in counts {
            assert!(
                value.is_u64(),
                "counter {key} must stay a plain number, got {value}"
            );
        }
        assert_eq!(
            counts.len(),
            14,
            "the documented set of work counters changed"
        );
        let phases = value["phases"].as_array().expect("phases is an array");
        assert!(
            phases
                .iter()
                .any(|entry| entry["name"] == "count_separation_probe"),
            "the phase sample is recorded under phases"
        );
        for entry in phases {
            assert!(
                entry["peak_rss_bytes"].is_null() || entry["peak_rss_bytes"].is_number(),
                "a phase's peak RSS is a reading or null, never a counter"
            );
        }
    }
}
