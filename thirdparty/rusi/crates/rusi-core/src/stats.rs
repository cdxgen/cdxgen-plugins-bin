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

    fn add_state_clones(&self, amount: u64) {
        let counter = match self {
            Self::Summary => &work().state_clones_summary,
            Self::Concrete => &work().state_clones_concrete,
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
/// read of `x` scans the environment for keys starting `x.`, so a scan over
/// an environment of `n` entries adds `n`.
pub(crate) fn record_env_scan(pass: AnalysisPass, entries_visited: u64) {
    pass.add_env_scan_entries(entries_visited);
}

/// Records whole analysis states cloned for `pass`: the per-trip body copy, the
/// emitting body copy, and the settled head stored for the next entry.
pub(crate) fn record_state_clones(pass: AnalysisPass, amount: u64) {
    pass.add_state_clones(amount);
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
    /// Whole analysis states cloned in the summary pass.
    pub state_clones_summary: AtomicU64,
    /// Same, for the concrete taint pass.
    pub state_clones_concrete: AtomicU64,
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
    state_clones_summary: AtomicU64::new(0),
    state_clones_concrete: AtomicU64::new(0),
};

/// The run's counters.
pub fn work() -> &'static WorkCounters {
    &WORK
}

/// Phase wall times, in submission order.
static PHASES: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());

/// Records a phase's wall time in microseconds.
pub fn record_phase(name: &'static str, micros: u64) {
    if let Ok(mut phases) = PHASES.lock() {
        phases.push((name, micros));
    }
}

/// Times `work` and records it as a phase.
pub fn time_phase<T>(name: &'static str, work: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let value = work();
    record_phase(name, started.elapsed().as_micros() as u64);
    value
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
        for (name, micros) in guard.iter() {
            *phases.entry(name).or_insert(0.0) += *micros as f64 / 1_000_000.0;
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
            "state_clones_summary": load(&counters.state_clones_summary),
            "state_clones_concrete": load(&counters.state_clones_concrete),
        },
        "phase_seconds": phases,
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
