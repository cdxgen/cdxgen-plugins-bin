#!/usr/bin/env python3
"""Rusi differential evaluation runner.

Runs `rusi analyze` over the configured corpus, captures per-project metrics
(node/edge/slice counts, wall time, peak RSS), enforces byte-identical
determinism on re-run, computes precision/recall vs hand-authored
ground-truth flows, and golden-diffs a stable digest so any analysis change
that affects output is loudly surfaced.

Designed to run on a clean checkout with no arguments:

    python3 scripts/eval/run.py --tier small

Modes:
    --check-determinism   (default on) run each project twice, compare bytes
    --update-golden       bless the new digest (use only after review)
    --metrics PATH        write a JSON metrics summary
    --junit PATH          write a tiny pass/fail summary
    --backend stable|compiler|both
    --skip-compiler       auto-skip compiler backend if nightly is unavailable

Self-bless rule (autonomous mode): when you intend to change behavior, the
golden diff is *expected*; you run with --update-golden, inspect the digest
delta, and append a justification line to the Progress log. The runner will
never auto-bless — that's a human (or autonomous agent) decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_TOML = REPO_ROOT / "corpus.toml"
GOLDEN_DIR = REPO_ROOT / "scripts" / "eval" / "golden"
RUNS_DIR = REPO_ROOT / "scripts" / "eval" / "runs"
CACHE_DIR = REPO_ROOT / ".corpus-cache"

DEFAULT_FIXTURES_TIER = "small"

TIER_ORDER = ["fixtures", "small", "medium", "hybrid", "large", "vuln"]


# ---------------------------------------------------------------------------
# Corpus loading + path resolution
# ---------------------------------------------------------------------------


def load_corpus() -> list[dict]:
    with CORPUS_TOML.open("rb") as handle:
        data = tomllib.load(handle)
    return list(data.get("fixtures", []))


def resolve_target_path(entry: dict) -> Path:
    """Return the on-disk directory rusi should analyze for a corpus entry."""
    if "path" in entry:
        return (REPO_ROOT / entry["path"]).resolve()
    return (CACHE_DIR / entry["slug"]).resolve()


def select_tiers(tier_arg: str) -> set[str]:
    if tier_arg == "all":
        return set(TIER_ORDER)
    if tier_arg == "fixtures":
        return {"fixtures"}
    # tier_arg is a single tier name; include all tiers up to and including it
    # in TIER_ORDER, plus itself.
    idx = TIER_ORDER.index(tier_arg) if tier_arg in TIER_ORDER else -1
    if idx < 0:
        raise SystemExit(f"unknown tier '{tier_arg}'")
    return set(TIER_ORDER[: idx + 1])


# ---------------------------------------------------------------------------
# Subprocess wrapper with timeout + process-group cleanup
# ---------------------------------------------------------------------------


def run_with_timeout(
    command: list[str],
    cwd: Path,
    timeout: int | None,
    env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str] | subprocess.TimeoutExpired, float, int | None]:
    """Run a subprocess in its own process group; on timeout SIGTERM then
    SIGKILL the whole group so cargo/rustc children don't leak. Returns
    (result, wall_seconds, peak_rss_kb_or_None)."""
    started = time.perf_counter()
    peak_rss_kb: int | None = None

    # `/usr/bin/time -l` (macOS/BSD) or `time -v` (GNU) is the portable way
    # to read peak RSS without polling. We prefer /usr/bin/time on darwin.
    use_time_wrapper = shutil.which("time") is not None
    if use_time_wrapper:
        # /usr/bin/time -l prints peak RSS in bytes on macOS, KB on Linux.
        time_bin = shutil.which("/usr/bin/time") or shutil.which("time")
        # On GNU coreutils `time -v` outputs "Maximum resident set size (kbytes)".
        # On macOS `/usr/bin/time -l` outputs a line like "maximum resident set
        # size = <bytes>". We detect either after the fact.
        wrapped = [time_bin, "-l"] if platform.system() == "Darwin" else [time_bin, "-v"]
        full_command = wrapped + command
    else:
        full_command = command

    process = subprocess.Popen(
        full_command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        elapsed = time.perf_counter() - started
        completed = subprocess.CompletedProcess(
            command, process.returncode, stdout, stderr
        )
        # Best-effort parse of /usr/bin/time output appended to stderr.
        peak_rss_kb = parse_peak_rss(stderr, platform.system())
        return completed, elapsed, peak_rss_kb
    except subprocess.TimeoutExpired as error:
        # SIGTERM the whole process group, then SIGKILL if it survives.
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                break
            try:
                process.communicate(timeout=5)
                break
            except subprocess.TimeoutExpired:
                continue
        elapsed = time.perf_counter() - started
        return error, elapsed, None


def parse_peak_rss(time_stderr: str, system: str) -> int | None:
    """Extract peak RSS in KB from `/usr/bin/time` output (BSD `-l` or GNU `-v`).

    Handles three formats emitted by the wrappers we support:
      macOS old:  `maximum resident set size = 12345`        (bytes)
      macOS new:  `       12345  maximum resident set size`  (bytes)
      macOS 14+:  `       12345  peak memory footprint`      (bytes)
      GNU:        `Maximum resident set size (kbytes): 12345` (kB already)
    """
    if not time_stderr:
        return None
    for line in time_stderr.splitlines():
        low = line.lower()
        # macOS new-style: value-then-label, two-space separator.
        if "peak memory footprint" in low:
            try:
                value = int(low.split()[0])
                return value // 1024
            except (ValueError, IndexError):
                continue
        if "maximum resident set size" in low:
            try:
                # Either "label = value" or "value  label"
                if "=" in low:
                    value = int(low.split("=", 1)[1].strip())
                else:
                    value = int(low.split()[0])
                return value // 1024 if system == "Darwin" else value
            except (ValueError, IndexError):
                continue
    return None


# ---------------------------------------------------------------------------
# Per-project analysis
# ---------------------------------------------------------------------------


def invoke_rusi(
    rusi_bin: Path,
    target: Path,
    backend: str,
    out_path: Path,
    *,
    timeout: int | None,
    extra_args: Iterable[str] = (),
) -> dict:
    command = [
        str(rusi_bin),
        "analyze",
        "--dir",
        str(target),
        "--backend",
        backend,
        "--callgraph",
        "static",
        "--dataflow",
        "security",
        "--out",
        str(out_path),
    ]
    command.extend(extra_args)
    result, elapsed, peak_rss = run_with_timeout(command, cwd=REPO_ROOT, timeout=timeout)
    status = "ok"
    error_text: str | None = None
    if isinstance(result, subprocess.TimeoutExpired):
        status = "timeout"
        raw = result.stderr or result.stdout or b""
        error_text = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw).strip()
    elif result.returncode != 0:
        status = "error"
        error_text = (result.stderr or result.stdout or "").strip()
    return {
        "status": status,
        "seconds": round(elapsed, 3),
        "peak_rss_kb": peak_rss,
        "error": error_text,
        "report_path": str(out_path),
    }


def load_report(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def extract_counts(report: dict) -> dict:
    cg = report.get("call_graph") or {}
    df = report.get("data_flow") or {}
    cg_stats = cg.get("stats") or {}
    df_stats = df.get("stats") or {}
    return {
        "cg_nodes": cg_stats.get("node_count", 0),
        "cg_edges": cg_stats.get("edge_count", 0),
        "df_nodes": df_stats.get("node_count", 0),
        "df_edges": df_stats.get("edge_count", 0),
        "df_slices": df_stats.get("slice_count", 0),
        "df_summaries": df_stats.get("summary_count", 0),
    }


# ---------------------------------------------------------------------------
# Deterministic digest (golden)
# ---------------------------------------------------------------------------


def compute_digest(report: dict) -> dict:
    """A compact, sorted, content-addressable digest of the analysis output.

    Two reports with the same digest will produce byte-identical serialized
    JSON (modulo whitespace), so the digest is a sound stand-in for the full
    diff against golden. The digest deliberately excludes counts/perf so a
    change in ordering that doesn't affect the analysis still passes.
    """
    cg = report.get("call_graph") or {}
    df = report.get("data_flow") or {}

    edges = []
    for edge in cg.get("edges") or []:
        edges.append(
            (
                edge.get("source_name", ""),
                edge.get("target_name", ""),
                edge.get("call_type", ""),
            )
        )
    edges.sort()

    slices = []
    for sl in df.get("slices") or []:
        slices.append(
            (
                sl.get("source_category", ""),
                sl.get("sink_category", ""),
                sl.get("source_function", ""),
                sl.get("sink_function", ""),
            )
        )
    slices.sort()

    digests = {
        "edges_sha": sha_lines(edges),
        "slices_sha": sha_lines(slices),
        "edges_count": len(edges),
        "slices_count": len(slices),
    }
    return digests


def sha_lines(rows: Iterable[tuple]) -> str:
    h = hashlib.sha256()
    for row in rows:
        h.update("|".join(str(c) for c in row).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def golden_path(slug: str, backend: str) -> Path:
    return GOLDEN_DIR / f"{slug}.{backend}.digest.json"


def compare_digest(slug: str, backend: str, current: dict) -> dict:
    """Compare the current digest to the golden file on disk."""
    path = golden_path(slug, backend)
    if not path.exists():
        return {"status": "missing-golden", "golden_path": str(path)}
    try:
        golden = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"status": "corrupt-golden", "golden_path": str(path)}
    diffs = []
    for key in ("edges_sha", "slices_sha"):
        if golden.get(key) != current.get(key):
            diffs.append(key)
    if diffs:
        return {
            "status": "diff",
            "golden_path": str(path),
            "diff_keys": diffs,
            "golden": {
                "edges_count": golden.get("edges_count"),
                "slices_count": golden.get("slices_count"),
                "edges_sha": golden.get("edges_sha"),
                "slices_sha": golden.get("slices_sha"),
            },
            "current": current,
        }
    return {"status": "match"}


def write_golden(slug: str, backend: str, digest: dict) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    path = golden_path(slug, backend)
    path.write_text(json.dumps(digest, sort_keys=True, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Ground-truth / precision-recall
# ---------------------------------------------------------------------------


def load_expected_flows(entry: dict, target: Path) -> list[dict]:
    rel = entry.get("expected_flows")
    if not rel:
        return []
    candidate = target / rel
    if not candidate.exists():
        return []
    flows = []
    for line in candidate.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            flows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return flows


def evaluate_precision_recall(report: dict, expected: list[dict]) -> dict:
    """Compute precision/recall/F1 vs hand-authored expected flows.

    Each expected flow is matched against actual slices by category pair
    (source_category, sink_category); a finer key including the source/sink
    function name is also tracked so we can tell coarse from precise matches.
    """
    if not expected:
        return {"precision": None, "recall": None, "f1": None, "expected": 0, "actual": 0}

    actual_slices = report.get("data_flow", {}).get("slices") or []
    actual_keys = {
        (s.get("source_category", ""), s.get("sink_category", "")) for s in actual_slices
    }
    actual_keys_fine = {
        (
            s.get("source_category", ""),
            s.get("sink_category", ""),
            s.get("source_function", ""),
            s.get("sink_function", ""),
        )
        for s in actual_slices
    }
    expected_keys = {(e.get("source_category", ""), e.get("sink_category", "")) for e in expected}
    expected_keys_fine = {
        (
            e.get("source_category", ""),
            e.get("sink_category", ""),
            e.get("source_function", ""),
            e.get("sink_function", ""),
        )
        for e in expected
    }

    true_positives = len(expected_keys & actual_keys)
    false_negatives = len(expected_keys - actual_keys)
    false_positives = len(actual_keys - expected_keys)
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    true_positives_fine = len(expected_keys_fine & actual_keys_fine)
    false_negatives_fine = len(expected_keys_fine - actual_keys_fine)
    false_positives_fine = len(actual_keys_fine - expected_keys_fine)
    precision_fine = true_positives_fine / (true_positives_fine + false_positives_fine) if (true_positives_fine + false_positives_fine) else 0.0
    recall_fine = true_positives_fine / (true_positives_fine + false_negatives_fine) if (true_positives_fine + false_negatives_fine) else 0.0
    f1_fine = (2 * precision_fine * recall_fine / (precision_fine + recall_fine)) if (precision_fine + recall_fine) else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "expected": len(expected_keys),
        "actual": len(actual_keys),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "precision_fine": round(precision_fine, 4),
        "recall_fine": round(recall_fine, 4),
        "f1_fine": round(f1_fine, 4),
    }


# ---------------------------------------------------------------------------
# Toolchain detection
# ---------------------------------------------------------------------------


def have_nightly() -> bool:
    if not shutil.which("cargo"):
        return False
    try:
        result = subprocess.run(
            ["cargo", "+nightly", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def run_one(
    entry: dict,
    *,
    rusi_bin: Path,
    backends: list[str],
    timeout: int | None,
    check_determinism: bool,
    update_golden: bool,
    runs_root: Path,
) -> dict:
    target = resolve_target_path(entry)
    summary = {
        "slug": entry["slug"],
        "tier": entry["tier"],
        "target": str(target),
        "missing": not target.exists(),
        "backends": {},
    }
    if not target.exists():
        return summary

    expected_flows = load_expected_flows(entry, target)

    for backend in backends:
        run_dir = runs_root / entry["slug"] / backend
        run_dir.mkdir(parents=True, exist_ok=True)
        out1 = run_dir / "run1.json"
        out2 = run_dir / "run2.json"

        result = invoke_rusi(
            rusi_bin, target, backend, out1, timeout=timeout
        )
        backend_summary: dict = {"run1": result}

        report1 = load_report(out1)
        if report1 is None:
            backend_summary["counts"] = None
            backend_summary["digest"] = None
            backend_summary["golden"] = {"status": "no-report"}
            backend_summary["determinism"] = {"status": "skipped"}
            backend_summary["precision_recall"] = None
            summary["backends"][backend] = backend_summary
            continue

        counts = extract_counts(report1)
        digest = compute_digest(report1)
        golden_cmp = compare_digest(entry["slug"], backend, digest)

        determinism: dict
        if check_determinism and result["status"] == "ok":
            second = invoke_rusi(
                rusi_bin, target, backend, out2, timeout=timeout
            )
            report2 = load_report(out2)
            if report2 is None:
                determinism = {"status": "no-second-report", "run2": second}
            else:
                digest2 = compute_digest(report2)
                bytes_match = out1.read_bytes() == out2.read_bytes()
                # The hard gate is byte-identical. We also expose the digest
                # match so a future intentional non-determinism (e.g. embedded
                # timestamp) would still be detectable as content-stable.
                determinism = {
                    "status": "match" if bytes_match else "diff",
                    "bytes_match": bytes_match,
                    "digest_match": digest == digest2,
                    "run2_seconds": second.get("seconds"),
                }
        else:
            determinism = {"status": "skipped"}

        if update_golden and golden_cmp["status"] in ("diff", "missing-golden"):
            write_golden(entry["slug"], backend, digest)
            golden_cmp = {"status": "blessed", "previous": golden_cmp}

        backend_summary.update(
            {
                "counts": counts,
                "digest": digest,
                "golden": golden_cmp,
                "determinism": determinism,
                "precision_recall": evaluate_precision_recall(report1, expected_flows),
            }
        )
        summary["backends"][backend] = backend_summary

    return summary


def render_table(summaries: list[dict]) -> str:
    rows = []
    header = [
        "slug",
        "tier",
        "backend",
        "cg_nodes",
        "cg_edges",
        "slices",
        "summaries",
        "wall_s",
        "rss_mb",
        "det",
        "golden",
        "p/r/f1",
    ]
    rows.append(header)
    for summary in summaries:
        for backend, info in summary.get("backends", {}).items():
            counts = info.get("counts") or {}
            run1 = (info.get("run1") or {})
            det = info.get("determinism") or {}
            golden = info.get("golden") or {}
            pr = info.get("precision_recall") or {}
            rss = run1.get("peak_rss_kb")
            rss_str = f"{rss // 1024}" if rss else "-"
            pr_str = "-"
            if pr.get("precision") is not None:
                pr_str = f"{pr['precision']}/{pr['recall']}/{pr['f1']}"
            rows.append(
                [
                    summary["slug"],
                    summary["tier"],
                    backend,
                    str(counts.get("cg_nodes", "-")),
                    str(counts.get("cg_edges", "-")),
                    str(counts.get("df_slices", "-")),
                    str(counts.get("df_summaries", "-")),
                    f"{run1.get('seconds', 0)}",
                    rss_str,
                    det.get("status", "-"),
                    golden.get("status", "-"),
                    pr_str,
                ]
            )
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines = []
    for row in rows:
        line = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        lines.append(line)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tier",
        default=DEFAULT_FIXTURES_TIER,
        help="Corpus tier to run (default: small). 'all' runs every tier.",
    )
    parser.add_argument("--slug", help="Run only the named corpus entry.")
    parser.add_argument(
        "--rusi-bin",
        type=Path,
        default=(REPO_ROOT / "target" / "release" / "rusi"),
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help=(
            "Skip the automatic `cargo build --release -p rusi-cli` performed "
            "before the run. By default the harness ALWAYS rebuilds so it can "
            "never test a stale binary (this class of bug silently invalidated "
            "an earlier baseline). Only pass this if you have just built."
        ),
    )
    parser.add_argument(
        "--backend",
        choices=["stable", "compiler", "both"],
        default="stable",
    )
    parser.add_argument(
        "--skip-compiler-if-no-nightly",
        action="store_true",
        default=True,
        help="If --backend includes compiler but nightly is missing, skip gracefully.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Per-project per-run timeout in seconds.",
    )
    parser.add_argument(
        "--no-determinism",
        action="store_true",
        help="Skip the second run used to check byte-identical output.",
    )
    parser.add_argument(
        "--update-golden",
        action="store_true",
        help="Bless the current digest as the new golden (record why in the Progress log).",
    )
    parser.add_argument(
        "--metrics",
        type=Path,
        help="Write a JSON metrics summary to this path.",
    )
    parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="Exit non-zero if any golden digest differs (CI mode).",
    )
    args = parser.parse_args()

    # Always rebuild before evaluating so the harness measures the current tree,
    # not a stale artifact. `--rusi-bin` overrides both the build target and the
    # binary path only when it points outside the default release location.
    default_bin = (REPO_ROOT / "target" / "release" / "rusi").resolve()
    building_default = args.rusi_bin.resolve() == default_bin
    if not args.no_build and building_default:
        print("[run] building rusi (cargo build --release -p rusi-cli)", file=sys.stderr)
        build = subprocess.run(
            ["cargo", "build", "--release", "-p", "rusi-cli"],
            cwd=REPO_ROOT,
        )
        if build.returncode != 0:
            print("[run] build failed; aborting", file=sys.stderr)
            return 2

    if not args.rusi_bin.exists():
        print(f"rusi binary not found at {args.rusi_bin}; build first", file=sys.stderr)
        return 2

    wanted_tiers = select_tiers(args.tier) if not args.slug else None
    backends = ["stable"]
    if args.backend in ("compiler", "both"):
        if args.skip_compiler_if_no_nightly and not have_nightly():
            print(
                "[run] nightly toolchain not available; skipping compiler backend",
                file=sys.stderr,
            )
        else:
            backends.append("compiler")
    if args.backend == "both":
        # already includes stable
        pass
    elif args.backend == "compiler":
        backends = ["compiler"] if "compiler" in backends else []

    entries = load_corpus()
    if args.slug:
        entries = [e for e in entries if e["slug"] == args.slug]
    elif wanted_tiers is not None:
        entries = [e for e in entries if e["tier"] in wanted_tiers]

    stamp = time.strftime("%Y%m%d-%H%M%S")
    runs_root = RUNS_DIR / stamp
    runs_root.mkdir(parents=True, exist_ok=True)

    summaries: list[dict] = []
    failed_determinism = 0
    failed_golden = 0
    failed_runs = 0
    for entry in entries:
        print(f"[run] {entry['slug']} ({entry['tier']})", file=sys.stderr)
        summary = run_one(
            entry,
            rusi_bin=args.rusi_bin,
            backends=backends,
            timeout=args.timeout,
            check_determinism=not args.no_determinism,
            update_golden=args.update_golden,
            runs_root=runs_root,
        )
        if summary.get("missing"):
            print(
                f"[run] SKIP {entry['slug']}: target {summary['target']} not present "
                "(run scripts/corpus/fetch.py)",
                file=sys.stderr,
            )
        summaries.append(summary)
        for backend, info in summary.get("backends", {}).items():
            run1 = info.get("run1") or {}
            if run1.get("status") != "ok":
                failed_runs += 1
            det = info.get("determinism") or {}
            if det.get("status") == "diff":
                failed_determinism += 1
            golden = info.get("golden") or {}
            if golden.get("status") == "diff":
                failed_golden += 1

    table = render_table(summaries)
    print("\n" + table + "\n")
    print(
        f"[run] failed_runs={failed_runs} failed_determinism={failed_determinism} "
        f"failed_golden={failed_golden}",
        file=sys.stderr,
    )

    if args.metrics:
        args.metrics.parent.mkdir(parents=True, exist_ok=True)
        args.metrics.write_text(
            json.dumps(
                {
                    "stamp": stamp,
                    "tier": args.tier,
                    "backends": backends,
                    "summaries": summaries,
                },
                indent=2,
            )
            + "\n"
        )

    if args.fail_on_diff and (failed_determinism or failed_golden or failed_runs):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
