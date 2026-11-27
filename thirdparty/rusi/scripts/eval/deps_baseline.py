#!/usr/bin/env python3
"""Dependency-mode baseline runner.

Runs the three dependency modes the dependency-performance epic sets its
targets from, over the small and medium tiers of `corpus.toml`, and writes
a Markdown table of the wall time, the peak RSS, and the per-phase
breakdown each run's `--stats-json` document carries.

    python3 scripts/eval/deps_baseline.py                    # small + medium
    python3 scripts/eval/deps_baseline.py --tier small       # one tier
    python3 scripts/eval/deps_baseline.py --backend compiler # richer backend

The three modes per project:

    --deps                                      # dependency declarations
    --deps --callgraph none --dataflow none     # dependency discovery alone
    --deps --dataflow security-deps             # + dependency bodies, for taint

`security-deps` reads a whole dependency closure and can take minutes on
mini-redis, so every run carries a generous timeout, and a timeout is a
recorded result (its own row) rather than a failure of the run. Corpus
projects are cloned by scripts/corpus/fetch.py; a project that has not been
fetched is skipped with a note rather than fetched here, so a baseline run
never surprises anyone with a large clone.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run import (  # noqa: E402
    REPO_ROOT,
    resolve_target_path,
    run_with_timeout,
)

# The passes whose wall times the table breaks out, in the order the
# analysis runs them. `concrete_pass` is the slice building pass.
PHASE_ORDER = [
    "module_tree",
    "macro_prepass",
    "parse",
    "import_resolution",
    "call_graph",
    "summary_fixpoint",
    "concrete_pass",
    "export",
    "report_write",
]

MODES = {
    "deps": ["--deps", "--callgraph", "static", "--dataflow", "security"],
    "deps-structure": ["--deps", "--callgraph", "none", "--dataflow", "none"],
    "deps-security": ["--deps", "--callgraph", "static", "--dataflow", "security-deps"],
}

DEFAULT_TIMEOUT_SECONDS = 1800


def load_tiers(tier_arg: str) -> list[dict]:
    with (REPO_ROOT / "corpus.toml").open("rb") as handle:
        data = tomllib.load(handle)
    wanted = {"small", "medium"} if tier_arg in ("all", "small+medium") else {tier_arg}
    return [entry for entry in data.get("fixtures", []) if entry.get("tier") in wanted]


def toolchain_description() -> dict:
    try:
        rustc = subprocess.run(
            ["rustc", "--version"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        rustc = "unknown"
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        commit = "unknown"
    return {
        "rusi_commit": commit,
        "rustc": rustc,
        "host": platform.platform(),
    }


def run_mode(
    rusi_bin: Path,
    target: Path,
    mode_args: list[str],
    timeout: int,
    scratch: Path,
    slug: str,
    mode: str,
) -> dict:
    scratch.mkdir(parents=True, exist_ok=True)
    stats_path = scratch / f"{slug}.{mode}.stats.json"
    command = [
        str(rusi_bin),
        "analyze",
        "--dir",
        str(target),
        *mode_args,
        "--stats-json",
        str(stats_path),
    ]
    result, elapsed, peak_rss_kb = run_with_timeout(
        command, cwd=REPO_ROOT, timeout=timeout
    )
    # A timeout is a recorded result of its own, not a failure of the run:
    # security-deps reads a whole dependency closure and can take minutes.
    if isinstance(result, subprocess.TimeoutExpired):
        status = "timeout"
    elif result.returncode != 0:
        status = "error"
    else:
        status = "ok"

    phases: dict[str, float] = {}
    if stats_path.exists():
        try:
            stats = json.loads(stats_path.read_text())
            # A phase that runs more than once has one entry per run.
            for entry in stats.get("phases") or []:
                name = entry["name"]
                phases[name] = phases.get(name, 0.0) + entry.get("seconds", 0.0)
        except (OSError, ValueError, KeyError, TypeError):
            pass
    # The table reports the peak RSS `/usr/bin/time` measured, which covers
    # child processes too; the per-phase readings in the stats document only
    # cover the rusi process itself.
    return {
        "slug": slug,
        "mode": mode,
        "status": status,
        "seconds": round(elapsed, 2),
        "peak_rss_kb": peak_rss_kb,
        "phases": phases,
    }


def markdown_table(results: list[dict], toolchain: dict, backend: str) -> str:
    lines = []
    lines.append("# Rusi dependency-mode baseline")
    lines.append("")
    lines.append(
        f"- rusi commit: `{toolchain['rusi_commit']}` (backend: {backend})"
    )
    lines.append(f"- toolchain: `{toolchain['rustc']}`")
    lines.append(f"- machine: {toolchain['host']}")
    lines.append(
        f"- generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    lines.append("")
    header = ["project", "tier", "mode", "status", "wall s", "peak RSS MB"]
    header.extend(f"{phase} s" for phase in PHASE_ORDER)
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")
    for row in results:
        peak_mb = "-"
        if row["peak_rss_kb"] is not None:
            peak_mb = f"{row['peak_rss_kb'] / 1024:.0f}"
        cells = [
            row["slug"],
            row["tier"],
            row["mode"],
            row["status"],
            str(row["seconds"]),
            peak_mb,
        ]
        for phase in PHASE_ORDER:
            value = row["phases"].get(phase)
            cells.append(f"{value:.2f}" if value is not None else "-")
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tier",
        default="small+medium",
        help="small, medium, or small+medium (default)",
    )
    parser.add_argument("--backend", default="stable", choices=["stable", "compiler"])
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-run timeout in seconds (default {DEFAULT_TIMEOUT_SECONDS}); "
        "security-deps reads a whole dependency closure and can take minutes",
    )
    parser.add_argument("--rusi-bin", type=Path, default=None)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "scripts" / "eval" / "runs" / "deps-baseline.md",
        help="where the Markdown table is written",
    )
    args = parser.parse_args()

    rusi_bin = args.rusi_bin or REPO_ROOT / "target" / "release" / "rusi"
    if not rusi_bin.exists():
        print(f"rusi binary not found at {rusi_bin}; build first: cargo build --release -p rusi-cli", file=sys.stderr)
        return 1

    entries = load_tiers(args.tier)
    if not entries:
        print(f"no corpus entries for tier '{args.tier}'", file=sys.stderr)
        return 1

    scratch = REPO_ROOT / "scripts" / "eval" / "runs" / f"deps-baseline-{args.backend}"
    results: list[dict] = []
    for entry in entries:
        slug = entry["slug"]
        target = resolve_target_path(entry)
        if not target.exists():
            print(
                f"[skip] {slug}: {target} not present (run scripts/corpus/fetch.py)",
                file=sys.stderr,
            )
            continue
        for mode, mode_args in MODES.items():
            print(f"[run] {slug} ({entry['tier']}) {mode}", file=sys.stderr)
            row = run_mode(rusi_bin, target, mode_args, args.timeout, scratch, slug, mode)
            row["tier"] = entry["tier"]
            results.append(row)
            print(
                f"       {row['status']} {row['seconds']}s peak={row['peak_rss_kb']}kB",
                file=sys.stderr,
            )

    toolchain = toolchain_description()
    table = markdown_table(results, toolchain, args.backend)
    args.out.write_text(table)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
