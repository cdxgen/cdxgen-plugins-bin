#!/usr/bin/env python3
"""Fetch + pin rusi evaluation corpus.

Reads `corpus.toml` from the repo root, clones each non-bundled entry at the
pinned SHA into `.corpus-cache/<slug>/`, and (optionally) warms the cargo
registry with `cargo fetch` so the compiler backend can build later.

Network is required. If a project is already checked out at the right SHA
the clone is skipped, so re-runs are fast.

Usage:
    scripts/corpus/fetch.py                    # fetch small + fixtures
    scripts/corpus/fetch.py --tier medium      # fetch medium tier too
    scripts/corpus/fetch.py --tier all         # everything
    scripts/corpus/fetch.py --slug mini-redis  # one project
    scripts/corpus/fetch.py --no-cargo-fetch   # skip cargo fetch warm-up
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_TOML = REPO_ROOT / "corpus.toml"
CACHE_DIR = REPO_ROOT / ".corpus-cache"

# Map tier name -> set of tiers included. `all` covers everything.
TIER_GROUPS = {
    "fixtures": {"fixtures"},
    "small": {"fixtures", "small"},
    "medium": {"fixtures", "small", "medium"},
    "hybrid": {"fixtures", "small", "hybrid"},
    "all": {"fixtures", "small", "medium", "hybrid", "large", "vuln"},
}


def load_corpus() -> list[dict]:
    with CORPUS_TOML.open("rb") as handle:
        data = tomllib.load(handle)
    return list(data.get("fixtures", []))


def current_sha(repo_dir: Path) -> str | None:
    if not (repo_dir / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip()


def clone_at_sha(slug: str, repo: str, sha: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[fetch] clone {repo} @ {sha[:10]} -> {dest.relative_to(REPO_ROOT)}", file=sys.stderr)
    # Bare shallow clone then checkout keeps the network pull tiny and the
    # working tree at exactly the pinned SHA (no branch ambiguity).
    subprocess.run(
        ["git", "clone", "--no-checkout", "--filter=blob:none", repo, str(dest)],
        check=True,
        timeout=300,
    )
    subprocess.run(
        ["git", "checkout", sha],
        cwd=dest,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def warm_cargo_fetch(dest: Path) -> bool:
    """Best-effort `cargo fetch` warm-up. Returns True if it ran successfully."""
    if not (dest / "Cargo.toml").exists():
        return False
    try:
        subprocess.run(
            ["cargo", "fetch", "--locked"],
            cwd=dest,
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )
        return True
    except subprocess.TimeoutExpired:
        print(f"[fetch] cargo fetch timed out in {dest}", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tier",
        default="small",
        choices=sorted(TIER_GROUPS.keys()),
        help="Which tiers to fetch (default: small = fixtures + small).",
    )
    parser.add_argument("--slug", help="Fetch only the named corpus entry.")
    parser.add_argument(
        "--no-cargo-fetch",
        action="store_true",
        help="Skip the cargo fetch warm-up (faster, but compiler-mode builds will be cold).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-clone even if the cache is already at the right SHA.",
    )
    args = parser.parse_args()

    entries = load_corpus()
    wanted_tiers = TIER_GROUPS[args.tier]
    fetched = 0
    skipped = 0
    for entry in entries:
        if args.slug and entry["slug"] != args.slug:
            continue
        if entry["tier"] not in wanted_tiers:
            continue
        if "path" in entry:
            # Bundled fixture; nothing to fetch.
            skipped += 1
            continue
        repo = entry["repo"]
        sha = entry["sha"]
        dest = CACHE_DIR / entry["slug"]
        if not args.force and current_sha(dest) == sha:
            skipped += 1
            continue
        try:
            clone_at_sha(entry["slug"], repo, sha, dest)
        except subprocess.CalledProcessError as error:
            print(
                f"[fetch] FAILED {entry['slug']}: {error}",
                file=sys.stderr,
            )
            continue
        if not args.no_cargo_fetch:
            warm_cargo_fetch(dest)
        fetched += 1
    print(f"[fetch] done: fetched={fetched} skipped={skipped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
