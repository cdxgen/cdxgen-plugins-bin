#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path


SUITES: dict[str, list[dict[str, str]]] = {
    "large": [
        {"name": "ripgrep", "repo": "BurntSushi/ripgrep", "branch": "master"},
        {"name": "tokio", "repo": "tokio-rs/tokio", "branch": "master"},
        {"name": "rust-analyzer", "repo": "rust-lang/rust-analyzer", "branch": "master"},
        {"name": "cargo", "repo": "rust-lang/cargo", "branch": "master"},
    ],
    "popular": [
        {"name": "serde", "repo": "serde-rs/serde", "branch": "master"},
        {"name": "reqwest", "repo": "seanmonstar/reqwest", "branch": "master"},
        {"name": "actix-web", "repo": "actix/actix-web", "branch": "master"},
        {"name": "diesel", "repo": "diesel-rs/diesel", "branch": "master"},
        {"name": "axum", "repo": "tokio-rs/axum", "branch": "main"},
        {"name": "syn", "repo": "dtolnay/syn", "branch": "master"},
    ],
}


def github_default_branch(repo: str) -> str:
    with urllib.request.urlopen(f"https://api.github.com/repos/{repo}", timeout=60) as response:
        payload = json.load(response)
    return payload.get("default_branch", "main")


def download_github_tarball(spec: dict[str, str], download_root: Path) -> Path:
    destination = download_root / spec["name"]
    if destination.exists():
        return destination

    archive_path = download_root / f"{spec['name']}.tar.gz"
    download_root.mkdir(parents=True, exist_ok=True)
    branch = spec["branch"]
    url = f"https://codeload.github.com/{spec['repo']}/tar.gz/refs/heads/{branch}"
    try:
        response = urllib.request.urlopen(url, timeout=120)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        branch = github_default_branch(spec["repo"])
        url = f"https://codeload.github.com/{spec['repo']}/tar.gz/refs/heads/{branch}"
        response = urllib.request.urlopen(url, timeout=120)
    with response, archive_path.open("wb") as output:
        output.write(response.read())
    with tarfile.open(archive_path, "r:gz") as archive:
        top_level = archive.getmembers()[0].name.split("/", 1)[0]
        try:
            archive.extractall(download_root, filter="data")
        except TypeError:
            archive.extractall(download_root)
    (download_root / top_level).rename(destination)
    archive_path.unlink(missing_ok=True)
    return destination


def resolve_repositories(args: argparse.Namespace) -> list[Path]:
    repos = [Path(repo).resolve() for repo in args.repos]
    for suite_name in args.suite:
        for spec in SUITES[suite_name]:
            repos.append(download_github_tarball(spec, args.download_root).resolve())
    return repos


def run_case(rusi_bin: Path, repo_path: Path, threads: int | None, output_dir: Path) -> dict:
    env = os.environ.copy()
    label = "auto" if threads is None else f"threads-{threads}"
    if threads is None:
        env.pop("RUSI_THREADS", None)
    else:
        env["RUSI_THREADS"] = str(threads)

    out_file = output_dir / f"{repo_path.name}-{label}.json"
    started = time.perf_counter()
    command = [
        str(rusi_bin),
        "analyze",
        "--dir",
        str(repo_path),
        "--backend",
        "stable",
        "--callgraph",
        "static",
        "--dataflow",
        "security",
        "--out",
        str(out_file),
    ]
    try:
        subprocess.run(command, check=True, env=env, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        elapsed = time.perf_counter() - started
        return {
            "repo": repo_path.name,
            "path": str(repo_path),
            "mode": label,
            "seconds": round(elapsed, 3),
            "status": "error",
            "error": (error.stderr or error.stdout or str(error)).strip(),
            "output": str(out_file),
        }
    elapsed = time.perf_counter() - started
    report = json.loads(out_file.read_text())
    graph = report.get("call_graph") or {}
    flow = report.get("data_flow") or {}
    return {
        "repo": repo_path.name,
        "path": str(repo_path),
        "mode": label,
        "status": "ok",
        "seconds": round(elapsed, 3),
        "callgraph_nodes": len(graph.get("nodes", [])),
        "callgraph_edges": len(graph.get("edges", [])),
        "dataflow_nodes": len(flow.get("nodes", [])),
        "dataflow_slices": len(flow.get("slices", [])),
        "output": str(out_file),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark stable Rusi analyses against real Rust repositories")
    parser.add_argument("repos", nargs="*", help="Repository directories to analyze")
    parser.add_argument(
        "--suite",
        action="append",
        choices=sorted(SUITES),
        default=[],
        help="Named benchmark suite to download and analyze",
    )
    parser.add_argument(
        "--rusi-bin",
        default=Path(__file__).resolve().parents[1] / "target" / "release" / "rusi",
        type=Path,
        help="Path to the Rusi CLI binary",
    )
    parser.add_argument(
        "--threads",
        action="append",
        type=int,
        default=[],
        help="Explicit RUSI_THREADS value to benchmark; repeat to test multiple values",
    )
    parser.add_argument(
        "--include-auto",
        action="store_true",
        help="Also benchmark the default auto-threaded mode",
    )
    parser.add_argument(
        "--output-dir",
        default=Path("/tmp/rusi-benchmarks"),
        type=Path,
        help="Directory for analysis outputs",
    )
    parser.add_argument(
        "--download-root",
        default=Path("/tmp/rusi-benchmark-repos"),
        type=Path,
        help="Directory used when downloading named benchmark suites",
    )
    args = parser.parse_args()

    if not args.repos and not args.suite:
        parser.error("provide at least one repository path or one --suite")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    modes: list[int | None] = []
    if args.include_auto or not args.threads:
        modes.append(None)
    modes.extend(args.threads)

    for repo_path in resolve_repositories(args):
        for threads in modes:
            result = run_case(args.rusi_bin, repo_path, threads, args.output_dir)
            print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
