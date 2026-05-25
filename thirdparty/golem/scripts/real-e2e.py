#!/usr/bin/env python3
"""Fetch real Go repositories and run golem smoke analyses.

This script is intentionally opt-in because it performs network clones and may
cause the Go toolchain to download modules while loading packages.
"""

import argparse
import json
import shutil
import subprocess
from pathlib import Path

DEFAULT_REPOS = [
    ("fatih-color", "https://github.com/fatih/color.git", "./..."),
    ("gorilla-mux", "https://github.com/gorilla/mux.git", "./..."),
    ("samber-lo", "https://github.com/samber/lo.git", "./..."),
    ("urfave-cli", "https://github.com/urfave/cli.git", "./..."),
    ("go-chi", "https://github.com/go-chi/chi.git", "./..."),
    ("hey", "https://github.com/rakyll/hey.git", "./..."),
]


def run(args, timeout):
    return subprocess.run(
        args,
        check=False,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def summarize_json(path):
    data = json.loads(path.read_text())
    return {
        "packages": data.get("stats", {}).get("packageCount"),
        "modules": data.get("stats", {}).get("moduleCount"),
        "imports": data.get("stats", {}).get("importCount"),
        "decls": data.get("stats", {}).get("declarationCount"),
        "usages": data.get("stats", {}).get("usageCount"),
        "diagnostics": data.get("stats", {}).get("diagnosticCount"),
        "graph": data.get("callGraph", {}).get("stats"),
        "aliasedImports": sum(1 for i in data.get("imports", []) if i.get("aliasKind") == "named"),
        "dotImports": sum(1 for i in data.get("imports", []) if i.get("aliasKind") == "dot"),
        "blankImports": sum(1 for i in data.get("imports", []) if i.get("aliasKind") == "blank"),
        "typeAliases": sum(1 for d in data.get("declarations", []) if d.get("alias")),
        "functionValueCalls": sum(1 for u in data.get("usages", []) if u.get("kind") == "functionValueCall"),
        "methodValueCalls": sum(1 for u in data.get("usages", []) if u.get("kind") == "methodValueCall"),
    }


def main():
    parser = argparse.ArgumentParser(description="Run golem against real Go repositories")
    parser.add_argument("--golem", default="./build/golem-darwin-arm64", help="path to golem binary")
    parser.add_argument("--workdir", default="/tmp/golem-real-repos", help="clone workspace")
    parser.add_argument("--out", default="/tmp/golem-real-results", help="output directory")
    parser.add_argument("--clone-timeout", type=int, default=90)
    parser.add_argument("--analyze-timeout", type=int, default=180)
    parser.add_argument("--modes", default="none,static,rta,pointer", help="comma-separated callgraph modes to test")
    parser.add_argument("--keep", action="store_true", help="reuse existing clones")
    args = parser.parse_args()
    modes = [mode.strip() for mode in args.modes.split(",") if mode.strip()]

    root = Path(args.workdir)
    out = Path(args.out)
    if not args.keep:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)

    summary = []
    for name, url, patterns in DEFAULT_REPOS:
        target = root / name
        if not target.exists():
            print(f"CLONE {name}", flush=True)
            try:
                cp = run(["git", "clone", "--depth", "1", url, str(target)], args.clone_timeout)
            except subprocess.TimeoutExpired:
                summary.append({"name": name, "cloneTimeout": True})
                continue
            if cp.returncode != 0:
                summary.append({"name": name, "cloneReturncode": cp.returncode, "stderr": cp.stderr[-400:]})
                continue
        for mode in modes:
            output = out / f"{name}-{mode}.json"
            cmd = [args.golem, "analyze", "--dir", str(target), "--patterns", patterns, "--callgraph", mode, "--format", "json", "--out", str(output)]
            print(f"RUN {name} {mode}", flush=True)
            try:
                cp = run(cmd, args.analyze_timeout)
            except subprocess.TimeoutExpired:
                summary.append({"name": name, "mode": mode, "timeout": True})
                continue
            record = {"name": name, "mode": mode, "returncode": cp.returncode, "stderr": cp.stderr[-400:]}
            if output.exists():
                try:
                    record.update(summarize_json(output))
                except Exception as exc:
                    record["parseError"] = str(exc)
            summary.append(record)
    summary_file = out / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"summary: {summary_file}")


if __name__ == "__main__":
    main()