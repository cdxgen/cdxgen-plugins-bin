#!/usr/bin/env python3
"""Fetch real Go repositories and run golem smoke analyses.

This script is intentionally opt-in because it performs network clones and may
cause the Go toolchain to download modules while loading packages.
"""

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

DEFAULT_REPOS = [
    ("fatih-color", "https://github.com/fatih/color.git", "./..."),
    ("gorilla-mux", "https://github.com/gorilla/mux.git", "./..."),
    ("gin-examples", "https://github.com/gin-gonic/examples.git", "./..."),
    ("govwa", "https://github.com/0c34/govwa.git", "./..."),
    ("go-sqlite3", "https://github.com/mattn/go-sqlite3.git", "./..."),
    ("samber-lo", "https://github.com/samber/lo.git", "./..."),
    ("urfave-cli", "https://github.com/urfave/cli.git", "./..."),
    ("go-chi", "https://github.com/go-chi/chi.git", "./..."),
    ("hey", "https://github.com/rakyll/hey.git", "./..."),
]

REPO_EXPECTATIONS = {
    "govwa": {"apiEndpoints": 10, "dataFlowSlices": 1},
    "go-sqlite3": {"nativeArtifacts": 1, "securitySignals": 1},
}


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
    dataflow = data.get("dataFlow") or {}
    dataflow_stats = dataflow.get("stats") or {}
    return {
        "packages": data.get("stats", {}).get("packageCount"),
        "modules": data.get("stats", {}).get("moduleCount"),
        "generatedFiles": data.get("stats", {}).get("generatedFileCount"),
        "imports": data.get("stats", {}).get("importCount"),
        "decls": data.get("stats", {}).get("declarationCount"),
        "usages": data.get("stats", {}).get("usageCount"),
        "runtimeUsages": data.get("stats", {}).get("runtimeUsageCount"),
        "testUsages": data.get("stats", {}).get("testUsageCount"),
        "benchmarkUsages": data.get("stats", {}).get("benchmarkUsageCount"),
        "fuzzUsages": data.get("stats", {}).get("fuzzUsageCount"),
        "exampleUsages": data.get("stats", {}).get("exampleUsageCount"),
        "buildDirectives": data.get("stats", {}).get("buildDirectiveCount"),
        "nativeArtifacts": data.get("stats", {}).get("nativeArtifactCount"),
        "apiEndpoints": data.get("stats", {}).get("apiEndpointCount"),
        "externalUrls": data.get("stats", {}).get("externalUrlCount"),
        "services": data.get("stats", {}).get("serviceCount"),
        "securitySignals": data.get("stats", {}).get("securitySignalCount"),
        "goModReplaces": data.get("stats", {}).get("goModReplaceCount"),
        "goModExcludes": data.get("stats", {}).get("goModExcludeCount"),
        "vendorModules": data.get("stats", {}).get("vendorModuleCount"),
        "workspaceModules": data.get("stats", {}).get("workspaceModuleCount"),
        "privateModuleHints": data.get("stats", {}).get("privateModuleHintCount"),
        "licenseFileModules": data.get("stats", {}).get("licenseFileModuleCount"),
        "diagnostics": data.get("stats", {}).get("diagnosticCount"),
        "graph": data.get("callGraph", {}).get("stats"),
        "dataFlow": dataflow_stats,
        "dataFlowSources": dataflow_stats.get("sourceCount"),
        "dataFlowSinks": dataflow_stats.get("sinkCount"),
        "dataFlowSlices": dataflow_stats.get("sliceCount"),
        "dataFlowNodes": dataflow_stats.get("nodeCount"),
        "dataFlowEdges": dataflow_stats.get("edgeCount"),
        "dataFlowSummaries": dataflow_stats.get("summaryCount"),
        "aliasedImports": sum(1 for i in data.get("imports", []) if i.get("aliasKind") == "named"),
        "dotImports": sum(1 for i in data.get("imports", []) if i.get("aliasKind") == "dot"),
        "blankImports": sum(1 for i in data.get("imports", []) if i.get("aliasKind") == "blank"),
        "typeAliases": sum(1 for d in data.get("declarations", []) if d.get("alias")),
        "functionValueCalls": sum(1 for u in data.get("usages", []) if u.get("kind") == "functionValueCall"),
        "methodValueCalls": sum(1 for u in data.get("usages", []) if u.get("kind") == "methodValueCall"),
    }


def parse_repo_filter(value):
    if not value or value == "all":
        return None
    return {part.strip() for part in value.split(",") if part.strip()}


def selected_repos(value):
    wanted = parse_repo_filter(value)
    if wanted is None:
        return DEFAULT_REPOS
    repos = [repo for repo in DEFAULT_REPOS if repo[0] in wanted]
    missing = wanted - {repo[0] for repo in repos}
    if missing:
        raise SystemExit(f"unknown repo names in --repos: {', '.join(sorted(missing))}")
    return repos


def run_fixture(args, out, timeout):
    script = Path(__file__).resolve()
    golem_root = script.parents[1]
    fixture = golem_root / "testdata" / "dataflow"
    if not fixture.exists():
        return {"name": "dataflow-fixture", "missing": str(fixture)}
    output = out / "dataflow-fixture.json"
    graph = out / "dataflow-fixture.graphml"
    cmd = [
        args.golem,
        "analyze",
        "--dir",
        str(fixture),
        "--patterns",
        "./...",
        "--dataflow",
        "all",
        "--include-local",
        "--format",
        "json",
        "--out",
        str(output),
        "--dataflow-graph-out",
        str(graph),
    ]
    print("RUN dataflow-fixture", flush=True)
    try:
        cp = run(cmd, timeout)
    except subprocess.TimeoutExpired:
        return {"name": "dataflow-fixture", "timeout": True}
    record = {"name": "dataflow-fixture", "mode": "fixture", "returncode": cp.returncode, "stderr": cp.stderr[-400:]}
    if output.exists():
        try:
            record.update(summarize_json(output))
        except Exception as exc:
            record["parseError"] = str(exc)
    record["graphExists"] = graph.exists() and graph.stat().st_size > 0
    if record.get("returncode") != 0:
        record["failed"] = True
    if record.get("dataFlowSlices", 0) < 6:
        record["failed"] = True
        record["failureReason"] = "fixture emitted fewer than six expected data-flow slices"
    if record.get("apiEndpoints", 0) < 3 or record.get("externalUrls", 0) < 1 or record.get("services", 0) < 2:
        record["failed"] = True
        record["failureReason"] = "fixture did not emit expected endpoint/url/service evidence"
    if not record["graphExists"]:
        record["failed"] = True
        record["failureReason"] = "fixture data-flow graph sidecar was not created"
    return record


def apply_repo_expectations(record):
    expected = REPO_EXPECTATIONS.get(record.get("name"))
    if not expected or record.get("returncode") != 0:
        return record
    if record.get("dataflowMode") == "none" and "dataFlowSlices" in expected:
        return record
    failures = []
    for key, minimum in expected.items():
        actual = record.get(key, 0) or 0
        if actual < minimum:
            failures.append(f"{key}={actual} < {minimum}")
    if failures:
        record["failed"] = True
        record["failureReason"] = "; ".join(failures)
    return record


def main():
    parser = argparse.ArgumentParser(description="Run golem against real Go repositories")
    parser.add_argument("--golem", default="./build/golem-darwin-arm64", help="path to golem binary")
    parser.add_argument("--workdir", default="/tmp/golem-real-repos", help="clone workspace")
    parser.add_argument("--out", default="/tmp/golem-real-results", help="output directory")
    parser.add_argument("--clone-timeout", type=int, default=90)
    parser.add_argument("--analyze-timeout", type=int, default=180)
    parser.add_argument("--modes", default="none,static,rta,pointer", help="comma-separated callgraph modes to test")
    parser.add_argument("--dataflow-modes", default="none,security,all", help="comma-separated data-flow modes to test")
    parser.add_argument("--repos", default="all", help="comma-separated built-in repo names or all")
    parser.add_argument("--skip-fixture", action="store_true", help="skip local semantic data-flow fixture validation")
    parser.add_argument("--fail-on-repo-error", action="store_true", help="exit non-zero when any real repo clone/analyze fails")
    parser.add_argument("--keep", action="store_true", help="reuse existing clones")
    args = parser.parse_args()
    modes = [mode.strip() for mode in args.modes.split(",") if mode.strip()]
    dataflow_modes = [mode.strip() for mode in args.dataflow_modes.split(",") if mode.strip()]
    repos = selected_repos(args.repos)

    root = Path(args.workdir)
    out = Path(args.out)
    if not args.keep:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)

    summary = []
    if not args.skip_fixture:
        summary.append(run_fixture(args, out, args.analyze_timeout))
    for name, url, patterns in repos:
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
            for dataflow_mode in dataflow_modes:
                suffix = f"{mode}-df-{dataflow_mode}"
                output = out / f"{name}-{suffix}.json"
                graph = out / f"{name}-{suffix}.graphml"
                cmd = [args.golem, "analyze", "--dir", str(target), "--patterns", patterns, "--callgraph", mode, "--dataflow", dataflow_mode, "--format", "json", "--out", str(output)]
                if dataflow_mode != "none":
                    cmd.extend(["--dataflow-graph-out", str(graph)])
                print(f"RUN {name} callgraph={mode} dataflow={dataflow_mode}", flush=True)
                try:
                    cp = run(cmd, args.analyze_timeout)
                except subprocess.TimeoutExpired:
                    summary.append({"name": name, "mode": mode, "dataflowMode": dataflow_mode, "timeout": True})
                    continue
                record = {"name": name, "mode": mode, "dataflowMode": dataflow_mode, "returncode": cp.returncode, "stderr": cp.stderr[-400:]}
                if output.exists():
                    try:
                        record.update(summarize_json(output))
                    except Exception as exc:
                        record["parseError"] = str(exc)
                if dataflow_mode != "none":
                    record["graphExists"] = graph.exists() and graph.stat().st_size > 0
                summary.append(apply_repo_expectations(record))
    summary_file = out / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"summary: {summary_file}")
    failures = [
        item
        for item in summary
        if item.get("failed")
        or item.get("timeout")
        or item.get("parseError")
        or item.get("returncode", 0) != 0
        or (item.get("dataflowMode") not in (None, "none") and not item.get("graphExists", False))
    ]
    if failures and (args.fail_on_repo_error or any(item.get("name") == "dataflow-fixture" for item in failures)):
        print(json.dumps({"failures": failures}, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()