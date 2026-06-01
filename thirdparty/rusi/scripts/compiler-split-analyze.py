#!/usr/bin/env python3
"""Run compiler-mode Rusi analysis per Cargo workspace package and join the reports.

This is intended for large repositories where one root-level compiler analysis is too slow
or times out. Each workspace package is analyzed independently, in parallel, and the
resulting reports are deduplicated into joined JSON plus simple GraphML exports.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import html
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--repo", type=Path, help="Existing Cargo repository/workspace to analyze")
    source.add_argument("--repo-url", help="Git URL to clone before analysis")
    parser.add_argument("--out", type=Path, required=True, help="Output directory")
    parser.add_argument("--join-existing", action="store_true", help="Join existing package reports under --out without running analysis")
    parser.add_argument("--rusi-bin", type=Path, default=None, help="Path to rusi binary")
    parser.add_argument("--toolchain", default="nightly", help="Rust toolchain for compiler backend")
    parser.add_argument("--dataflow", default="security", help="Rusi data-flow mode")
    parser.add_argument("--callgraph", default="static", help="Rusi call graph mode")
    parser.add_argument("--jobs", type=int, default=max(1, min((os.cpu_count() or 2) // 2, 4)))
    parser.add_argument("--timeout", type=int, default=600, help="Per-package timeout in seconds")
    parser.add_argument("--include-tests", action="store_true", help="Pass --tests to Rusi")
    parser.add_argument("--keep-going", action="store_true", help="Join successful package reports even if some packages fail")
    parser.add_argument("--clone-depth", type=int, default=1, help="Depth for --repo-url clone")
    return parser.parse_args()


def run(command: list[str], cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_rusi_bin() -> Path:
    return workspace_root() / "target" / "debug" / "rusi"


def ensure_repo(args: argparse.Namespace) -> Path:
    args.out.mkdir(parents=True, exist_ok=True)
    if args.repo:
        return args.repo.resolve()
    clone_dir = args.out / "repo"
    if clone_dir.exists():
        shutil.rmtree(clone_dir)
    clone = run(["git", "clone", "--depth", str(args.clone_depth), args.repo_url, str(clone_dir)])
    if clone.returncode != 0:
        raise SystemExit(f"git clone failed for {args.repo_url}\n{clone.stderr}")
    return clone_dir.resolve()


def cargo_metadata(repo: Path) -> dict[str, Any]:
    result = run(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=repo)
    if result.returncode != 0:
        raise SystemExit(f"cargo metadata failed in {repo}\n{result.stderr}")
    return json.loads(result.stdout)


def workspace_packages(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    member_ids = set(metadata.get("workspace_members") or [])
    packages = [pkg for pkg in metadata.get("packages") or [] if pkg.get("id") in member_ids]
    packages.sort(key=lambda pkg: (pkg.get("name") or "", pkg.get("manifest_path") or ""))
    return packages


def safe_name(package: dict[str, Any]) -> str:
    version = package.get("version") or "0"
    name = package.get("name") or "package"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in f"{name}-{version}")


def analyze_package(
    package: dict[str, Any], repo: Path, out: Path, rusi_bin: Path, args: argparse.Namespace
) -> dict[str, Any]:
    name = safe_name(package)
    package_out = out / "packages" / name
    package_out.mkdir(parents=True, exist_ok=True)
    package_dir = Path(package["manifest_path"]).resolve().parent
    report_path = package_out / "rusi-report.json"
    callgraph_path = package_out / "callgraph.graphml"
    dataflow_path = package_out / "dataflow.graphml"
    debug_path = package_out / "debug.log"
    command = [
        str(rusi_bin),
        "analyze",
        "--dir",
        str(package_dir),
        "--backend",
        "compiler",
        "--toolchain",
        args.toolchain,
        "--callgraph",
        args.callgraph,
        "--dataflow",
        args.dataflow,
        "--debug",
        "--out",
        str(report_path),
        "--callgraph-out",
        str(callgraph_path),
        "--callgraph-export-format",
        "graphml",
        "--dataflow-out",
        str(dataflow_path),
        "--dataflow-export-format",
        "graphml",
    ]
    if args.include_tests:
        command.append("--tests")
    try:
        result = run(command, cwd=repo, timeout=args.timeout)
        debug_path.write_text(result.stderr)
        return {
            "package": package.get("name"),
            "directory": str(package_dir),
            "status": "ok" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "report": str(report_path) if report_path.exists() else None,
            "stderr_tail": result.stderr[-4000:],
            "stdout_tail": result.stdout[-4000:],
        }
    except subprocess.TimeoutExpired as error:
        debug_path.write_text((error.stderr or "") if isinstance(error.stderr, str) else "")
        return {
            "package": package.get("name"),
            "directory": str(package_dir),
            "status": "timeout",
            "returncode": None,
            "report": str(report_path) if report_path.exists() else None,
            "stderr_tail": "timed out",
            "stdout_tail": "",
        }


def dedupe_extend(target: list[dict[str, Any]], incoming: list[dict[str, Any]], key_fields: tuple[str, ...]) -> None:
    seen = {dedupe_key(item, key_fields) for item in target}
    for item in incoming or []:
        key = dedupe_key(item, key_fields)
        if key in seen:
            continue
        target.append(item)
        seen.add(key)


def dedupe_key(item: dict[str, Any], key_fields: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(json.dumps(item.get(field), sort_keys=True) for field in key_fields)


def merge_stats(report: dict[str, Any]) -> None:
    report["stats"] = {
        "package_count": len(report.get("packages") or []),
        "file_count": len(report.get("files") or []),
        "import_count": len(report.get("imports") or []),
        "declaration_count": len(report.get("declarations") or []),
        "usage_count": len(report.get("usages") or []),
        "security_signal_count": len(report.get("security_signals") or []),
        "crypto_library_count": len(((report.get("crypto") or {}).get("libraries") or [])),
        "crypto_component_count": len(((report.get("crypto") or {}).get("components") or [])),
        "crypto_material_count": len(((report.get("crypto") or {}).get("materials") or [])),
        "crypto_finding_count": len(((report.get("crypto") or {}).get("findings") or [])),
        "call_graph_node_count": len(((report.get("call_graph") or {}).get("nodes") or [])),
        "call_graph_edge_count": len(((report.get("call_graph") or {}).get("edges") or [])),
        "data_flow_node_count": len(((report.get("data_flow") or {}).get("nodes") or [])),
        "data_flow_edge_count": len(((report.get("data_flow") or {}).get("edges") or [])),
        "data_flow_slice_count": len(((report.get("data_flow") or {}).get("slices") or [])),
    }
    if report.get("call_graph"):
        report["call_graph"]["stats"] = {
            "node_count": len(report["call_graph"].get("nodes") or []),
            "edge_count": len(report["call_graph"].get("edges") or []),
        }
    if report.get("data_flow"):
        report["data_flow"]["stats"] = {
            "source_count": sum(1 for node in report["data_flow"].get("nodes") or [] if node.get("source")),
            "sink_count": sum(1 for node in report["data_flow"].get("nodes") or [] if node.get("sink")),
            "slice_count": len(report["data_flow"].get("slices") or []),
            "node_count": len(report["data_flow"].get("nodes") or []),
            "edge_count": len(report["data_flow"].get("edges") or []),
            "summary_count": len(report["data_flow"].get("summaries") or []),
        }


def join_reports(report_paths: list[Path], statuses: list[dict[str, Any]]) -> dict[str, Any]:
    loaded = [json.loads(path.read_text()) for path in report_paths if path and path.exists()]
    if not loaded:
        raise SystemExit("no successful package reports to join")
    joined = copy.deepcopy(loaded[0])
    for field in ["modules", "packages", "files", "imports", "declarations", "usages", "security_signals", "diagnostics"]:
        joined[field] = []
    joined["call_graph"] = {"mode": "joined", "nodes": [], "edges": [], "diagnostics": [], "stats": {}}
    joined["data_flow"] = {
        "mode": "joined-embedded-mir",
        "patterns": (loaded[0].get("data_flow") or {}).get("patterns") or {},
        "nodes": [],
        "edges": [],
        "slices": [],
        "summaries": [],
        "diagnostics": [],
        "stats": {},
    }
    joined["crypto"] = {"libraries": [], "components": [], "materials": [], "findings": [], "properties": {}}
    joined.setdefault("runtime", {})["working_directory"] = "joined split compiler analysis"
    joined.setdefault("options", {})["directory"] = "joined split compiler analysis"
    joined["diagnostics"].append({
        "kind": "split-analysis",
        "message": json.dumps(statuses, sort_keys=True),
        "package_path": None,
        "file_path": None,
        "position": None,
    })
    for report in loaded:
        dedupe_extend(joined["modules"], report.get("modules") or [], ("name", "version", "manifest_path"))
        dedupe_extend(joined["packages"], report.get("packages") or [], ("id", "manifest_path"))
        dedupe_extend(joined["files"], report.get("files") or [], ("path", "package_path"))
        dedupe_extend(joined["imports"], report.get("imports") or [], ("path", "package_path", "position"))
        dedupe_extend(joined["declarations"], report.get("declarations") or [], ("id",))
        dedupe_extend(joined["usages"], report.get("usages") or [], ("id",))
        dedupe_extend(joined["security_signals"], report.get("security_signals") or [], ("id",))
        joined["diagnostics"].extend(report.get("diagnostics") or [])
        cg = report.get("call_graph") or {}
        dedupe_extend(joined["call_graph"]["nodes"], cg.get("nodes") or [], ("id",))
        dedupe_extend(joined["call_graph"]["edges"], cg.get("edges") or [], ("id",))
        joined["call_graph"]["diagnostics"].extend(cg.get("diagnostics") or [])
        df = report.get("data_flow") or {}
        dedupe_extend(joined["data_flow"]["nodes"], df.get("nodes") or [], ("id",))
        dedupe_extend(joined["data_flow"]["edges"], df.get("edges") or [], ("id",))
        dedupe_extend(joined["data_flow"]["slices"], df.get("slices") or [], ("id",))
        dedupe_extend(joined["data_flow"]["summaries"], df.get("summaries") or [], ("function_id",))
        joined["data_flow"]["diagnostics"].extend(df.get("diagnostics") or [])
        crypto = report.get("crypto") or {}
        for field in ["libraries", "components", "materials", "findings"]:
            dedupe_extend(joined["crypto"][field], crypto.get(field) or [], ("id",))
    merge_stats(joined)
    return joined


def graphml_data(key: str, value: Any, indent: int = 3) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True)
    return f"{'  '*indent}<data key=\"{html.escape(key)}\">{html.escape(value)}</data>\n"


def write_dataflow_graphml(data_flow: dict[str, Any], path: Path) -> None:
    xml = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n"]
    keys = ["kind", "name", "function", "category", "source", "sink", "sourceCategory", "sinkCategory", "ruleName", "properties"]
    for key in keys:
        target = "edge" if key in {"sourceCategory", "sinkCategory", "ruleName"} else "node"
        xml.append(f"  <key id=\"{key}\" for=\"{target}\" attr.name=\"{key}\" attr.type=\"string\"/>\n")
    xml.append("  <graph id=\"joined-dataflow\" edgedefault=\"directed\">\n")
    for node in data_flow.get("nodes") or []:
        xml.append(f"    <node id=\"{html.escape(node.get('id',''))}\">\n")
        for key in ["kind", "name", "function", "category", "source", "sink", "properties"]:
            xml.append(graphml_data(key, node.get(key), 3))
        xml.append("    </node>\n")
    for item in data_flow.get("slices") or []:
        xml.append(
            f"    <edge id=\"{html.escape(item.get('id',''))}\" source=\"{html.escape(item.get('source_id',''))}\" target=\"{html.escape(item.get('sink_id',''))}\">\n"
        )
        xml.append(graphml_data("sourceCategory", item.get("source_category"), 3))
        xml.append(graphml_data("sinkCategory", item.get("sink_category"), 3))
        xml.append(graphml_data("ruleName", item.get("rule_name"), 3))
        xml.append(graphml_data("properties", item.get("properties"), 3))
        xml.append("    </edge>\n")
    xml.append("  </graph>\n</graphml>\n")
    path.write_text("".join(xml))


def write_callgraph_graphml(call_graph: dict[str, Any], path: Path) -> None:
    xml = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n"]
    for key, target in [("name", "node"), ("qualifiedName", "node"), ("kind", "node"), ("callType", "edge")]:
        xml.append(f"  <key id=\"{key}\" for=\"{target}\" attr.name=\"{key}\" attr.type=\"string\"/>\n")
    xml.append("  <graph id=\"joined-callgraph\" edgedefault=\"directed\">\n")
    for node in call_graph.get("nodes") or []:
        xml.append(f"    <node id=\"{html.escape(node.get('id',''))}\">\n")
        xml.append(graphml_data("name", node.get("name"), 3))
        xml.append(graphml_data("qualifiedName", node.get("qualified_name"), 3))
        xml.append(graphml_data("kind", node.get("kind"), 3))
        xml.append("    </node>\n")
    for edge in call_graph.get("edges") or []:
        xml.append(
            f"    <edge id=\"{html.escape(edge.get('id',''))}\" source=\"{html.escape(edge.get('source_id',''))}\" target=\"{html.escape(edge.get('target_id',''))}\">\n"
        )
        xml.append(graphml_data("callType", edge.get("call_type"), 3))
        xml.append("    </edge>\n")
    xml.append("  </graph>\n</graphml>\n")
    path.write_text("".join(xml))


def main() -> int:
    args = parse_args()
    if args.join_existing:
        statuses_path = args.out / "split-status.json"
        statuses = json.loads(statuses_path.read_text()) if statuses_path.exists() else []
        report_paths = sorted(args.out.glob("packages/*/rusi-report.json"))
        joined = join_reports(report_paths, statuses)
        joined_report = args.out / "joined-rusi-report.json"
        joined_report.write_text(json.dumps(joined, indent=2, sort_keys=True))
        write_callgraph_graphml(joined.get("call_graph") or {}, args.out / "joined-callgraph.graphml")
        write_dataflow_graphml(joined.get("data_flow") or {}, args.out / "joined-dataflow.graphml")
        print(f"joined report: {joined_report}")
        print(f"joined stats: {json.dumps(joined.get('stats') or {}, sort_keys=True)}")
        print(f"data-flow stats: {json.dumps((joined.get('data_flow') or {}).get('stats') or {}, sort_keys=True)}")
        return 0
    if not args.repo and not args.repo_url:
        raise SystemExit("one of --repo/--repo-url is required unless --join-existing is used")
    repo = ensure_repo(args)
    rusi_bin = (args.rusi_bin or default_rusi_bin()).resolve()
    if not rusi_bin.exists():
        raise SystemExit(f"rusi binary not found: {rusi_bin}; run cargo build -p rusi-cli first")
    metadata = cargo_metadata(repo)
    packages = workspace_packages(metadata)
    if not packages:
        raise SystemExit(f"no workspace packages found in {repo}")
    statuses: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        future_map = {
            executor.submit(analyze_package, package, repo, args.out, rusi_bin, args): package
            for package in packages
        }
        for future in concurrent.futures.as_completed(future_map):
            status = future.result()
            statuses.append(status)
            print(f"{status['status']:>7} {status['package']} {status['directory']}")
    statuses.sort(key=lambda item: item.get("package") or "")
    (args.out / "split-status.json").write_text(json.dumps(statuses, indent=2, sort_keys=True))
    failed = [status for status in statuses if status["status"] != "ok"]
    if failed and not args.keep_going:
        raise SystemExit(f"{len(failed)} package analyses failed or timed out; see {args.out / 'split-status.json'}")
    report_paths = [Path(status["report"]) for status in statuses if status["status"] == "ok" and status.get("report")]
    joined = join_reports(report_paths, statuses)
    joined_report = args.out / "joined-rusi-report.json"
    joined_report.write_text(json.dumps(joined, indent=2, sort_keys=True))
    write_callgraph_graphml(joined.get("call_graph") or {}, args.out / "joined-callgraph.graphml")
    write_dataflow_graphml(joined.get("data_flow") or {}, args.out / "joined-dataflow.graphml")
    print(f"joined report: {joined_report}")
    print(f"joined stats: {json.dumps(joined.get('stats') or {}, sort_keys=True)}")
    print(f"data-flow stats: {json.dumps((joined.get('data_flow') or {}).get('stats') or {}, sort_keys=True)}")
    return 0 if not failed else 2


if __name__ == "__main__":
    sys.exit(main())
