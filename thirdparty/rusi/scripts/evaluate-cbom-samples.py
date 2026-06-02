#!/usr/bin/env python3
import argparse
import json
import os
import signal
import subprocess
import time
from pathlib import Path


DEFAULT_FIXTURES = [
    "fixtures/cbom-real-crates-app",
    "fixtures/cbom-real-modern-app",
    "fixtures/cbom-real-asymmetric-app",
]


def run_case(rusi_bin: Path, target: Path, backend: str, output_dir: Path, timeout_seconds: int | None) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / f"{target.name}.json"
    command = [
        str(rusi_bin),
        "analyze",
        "--dir",
        str(target),
        "--backend",
        backend,
        "--callgraph",
        "none",
        "--dataflow",
        "none",
        "--out",
        str(out_file),
    ]
    started = time.perf_counter()
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
        elapsed = round(time.perf_counter() - started, 3)
        return {
            "target": str(target),
            "backend": backend,
            "status": "timeout",
            "seconds": elapsed,
            "error": (error.stderr or error.stdout or f"timed out after {timeout_seconds}s").strip(),
        }

    elapsed = round(time.perf_counter() - started, 3)
    completed = subprocess.CompletedProcess(command, process.returncode if process is not None else 1, stdout, stderr)
    if completed.returncode != 0:
        return {
            "target": str(target),
            "backend": backend,
            "status": "error",
            "seconds": elapsed,
            "error": (completed.stderr or completed.stdout).strip(),
        }

    report = json.loads(out_file.read_text())
    crypto = report.get("crypto") or {}
    libraries = crypto.get("libraries", [])
    components = crypto.get("components", [])
    materials = crypto.get("materials", [])
    findings = crypto.get("findings", [])
    return {
        "target": str(target),
        "backend": backend,
        "status": "ok",
        "seconds": elapsed,
        "libraries": sorted({f"{entry['path']}:{entry['family']}" for entry in libraries}),
        "algorithms": sorted({entry["algorithm"] for entry in components}),
        "providers": sorted({entry["provider"] for entry in components}),
        "materialKinds": sorted({entry["kind"] for entry in materials}),
        "findingCategories": sorted({entry["category"] for entry in findings}),
        "counts": {
            "libraries": len(libraries),
            "components": len(components),
            "materials": len(materials),
            "findings": len(findings),
        },
        "report": str(out_file),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Rusi CBOM-oriented crypto detection against curated sample apps")
    parser.add_argument(
        "targets",
        nargs="*",
        help="Fixture or repository directories to analyze. Defaults to the curated CBOM fixtures.",
    )
    parser.add_argument(
        "--rusi-bin",
        default=Path(__file__).resolve().parents[1] / "target" / "debug" / "rusi",
        type=Path,
        help="Path to the Rusi CLI binary",
    )
    parser.add_argument(
        "--backend",
        default="stable",
        choices=["stable", "compiler"],
        help="Backend to use for CBOM evaluation",
    )
    parser.add_argument(
        "--output-dir",
        default=Path("/tmp/rusi-cbom-eval"),
        type=Path,
        help="Directory where per-target reports are written",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=None,
        help="Optional per-target timeout for the analysis command",
    )
    args = parser.parse_args()

    targets = args.targets or DEFAULT_FIXTURES
    for target in targets:
        result = run_case(args.rusi_bin, Path(target).resolve(), args.backend, args.output_dir, args.timeout_seconds)
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
