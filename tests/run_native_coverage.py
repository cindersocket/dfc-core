#!/usr/bin/env python3
"""Measure emulator coverage from unit, synthetic, and physical evidence."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

MODES = ("all", "physical", "synthetic-unit")
MINIMUM_PERCENT = {
    "all": {"lines": 90.0, "branches": 78.0, "functions": 97.0},
    "physical": {"lines": 68.0, "branches": 54.0, "functions": 80.0},
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--test", action="append", default=[], type=Path)
    return parser.parse_args()


def llvm_tool(name: str) -> str:
    override = os.environ.get(f"DFC_{name.upper().replace('-', '_')}")
    if override:
        return override
    found = shutil.which(name)
    if found:
        return found
    xcrun = shutil.which("xcrun")
    if xcrun:
        result = subprocess.run(
            (xcrun, "--find", name),
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    raise RuntimeError(
        f"{name} was not found; install LLVM or set DFC_{name.upper().replace('-', '_')}"
    )


def vector_paths(manifest: Path, origin: str | None) -> list[Path]:
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    root = manifest.parent
    selected = []
    for item in payload["files"]:
        metadata = item["metadata"]
        if not metadata["replayable"]:
            continue
        if origin is not None and metadata["origin"] != origin:
            continue
        selected.append(root / item["path"])
    return selected


def coverage_sources(repo_root: Path) -> list[Path]:
    src = repo_root / "src"
    # Include the complete runtime dependency surface used while emulating a
    # card. Command builders, reader-side transport, codecs, and response
    # decoders are separate consumers and intentionally stay out of this scope.
    sources = list(src.glob("dfc_emulator*.c"))
    sources.extend(
        src / name
        for name in (
            "aes_cmac.c",
            "des_cmac.c",
            "dfc_an10922.c",
            "dfc_common.c",
            "dfc_credential.c",
            "dfc_crypto.c",
            "dfc_crypto_des_chain.c",
            "dfc_crypto_disabled.c",
            "dfc_virtual_picc.c",
            "dfc_ev2.c",
            "dfc_ev2_command.c",
            "dfc_ev2_crypto.c",
            "dfc_sdm.c",
            "dfc_secure_messaging.c",
            "dfc_transaction_mac.c",
        )
    )
    return sorted(set(sources))


def run_logged(command: list[str], cwd: Path, env: dict[str, str], log: Path) -> None:
    with log.open("a", encoding="utf-8") as stream:
        stream.write(f"$ {' '.join(command)}\n")
        stream.flush()
        subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=True,
        )


def cov_command(
    llvm_cov: str,
    action: str,
    objects: list[Path],
    profile: Path,
    sources: list[Path],
) -> list[str]:
    command = [llvm_cov, action, str(objects[0])]
    command.extend(f"-object={item}" for item in objects[1:])
    command.append(f"-instr-profile={profile}")
    command.extend(str(source) for source in sources)
    return command


def run_mode(
    mode: str,
    output_root: Path,
    runner: Path,
    tests: list[Path],
    vectors: list[Path],
    sources: list[Path],
    llvm_profdata: str,
    llvm_cov: str,
) -> dict[str, Any]:
    mode_dir = output_root / mode
    raw_dir = mode_dir / "raw"
    shutil.rmtree(mode_dir, ignore_errors=True)
    raw_dir.mkdir(parents=True)
    log = mode_dir / "run.log"
    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = str(raw_dir / "%m-%p.profraw")
    tests_dir = runner.parent

    mode_tests = [] if mode == "physical" else tests
    for test in mode_tests:
        run_logged([str(test)], tests_dir, env, log)
    run_logged([str(runner), *(str(path) for path in vectors)], tests_dir, env, log)

    raw_profiles = sorted(raw_dir.glob("*.profraw"))
    if not raw_profiles:
        raise RuntimeError(f"{mode}: no LLVM raw profiles were produced")
    profile = mode_dir / "merged.profdata"
    subprocess.run(
        [
            llvm_profdata,
            "merge",
            "-sparse",
            *(str(path) for path in raw_profiles),
            "-o",
            str(profile),
        ],
        check=True,
    )

    objects = [runner, *mode_tests]
    report = subprocess.run(
        cov_command(llvm_cov, "report", objects, profile, sources),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (mode_dir / "report.txt").write_text(report, encoding="utf-8")

    functions = subprocess.run(
        [
            *cov_command(llvm_cov, "report", objects, profile, sources),
            "--show-functions",
            "--line-coverage-lt=100",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (mode_dir / "uncovered-functions.txt").write_text(functions, encoding="utf-8")

    summary_command = cov_command(llvm_cov, "export", objects, profile, sources)
    summary = subprocess.run(
        [*summary_command, "--summary-only"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (mode_dir / "summary.json").write_text(summary, encoding="utf-8")
    full = subprocess.run(
        summary_command,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (mode_dir / "coverage.json").write_text(full, encoding="utf-8")

    html_dir = mode_dir / "html"
    subprocess.run(
        [
            *cov_command(llvm_cov, "show", objects, profile, sources),
            "-format=html",
            f"-output-dir={html_dir}",
            "-show-branches=count",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return json.loads(summary)["data"][0]["totals"]


def function_regions(
    payload: dict[str, Any], source_names: set[str]
) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for function in payload["data"][0]["functions"]:
        filenames = function.get("filenames", [])
        if not filenames:
            continue
        selected = next(
            (
                (index, Path(candidate))
                for index, candidate in enumerate(filenames)
                if Path(candidate).name in source_names
                and Path(candidate).parent.name == "src"
            ),
            None,
        )
        if selected is None:
            continue
        file_index, filename = selected
        regions = {
            tuple(region[:4]): region[4]
            for region in function["regions"]
            if region[5] == file_index and region[7] == 0
        }
        branches = {
            (*branch[:4], outcome): branch[4 + outcome]
            for branch in function.get("branches", [])
            if branch[6] == file_index
            for outcome in (0, 1)
        }
        result[(filename.name, function["name"])] = {
            "file": filename.name,
            "function": function["name"],
            "line": min((location[0] for location in regions), default=0),
            "count": function["count"],
            "regions": regions,
            "branches": branches,
        }
    return result


def capture_gaps_from_payloads(
    all_payload: dict[str, Any],
    physical_payload: dict[str, Any],
    names: set[str],
) -> list[dict[str, Any]]:
    all_functions = function_regions(all_payload, names)
    physical_functions = function_regions(physical_payload, names)
    gaps = []
    for key, function in all_functions.items():
        physical = physical_functions.get(
            key, {"count": 0, "regions": {}, "branches": {}}
        )
        region_delta = sum(
            1
            for location, count in function["regions"].items()
            if count > 0 and physical["regions"].get(location, 0) == 0
        )
        branch_delta = sum(
            1
            for location, count in function["branches"].items()
            if count > 0 and physical["branches"].get(location, 0) == 0
        )
        function_delta = function["count"] > 0 and physical["count"] == 0
        if function_delta or region_delta or branch_delta:
            gaps.append(
                {
                    "file": function["file"],
                    "line": function["line"],
                    "function": function["function"],
                    "function_missing_physical_evidence": function_delta,
                    "covered_branch_outcomes_missing_physical_evidence": branch_delta,
                    "covered_regions_missing_physical_evidence": region_delta,
                }
            )
    gaps.sort(
        key=lambda item: (
            -item["function_missing_physical_evidence"],
            -item["covered_branch_outcomes_missing_physical_evidence"],
            -item["covered_regions_missing_physical_evidence"],
            item["file"],
            item["line"],
        )
    )
    return gaps


def capture_gaps(output_root: Path, sources: list[Path]) -> list[dict[str, Any]]:
    all_payload = json.loads(
        (output_root / "all" / "coverage.json").read_text(encoding="utf-8")
    )
    physical_payload = json.loads(
        (output_root / "physical" / "coverage.json").read_text(encoding="utf-8")
    )
    return capture_gaps_from_payloads(
        all_payload, physical_payload, {path.name for path in sources}
    )


def enforce_minimums(metrics: dict[str, dict[str, Any]]) -> None:
    failures = []
    for mode, categories in MINIMUM_PERCENT.items():
        for category, minimum in categories.items():
            actual = metrics[mode][category]["percent"]
            if actual < minimum:
                failures.append(f"{mode} {category}: {actual:.2f}% < {minimum:.2f}%")
    if failures:
        raise RuntimeError("coverage regression: " + "; ".join(failures))


def main() -> int:
    args = arguments()
    runner = args.runner.resolve()
    tests = [path.resolve() for path in args.test]
    repo_root = Path(__file__).resolve().parent.parent
    manifest = repo_root / "tests" / "vectors" / "desfire" / "manifest.json"
    sources = coverage_sources(repo_root)
    output_root = args.output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    llvm_profdata = llvm_tool("llvm-profdata")
    llvm_cov = llvm_tool("llvm-cov")

    selections = {
        "all": vector_paths(manifest, None),
        "physical": vector_paths(manifest, "physical-card"),
        "synthetic-unit": vector_paths(manifest, "synthetic"),
    }
    metrics = {
        mode: run_mode(
            mode,
            output_root,
            runner,
            tests,
            selections[mode],
            sources,
            llvm_profdata,
            llvm_cov,
        )
        for mode in MODES
    }
    gaps = capture_gaps(output_root, sources)
    (output_root / "capture-gaps.json").write_text(
        json.dumps(gaps, indent=2) + "\n", encoding="utf-8"
    )
    with (output_root / "capture-gaps.txt").open("w", encoding="utf-8") as stream:
        stream.write(
            "Covered by tests but missing replayable physical-vector evidence\n"
        )
        stream.write(" fn  branches  regions  location  function\n")
        for item in gaps:
            stream.write(
                f" {'yes' if item['function_missing_physical_evidence'] else ' no'}  "
                f"{item['covered_branch_outcomes_missing_physical_evidence']:8d}  "
                f"{item['covered_regions_missing_physical_evidence']:4d}  "
                f"{item['file']}:{item['line']}  {item['function']}\n"
            )

    totals = {
        "scope": [path.name for path in sources],
        "physical_evidence": "replayable physical-origin vectors",
        "modes": metrics,
        "capture_delta": {
            name: metrics["all"][name]["covered"] - metrics["physical"][name]["covered"]
            for name in ("lines", "branches", "functions", "regions")
        },
    }
    (output_root / "metrics.json").write_text(
        json.dumps(totals, indent=2) + "\n", encoding="utf-8"
    )
    for mode in MODES:
        values = metrics[mode]
        print(
            f"{mode:14s} lines={values['lines']['percent']:.2f}% "
            f"branches={values['branches']['percent']:.2f}% "
            f"functions={values['functions']['percent']:.2f}%"
        )
    print(
        f"capture queue: {len(gaps)} functions; see {output_root / 'capture-gaps.txt'}"
    )
    enforce_minimums(metrics)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
