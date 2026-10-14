"""Dispatch optional engines, bound their processes, and normalize JSON results."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from .analysis_constants import (
    MAX_STRING_LENGTH,
    MAX_TOOL_ITEMS,
    MAX_TOOL_OUTPUT,
    MINIMUM_STRING_LENGTH,
)
from .analysis_models import StageResult


def run_json_tool(command: list[str], sample: Path, timeout: int) -> StageResult:
    executable = shutil.which(command[0])
    if executable is None:
        return StageResult(
            "unavailable", notes=[f"Engine executable not found: {command[0]}"]
        )
    if Path(executable).resolve() == sample.resolve():
        return StageResult(
            "failed", notes=["Engine executable cannot be the analyzed sample"]
        )
    command = [executable, *command[1:]]
    try:
        return _run(command, timeout)
    except (OSError, ValueError, RecursionError) as error:
        return StageResult("failed", notes=[str(error)[:1000]])

def _run(command: list[str], timeout: int) -> StageResult:
    environment = dict(os.environ)
    environment.update(
        FLOSS_CACHE_ENABLE="0", FLOSS_SAVE_WORKSPACE="0", CAPA_SAVE_WORKSPACE="0"
    )
    app = str(Path(__file__).resolve().parents[1])
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, [app, environment.get("PYTHONPATH")])
    )
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        with subprocess.Popen(
            command,
            stdout=output,
            stderr=errors,
            stdin=subprocess.DEVNULL,
            env=environment,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ) as process:
            failure = _wait(process, output, errors, timeout)
            if failure:
                process.kill()
                process.wait()
                return StageResult("partial", notes=[failure])
            if process.returncode:
                errors.seek(0)
                detail = errors.read(1000).decode("utf-8", "replace")
                return StageResult(
                    "failed", notes=[f"Engine exited {process.returncode}: {detail}"]
                )
            output.seek(0)
            document = json.loads(output.read(MAX_TOOL_OUTPUT).decode("utf-8-sig"))
            if not isinstance(document, dict):
                raise ValueError("Engine JSON must contain an object")
            return StageResult("completed", details=document)

def _wait(process, output, errors, timeout):
    deadline = time.monotonic() + timeout
    while True:
        if (
            os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size
            > MAX_TOOL_OUTPUT
        ):
            return "Engine stopped at output byte limit"
        if process.poll() is not None:
            return None
        if time.monotonic() >= deadline:
            return f"Engine timed out after {timeout} seconds; no complete result"
        try:
            process.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass

def die_results(document: dict) -> StageResult:
    if not isinstance(document.get("detects"), list):
        raise ValueError("Unrecognized Detect It Easy JSON: expected detects list")
    results = []
    for group in document["detects"]:
        for value in group.get("values", []):
            if not isinstance(value, dict) or not value.get("name"):
                continue
            record = {
                key: value[key]
                for key in ("type", "name", "version", "info")
                if key in value
            }
            if record not in results:
                results.append(record)
            if len(results) >= MAX_TOOL_ITEMS:
                return StageResult(
                    "partial",
                    details={"detections": results},
                    notes=["DiE detections truncated"],
                )
    return StageResult(
        "completed", str(document.get("version", "unknown")), {"detections": results}
    )

def _matched_rules(node, names):
    """Find successful rule dependencies without listing their capabilities twice."""
    stack = [node]
    while stack:
        item = stack.pop()
        if not isinstance(item, dict) or item.get("success") is False:
            continue
        feature = item.get("node", {}).get("feature", {})
        if feature.get("type") == "match":
            names.add(feature.get("match"))
        stack.extend(item.get("children", []))

def capa_results(document: dict) -> StageResult:
    rules = document.get("rules")
    if not isinstance(rules, dict):
        raise ValueError("Unrecognized capa JSON: expected rules object")
    dependencies = set()
    for rule in rules.values():
        for match in rule.get("matches", []):
            if isinstance(match, list) and len(match) == 2:
                _matched_rules(match[1], dependencies)
    capabilities = []
    for name, rule in rules.items():
        meta = rule.get("meta", {})
        if name in dependencies or meta.get("lib") or meta.get("capa/subscope"):
            continue
        addresses = [
            match[0]
            for match in rule.get("matches", [])[:16]
            if isinstance(match, list) and match
        ]
        capabilities.append(
            {"name": name, "namespace": meta.get("namespace"), "locations": addresses}
        )
    truncated = len(capabilities) > MAX_TOOL_ITEMS
    return StageResult(
        "partial" if truncated else "completed",
        document.get("meta", {}).get("version"),
        {"capabilities": capabilities[:MAX_TOOL_ITEMS]},
        ["capa capabilities truncated"] if truncated else [],
    )

def floss_results(document: dict) -> StageResult:
    groups = document.get("strings")
    if not isinstance(groups, dict):
        raise ValueError("Unrecognized FLOSS JSON: expected strings object")
    results, seen = [], set()
    for group, values in groups.items():
        if group not in {
            "stack_strings",
            "tight_strings",
            "decoded_strings",
            "language_strings",
        }:
            continue
        for item in values:
            value = item.get("string")
            if not isinstance(value, str) or len(value) < MINIMUM_STRING_LENGTH or value in seen:
                continue
            seen.add(value)
            results.append(
                {
                    "value": value[:MAX_STRING_LENGTH],
                    "kind": group,
                    "function": item.get("function", item.get("decoding_routine")),
                    "decoded_at": item.get("decoded_at"),
                }
            )
            if len(results) >= MAX_TOOL_ITEMS:
                return StageResult(
                    "partial",
                    details={"recovered_strings": results},
                    notes=["FLOSS strings truncated"],
                )
    return StageResult(
        "completed",
        document.get("metadata", {}).get("version"),
        {"recovered_strings": results},
    )

def library_engine(name, path, timeout):
    result = run_json_tool(
        [
            sys.executable,
            "-m",
            "pe_analyzer.optional_worker",
            name,
            str(path.resolve()),
        ],
        path,
        timeout,
    )
    if result.status == "completed":
        try:
            return StageResult(**result.details)
        except TypeError:
            return StageResult("failed", notes=["Invalid parser worker result"])
    return result

def executable_engine(name, executable, path, timeout, *, rules=None, signatures=None):
    arguments = ["--json"] if name == "die" else ["-j"]
    if name == "capa" and rules:
        rule_path = Path(rules).expanduser().resolve()
        if not rule_path.exists():
            return StageResult(
                "unavailable", notes=[f"capa rules not found: {rule_path}"]
            )
        arguments.extend(["-r", str(rule_path)])
    if name == "capa" and signatures:
        signature_path = Path(signatures).expanduser().resolve()
        if not signature_path.exists():
            return StageResult(
                "unavailable", notes=[f"capa signatures not found: {signature_path}"]
            )
        arguments.extend(["-s", str(signature_path)])
    result = run_json_tool([executable, *arguments, str(path.resolve())], path, timeout)
    if result.status != "completed":
        return result
    try:
        return {"die": die_results, "capa": capa_results, "floss": floss_results}[name](
            result.details
        )
    except (ValueError, TypeError, AttributeError, KeyError) as error:
        return StageResult("failed", notes=[f"Unsupported {name} result: {error}"])

def run_optional_engines(path: Path, options, managed: bool, notify):
    results = {}
    for name in ("authenticode", "dotnet", "die", "capa", "floss"):
        requested = getattr(options, name)
        if not requested:
            results[name] = StageResult()
            continue
        notify(f"Running optional {name} analysis (up to {options.tool_timeout}s)")
        if name == "dotnet" and not managed:
            result = StageResult("not_applicable", notes=["No CLR directory"])
        elif name in {"dotnet", "authenticode"}:
            result = library_engine(name, path, options.tool_timeout)
        else:
            result = executable_engine(
                name,
                requested,
                path,
                options.tool_timeout,
                rules=options.capa_rules if name == "capa" else None,
                signatures=options.capa_signatures if name == "capa" else None,
            )
        results[name] = result
        notify(f"Optional {name}: {result.status}")
    return results
