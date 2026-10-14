"""Select and render terminal evidence without loading analysis on import."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from pe_analyzer.analysis_models import BinaryAnalysisResult


def _useful_decoded_text(text: str | None) -> bool:
    if not text:
        return False
    letters = sum(character.isalpha() for character in text)
    return letters >= 3 and len(set(text.lower())) >= 5


def _decoded_api_names(text: str) -> list[str]:
    """Match whole decoded identifiers, without mistaking substrings for APIs."""
    from pe_analyzer.api_functions import iter_api_name_matches

    return list(dict.fromkeys(name for name, _ in iter_api_name_matches(text)))


def _persistence_summary(result: BinaryAnalysisResult) -> str | None:
    """Give scored persistence evidence a short, non-verdict summary label."""
    if not any(
        finding.category.casefold() == "persistence" and finding.score > 0
        for finding in result.findings
    ):
        return None
    techniques: list[str] = []
    for indicator in result.string_indicators:
        if indicator.category == "startup_folder":
            name = "Startup folder"
        elif indicator.category == "scheduled_task_creation":
            name = "scheduled task creation"
        elif indicator.category == "service_creation_command":
            name = "Windows service creation"
        elif indicator.category != "registry_persistence":
            continue
        else:
            path = indicator.value.casefold()
            if path.endswith("\\runonceex"):
                name = "Registry RunOnceEx key"
            elif path.endswith("\\runonce"):
                name = "Registry RunOnce key"
            elif path.endswith("\\run"):
                name = "Registry Run key"
            elif "\\services" in path:
                name = "Windows service registry key"
            elif "\\winlogon" in path:
                name = "Winlogon registry key"
            elif "image file execution options" in path:
                name = "Image File Execution Options key"
            else:
                name = "Persistence-related registry key"
        if name not in techniques:
            techniques.append(name)
    return (
        ", ".join(techniques)
        if techniques
        else "Possible service persistence capability"
    )


def _string_view(result: BinaryAnalysisResult) -> dict[str, Any] | None:
    if result.minimum_string_length is None:
        return None
    items: list[dict[str, Any]] = []
    for item in result.strings:
        if len(item.value) < result.minimum_string_length:
            continue
        decoded = [
            {
                "encoding": part.encoding,
                "text": part.text,
                "api_names": _decoded_api_names(part.text),
            }
            for part in item.decoded
            if part.text
            and (_useful_decoded_text(part.text) or _decoded_api_names(part.text))
        ]
        hash_matches = [
            asdict(candidate)
            for candidate in item.suspected_hashes
            if candidate.api_matches
        ]
        entry: dict[str, Any] = {
            "value": item.value,
            "decoded": decoded,
            "hash_matches": hash_matches,
        }
        if hash_matches or any(part["api_names"] for part in decoded):
            entry["offset"] = item.offset
            entry["encoding"] = item.encoding
        items.append(entry)
    return {
        "count": len(items),
        "items": items,
    }


def _manifest_requests(metadata: dict[str, Any]) -> list[str]:
    """Show only manifest privilege requests that affect how Windows launches the file."""
    requests = []
    for manifest in metadata.get("manifests", []):
        level = manifest.get("requested_execution_level")
        if level == "requireAdministrator":
            requests.append("Administrator privileges requested")
        elif level == "highestAvailable":
            requests.append("Highest available privileges requested")
        if str(manifest.get("ui_access", "false")).lower() == "true":
            requests.append("UI access requested")
    return list(dict.fromkeys(requests))


def _terminal_analysis(result: BinaryAnalysisResult, *, verbose: bool) -> dict[str, Any]:
    """Keep supporting evidence that adds information to the terminal findings."""
    from .report_serialization import extended_report

    analysis = extended_report(result.extended, verbose=verbose)
    # Raw build records belong in JSON. Directory/TLS and entropy evidence is
    # already represented by findings and suspicious PE sections in the terminal.
    for key in ("build_metadata", "structure", "entropy_regions"):
        analysis.pop(key, None)
    for stage in analysis.get("coverage", {}).values():
        # The same warnings are collected in the single Analysis notes section.
        stage.pop("notes", None)

    if not verbose:
        regions = [
            item for item in analysis.get("regions", []) if item.get("anomalies")
        ]
        if regions:
            analysis["regions"] = regions
        else:
            analysis.pop("regions", None)

        optional_evidence = {
            "authenticode": lambda details: details.get("embedded_signature") == "present",
            "dotnet": lambda details: bool(details),
            "die": lambda details: bool(details.get("detections")),
            "capa": lambda details: bool(details.get("capabilities")),
            "floss": lambda details: bool(details.get("recovered_strings_count")),
        }
        coverage = {
            name: stage
            for name, stage in analysis.get("coverage", {}).items()
            if stage.get("status") in {"failed", "partial", "unavailable"}
            or (
                stage.get("status") == "completed"
                and name in optional_evidence
                and optional_evidence[name](stage.get("details", {}))
            )
        }
        if coverage:
            analysis["coverage"] = coverage
        else:
            analysis.pop("coverage", None)

    requests = _manifest_requests(result.extended.metadata)
    if requests:
        analysis = {"manifest_requests": requests, **analysis}
    return analysis


def _terminal_findings(result: BinaryAnalysisResult, *, verbose: bool) -> list[dict[str, Any]]:
    """Keep scored conclusions without repeating section packing evidence."""
    section_evidence = {
        f"{section.name}: {reason}"
        for section in result.sections
        for reason in section.suspicious_reasons
    }
    findings = []
    for item in result.findings:
        if item.rule_id == "api_hash_matches" or (
            not verbose and item.severity.lower() == "informational" and item.score == 0
        ):
            continue
        details = asdict(item)
        if item.category == "Packing":
            details["evidence"] = [
                value for value in details["evidence"] if value not in section_evidence
            ]
            if not details["evidence"]:
                del details["evidence"]
        findings.append(details)
    return findings


def terminal_report(
    result: BinaryAnalysisResult, *, verbose: bool = False
) -> dict[str, Any]:
    """Keep file identity first, and suppress routine context by default."""
    from pe_analyzer.hashes import api_hash_evidence

    from .report_serialization import binary_analysis_to_dict

    concise = binary_analysis_to_dict(result)
    report: dict[str, Any] = {"file": concise["file"]}
    finding_counts = {
        "flagged_apis": len(result.flagged_apis),
        "hashed_functions": len(
            api_hash_evidence(result.api_hash_matches, result.strings)
        ),
    }
    persistence = _persistence_summary(result)
    if verbose:
        report.update(concise)
        for key in ("resources", "yara", "is_probably_packed"):
            report["summary"].pop(key, None)
        analysis = _terminal_analysis(result, verbose=True)
        if analysis:
            report["analysis"] = analysis
        else:
            report.pop("analysis", None)
        if persistence:
            report["summary"]["possible_persistence"] = persistence
        report["finding_counts"] = finding_counts
        if result.minimum_string_length is not None:
            report["strings"] = _string_view(result)
        report["imports"]["all_imports"] = result.all_imports
        report["pe"] = {
            "entry_point_rva": result.entry_point_rva,
            "entry_point_section": result.entry_point_section,
            "sections": [asdict(item) for item in result.sections],
            "resources": [asdict(item) for item in result.resources],
            "security_features": result.security_features,
            "signature": asdict(result.signature),
            "overlay": asdict(result.overlay),
            "tls_callbacks": result.tls_callbacks,
            "exports": result.exports,
            "debug_paths": result.debug_paths,
        }
        report["findings"] = _terminal_findings(result, verbose=True)
        report["summary"]["finding_count"] = len(report["findings"])
        report["indicators"] = [asdict(item) for item in result.string_indicators]
        report["analysis_notes"] = result.analysis_notes
        return report

    if result.minimum_string_length is not None:
        report["strings"] = _string_view(result)
        if result.analysis_notes:
            report["analysis_notes"] = result.analysis_notes
        return report

    findings = _terminal_findings(result, verbose=False)
    matches = result.yara_scan.matched_rules if result.yara_scan else []
    sections = [
        asdict(item)
        for item in result.sections
        if item.suspicious_reasons or item.is_packed_suspicious
    ]
    resources = [asdict(item) for item in result.resources if item.anomalies]
    has_evidence = bool(
        findings
        or matches
        or sections
        or resources
        or result.flagged_apis
        or result.string_indicators
        or result.api_hash_matches
    )
    if has_evidence:
        report["summary"] = {
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "suspicious_finding_count": len(findings),
            "suspicious_section_count": len(sections),
        }
        if persistence:
            report["summary"]["possible_persistence"] = persistence
    if findings or any(finding_counts.values()):
        report["finding_counts"] = finding_counts
        report["findings"] = findings
    if result.flagged_apis:
        report["imports"] = {
            "flagged_apis": [asdict(item) for item in result.flagged_apis],
            "interpretation": "Imported capabilities; presence does not prove execution.",
        }
    pe_details: dict[str, Any] = {}
    if sections:
        pe_details["suspicious_sections"] = sections
    if resources:
        pe_details["suspicious_resources"] = resources
    if pe_details:
        report["pe"] = pe_details
    if result.string_indicators:
        report["indicators"] = [asdict(item) for item in result.string_indicators]
    if result.api_hash_matches:
        report["api_hash_matches"] = [asdict(item) for item in result.api_hash_matches]
    if matches:
        report["yara_matches"] = {
            "matched_rules": matches,
            "interpretation": "User-supplied rule matches; not a malware verdict.",
        }
    if not has_evidence:
        report["status"] = {"result": "No suspicious findings detected."}

    extended = _terminal_analysis(result, verbose=False)
    if extended:
        report["analysis"] = extended

    # Coverage limitations remain visible even when routine results are hidden.
    notes = list(result.analysis_notes)
    for resource in result.resources:
        notes.extend(
            f"Resource {resource.name}: {note}" for note in resource.inspection_notes
        )
    if notes:
        report["analysis_notes"] = list(dict.fromkeys(notes))
    return report

def color_text(text: str, code: str, enabled: bool) -> str:
    """Wrap text in ANSI styling when the selected output supports color."""
    return f"\033[{code}m{text}\033[0m" if enabled else text
def supports_color(stream: TextIO) -> bool:
    if not stream.isatty() or "NO_COLOR" in os.environ:
        return False
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        try:
            handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
            mode = wintypes.DWORD()
            kernel = ctypes.windll.kernel32
            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel.SetConsoleMode(handle, mode.value | 0x0004))
        except (OSError, ValueError, AttributeError):
            return False
    return True


def safe_text(value: object) -> str:
    """Keep strings extracted from binaries from controlling the terminal."""
    return "".join(
        char if char.isprintable() else repr(char)[1:-1] for char in str(value)
    )


class ConsoleReport:
    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.color_enabled = supports_color(self.stream)

    def color(self, text: str, code: str) -> str:
        return color_text(text, code, self.color_enabled)

    def progress(self, message: str) -> None:
        print(self.color("[+]", "92"), safe_text(message), file=self.stream, flush=True)

    def _flagged_apis(self, apis: list[dict[str, Any]], indent: int) -> None:
        groups: dict[str, list[dict[str, Any]]] = {}
        for api in apis:
            groups.setdefault(api["dll"], []).append(api)
        padding = " " * indent
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
        for dll, entries in groups.items():
            print(file=self.stream)
            print(
                padding
                + self.color(safe_text(dll), "1;95")
                + self.color(f"  ({len(entries)} flagged)", "90"),
                file=self.stream,
            )
            names = [safe_text(api["function_name"]) for api in entries]
            column_width = max(map(len, names))
            for name, api in zip(names, entries):
                category = safe_text(api["category"])
                if indent + column_width + len(category) + 7 <= width:
                    print(
                        padding
                        + "  "
                        + self.color(name.ljust(column_width), "1;97")
                        + self.color("  |  ", "90")
                        + self.color(category, "93"),
                        file=self.stream,
                    )
                else:
                    print(
                        padding + "  " + self.color(name, "1;97"),
                        file=self.stream,
                    )
                    print(
                        padding + "    " + self.color(category, "93"),
                        file=self.stream,
                    )
        print(file=self.stream)

    def _strings(self, details: dict[str, Any]) -> None:
        """Keep ordinary strings compact; expand only flagged API matches."""
        print(
            self.color(f"  {details['count']} extracted", "90"),
            file=self.stream,
        )
        for item in details["items"]:
            original = safe_text(item["value"])
            base64_parts = [
                part for part in item["decoded"]
                if "base64" in part["encoding"].lower()
            ]
            primary = max(
                base64_parts,
                key=lambda part: part["encoding"].count("->"),
                default=None,
            )
            if primary is not None:
                decoded_text = safe_text(primary["text"])
                if len(decoded_text) > 240:
                    decoded_text = decoded_text[:237] + "..."
                print(
                    "  " + self.color("- " + decoded_text, "1;97"),
                    file=self.stream,
                )
            else:
                if len(original) > 120:
                    original = original[:117] + "..."
                print("  " + self.color("- " + original, "1;97"), file=self.stream)
            decoded_api_parts = [
                part for part in item["decoded"] if part["api_names"]
            ]
            if not decoded_api_parts and not item["hash_matches"]:
                continue
            if item.get("offset"):
                print(
                    "    " + self.color(
                        f"offset {item['offset']} | {item['encoding']}", "90"
                    ),
                    file=self.stream,
                )
            for decoded in decoded_api_parts:
                names = ", ".join(safe_text(name) for name in decoded["api_names"])
                print(
                    "    " + self.color("flagged API in decoded text: ", "93")
                    + names
                    + self.color(f" ({safe_text(decoded['encoding'])})", "90"),
                    file=self.stream,
                )
            for candidate in item["hash_matches"]:
                digest = safe_text(candidate["value"])
                for match in candidate["api_matches"]:
                    hashed_name = match.get("hashed_name", match["api_name"])
                    encoding = match.get("encoding", "ascii")
                    variant = (
                        f"; hashed as {safe_text(hashed_name)} ({encoding})"
                        if hashed_name != match["api_name"] or encoding != "ascii"
                        else ""
                    )
                    print(
                        "    " + self.color("possible API hash: ", "93")
                        + f"{digest} = {safe_text(match['api_name'])} "
                        + self.color(
                            f"({match['algorithm']}; {safe_text(match['category'])}{variant})",
                            "90",
                        ),
                        file=self.stream,
                    )

    def _api_hash_matches(self, matches: list[dict[str, Any]]) -> None:
        """Show only catalog matches, one compact line per occurrence."""
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
        for match in matches:
            lead = f"  {match['offset']}  {safe_text(match['api_name'])}"
            context = (
                f"{match['algorithm']} {match['value']} "
                f"({match['byte_order']}; {safe_text(match['category'])})"
            )
            hashed_name = match.get("hashed_name", match["api_name"])
            encoding = match.get("encoding", "ascii")
            if hashed_name != match["api_name"] or encoding != "ascii":
                context += f"  [{encoding}: {safe_text(hashed_name)}]"
            if len(lead) + len(context) + 2 <= width:
                print(
                    self.color(lead, "1;97") + "  " + self.color(context, "93"),
                    file=self.stream,
                )
            else:
                print(self.color(lead, "1;97"), file=self.stream)
                print("    " + self.color(context, "93"), file=self.stream)
        print(
            self.color("  Possible name matches; a hash alone does not prove use.", "90"),
            file=self.stream,
        )

    def _finding_counts(self, counts: dict[str, int]) -> None:
        for label, key in (
            ("Flagged APIs", "flagged_apis"),
            ("Hashed functions", "hashed_functions"),
        ):
            count = counts[key]
            print(
                "  " + self.color(f"{label}: ", "1")
                + self.color(str(count), "93" if count else "90"),
                file=self.stream,
            )

    def _details(self, value: Any, indent: int = 2) -> None:
        padding = " " * indent
        if isinstance(value, dict):
            for key, item in value.items():
                label = safe_text(key.replace("_", " ").capitalize())
                if key == "flagged_apis" and item:
                    self._flagged_apis(item, indent)
                    continue
                if isinstance(item, (dict, list)) and item:
                    print(padding + self.color(label + ":", "1"), file=self.stream)
                    self._details(item, indent + 2)
                else:
                    display = self._value(item)
                    if key in {"severity", "risk_level"}:
                        code = {
                            "critical": "91",
                            "high": "91",
                            "medium": "93",
                            "low": "96",
                            "informational": "94",
                        }.get(str(item), "0")
                        display = self.color(display.upper(), code)
                    elif key == "possible_persistence":
                        display = self.color(display, "1;93")
                    print(
                        padding + self.color(label + ":", "90") + f" {display}",
                        file=self.stream,
                    )
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    title_key = next(
                        (
                            key
                            for key in ("title", "name", "value", "encoding")
                            if item.get(key)
                        ),
                        None,
                    )
                    title = self._value(item[title_key]) if title_key else "Details"
                    print(padding + self.color("- " + title, "1;97"), file=self.stream)
                    self._details(
                        {key: entry for key, entry in item.items() if key != title_key},
                        indent + 2,
                    )
                    print(file=self.stream)
                elif isinstance(item, list):
                    self._details(item, indent)
                else:
                    print(padding + self.color("- ", "96") + self._value(item), file=self.stream)

    @staticmethod
    def _value(value: Any) -> str:
        if value is None:
            return "Unknown"
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if value == [] or value == {}:
            return "None"
        return safe_text(value)

    def render(self, report: dict[str, Any]) -> None:
        titles = {
            "summary": "Analysis summary",
            "file": "File details",
            "findings": "Findings",
            "indicators": "String indicators",
            "imports": "Imports and flagged APIs",
            "pe": "PE structure and security",
            "strings": "Extracted strings",
            "api_hash_matches": "Possible API hash matches",
            "analysis_notes": "Analysis notes",
        }
        for key, value in report.items():
            if key == "finding_counts":
                continue
            title = titles.get(key, key.replace("_", " ").title())
            print("\n" + self.color(title.upper(), "1;96"), file=self.stream)
            print(self.color("-" * len(title), "96"), file=self.stream)
            if key == "findings":
                counts = report.get("finding_counts")
                if counts:
                    self._finding_counts(counts)
                    if value:
                        print(file=self.stream)
                self._details(value)
            elif key == "strings" and "items" in value:
                self._strings(value)
            elif key == "api_hash_matches":
                self._api_hash_matches(value)
            else:
                self._details(value)
            if key == "summary":
                print(
                    "  Static evidence indicates capabilities, not a malware verdict.",
                    file=self.stream,
                )
