"""Serialize core and extended PE analysis to JSON-ready report data."""

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from pe_analyzer.analysis_models import BinaryAnalysisResult


DEFAULT_OUTPUT_DIRECTORY = Path(__file__).resolve().parent / "reports"


def extended_report(extended, *, verbose=False):
    report = {}
    metadata = {
        key: value for key, value in extended.metadata.items() if value or verbose
    }
    if metadata:
        report["build_metadata"] = metadata
    for key in ("structure", "entropy_regions", "embedded_pes", "regions"):
        values = getattr(extended, key)
        if values:
            report[key] = [
                asdict(item) if hasattr(item, "__dataclass_fields__") else item
                for item in values
            ]
    coverage = {}
    for name, stage in extended.stages.items():
        if stage.status == "not_requested" and not verbose:
            continue
        item = asdict(stage)
        # Full strings live in the strings view; indicators retain source context.
        for key in ("recovered_strings", "user_strings"):
            if key in item["details"]:
                values = item["details"].pop(key)
                item["details"][key + "_count"] = len(values)
        coverage[name] = _without_empty_values(item)
    if coverage:
        report["coverage"] = coverage
    return report


def _without_empty_values(data: dict[str, Any]) -> dict[str, Any]:
    """Remove values that add no information while preserving False and zero."""
    return {
        key: value
        for key, value in data.items()
        if value is not None and value != [] and value != {}
    }


def _relevant_sections(result: BinaryAnalysisResult) -> list[dict[str, Any]]:
    return [
        _without_empty_values(asdict(section))
        for section in result.sections
        if section.suspicious_reasons
    ]


def _relevant_resources(result: BinaryAnalysisResult) -> list[dict[str, Any]]:
    return [
        _without_empty_values(asdict(resource))
        for resource in result.resources
        if resource.anomalies or resource.inspection_notes
    ]


def binary_analysis_to_dict(
    result: BinaryAnalysisResult,
    *,
    include_all_imports: bool = False,
) -> dict[str, Any]:
    """Create a concise, finding-oriented JSON report.

    The complete import table remains available on ``BinaryAnalysisResult`` and can
    be included for debugging with ``include_all_imports=True``.
    """
    if not isinstance(result, BinaryAnalysisResult):
        raise TypeError("result must be a BinaryAnalysisResult instance")

    suspicious_sections = _relevant_sections(result)
    suspicious_resources = _relevant_resources(result)
    file_details = asdict(result.file_metadata)
    file_details.pop("is_packed")

    signature_details = {"present": False}
    if result.signature.present:
        signature_details = _without_empty_values(asdict(result.signature))

    pe_details: dict[str, Any] = {
        "entry_point": _without_empty_values(
            {
                "rva": result.entry_point_rva,
                "section": result.entry_point_section,
            }
        ),
        "section_count": len(result.sections),
        "security_features": result.security_features,
        "signature": signature_details,
        "suspicious_sections": suspicious_sections,
        "tls_callbacks": result.tls_callbacks,
        "packer_indicators": result.packer_indicators,
        "overlay": asdict(result.overlay) if result.overlay.present else None,
        "suspicious_resources": suspicious_resources,
        "resource_count": len(result.resources),
        "decoded_resources": [
            _without_empty_values(asdict(item))
            for item in result.resources
            if item.decoded and not item.anomalies and not item.inspection_notes
        ],
        "exports": result.exports,
        "debug_paths": result.debug_paths,
    }

    import_details: dict[str, Any] = {
        "dll_count": result.total_dlls,
        "function_count": result.total_imports,
        "flagged_apis": [asdict(api) for api in result.flagged_apis],
    }
    if include_all_imports:
        import_details["all_imports"] = result.all_imports

    return _without_empty_values(
        {
            "summary": {
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "finding_count": len(result.findings),
                "is_probably_packed": result.file_metadata.is_packed,
                **(
                    {
                        "yara": {
                            "rules_file": result.yara_scan.rules_file,
                            "matched": bool(result.yara_scan.matched_rules),
                            "match_count": len(result.yara_scan.matched_rules),
                            "matched_rules": result.yara_scan.matched_rules,
                        }
                    }
                    if result.yara_scan is not None
                    else {}
                ),
                "resources": {
                    "count": len(result.resources),
                    "anomalous_count": sum(
                        bool(item.anomalies) for item in result.resources
                    ),
                    "items": [
                        _without_empty_values(
                            {
                                "resource_type": item.resource_type,
                                "name": item.name,
                                "language": item.language,
                                "suspected_name": item.suspected_name,
                                "suspected_role": item.suspected_role,
                                "detected_type": item.detected_type,
                                "size": item.size,
                                "origin": item.origin,
                                "anomalies": item.anomalies,
                                "decodings": [
                                    decoded.encoding for decoded in item.decoded
                                ],
                                "inspection_notes": item.inspection_notes,
                            }
                        )
                        for item in result.resources
                    ],
                },
            },
            "file": _without_empty_values(file_details),
            "findings": [
                _without_empty_values(asdict(finding)) for finding in result.findings
            ],
            "indicators": [
                _without_empty_values(asdict(indicator))
                for indicator in result.string_indicators
            ],
            "imports": _without_empty_values(import_details),
            "pe": _without_empty_values(pe_details),
            "strings": (
                {
                    "minimum_length": result.minimum_string_length,
                    "count": sum(
                        len(item.value) >= result.minimum_string_length
                        for item in result.strings
                    ),
                    "items": [
                        asdict(item)
                        for item in result.strings
                        if len(item.value) >= result.minimum_string_length
                    ],
                }
                if result.minimum_string_length is not None
                else None
            ),
            "analysis_notes": result.analysis_notes,
            "analysis": extended_report(result.extended, verbose=True),
            "api_hash_matches": [asdict(item) for item in result.api_hash_matches],
        }
    )


# Backward-compatible alias for code that used the original public function name.
BAResult_to_dict = binary_analysis_to_dict


def save_dict_to_json(
    analysis: BinaryAnalysisResult | dict[str, Any],
    filename: str | None = None,
    output_dir: str | Path | None = None,
    *,
    include_all_imports: bool = False,
) -> Path:
    """Save an analysis result or existing dictionary as formatted JSON."""
    if isinstance(analysis, BinaryAnalysisResult):
        data = binary_analysis_to_dict(
            analysis,
            include_all_imports=include_all_imports,
        )
    elif isinstance(analysis, dict):
        data = analysis
    else:
        raise TypeError("analysis must be a BinaryAnalysisResult or dictionary")

    target_directory = Path(output_dir or DEFAULT_OUTPUT_DIRECTORY).resolve()
    target_directory.mkdir(parents=True, exist_ok=True)

    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = target_directory / f"output_{timestamp}.json"
    else:
        file_path = (target_directory / filename).with_suffix(".json")

    try:
        with file_path.open("w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
    except OSError as error:
        raise OSError(f"Failed to write JSON file to {file_path}: {error}") from error

    print(f"Successfully saved JSON to: {file_path}")
    return file_path
