"""Build, score, correlate, and consolidate static analyzer findings."""

from dataclasses import replace
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

import pefile

from .analysis_constants import (
    BEHAVIOR_CHAINS,
    DEBUG_QUERY_APIS,
    DIRECT_DEBUGGER_APIS,
    IMAGE_SCN_MEM_EXECUTE,
    INDICATOR_FINDING_CONFIG,
    MAX_EVIDENCE_ITEMS,
    NETWORK_ENDPOINT_APIS,
    PACKING_RULES,
    PROCESS_LAUNCH_APIS,
    REGISTRY_WRITE_APIS,
    SEVERITY_ORDER,
    SERVICE_CREATE_APIS,
    STARTUP_FILE_APIS,
)
from .analysis_models import (
    FlaggedAPI,
    OverlayInfo,
    ResourceInfo,
    SectionEntropy,
    SignatureInfo,
    StaticFinding,
    StringIndicator,
)
from .pe_structure import section_name


def finding(
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    score: int,
    confidence: float,
    evidence: Iterable[str],
    description: str,
) -> StaticFinding:
    return StaticFinding(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=list(evidence),
        description=description,
    )


def behavior_findings(import_names: set[str]) -> list[StaticFinding]:
    lowered = {name.lower() for name in import_names}
    results = []
    for rule_id, rule in BEHAVIOR_CHAINS.items():
        matched = []
        for alternatives in rule["required"]:
            match = next(
                (name for name in alternatives if name.lower() in lowered), None
            )
            if match is None:
                break
            matched.append(match)
        else:
            results.append(
                finding(
                    rule_id,
                    str(rule["title"]),
                    str(rule["category"]),
                    str(rule["severity"]),
                    int(rule["score"]),
                    float(rule["confidence"]),
                    matched,
                    "Native imports or managed P/Invoke declarations contain every API group needed for this behavior. "
                    "Declarations demonstrate capability, not execution order.",
                )
            )
    return results


def indicator_findings(
    indicators: list[StringIndicator], covered_evidence: set[str] | None = None
) -> list[StaticFinding]:
    """Report only indicator values not superseded by a strong correlation."""
    covered = covered_evidence or set()
    grouped: dict[str, list[StringIndicator]] = {}
    for indicator in indicators:
        if indicator.value.casefold() in covered:
            continue
        grouped.setdefault(indicator.category, []).append(indicator)
    results = []
    for category, config in INDICATOR_FINDING_CONFIG.items():
        title, finding_category, severity, score, confidence = config
        values = grouped.get(category, [])
        if values:
            results.append(
                finding(
                    f"strings_{category}",
                    title,
                    finding_category,
                    severity,
                    score,
                    confidence,
                    [item.value for item in values[:MAX_EVIDENCE_ITEMS]],
                    "Interesting strings are indicators only; they may be documentation or unused data.",
                )
            )
    return results


def strong_correlation_evidence(
    correlations: Iterable[StaticFinding],
) -> set[str]:
    """Only evidence explicitly named by high/critical correlations is covered."""
    return {
        value.casefold()
        for finding in correlations
        if finding.severity.lower() in {"high", "critical"}
        for value in finding.evidence
    }


def indicator_values(indicators: Iterable[StringIndicator], category: str) -> list[str]:
    """Keep exact, distinct evidence values for a single indicator category."""
    values = (item.value for item in indicators if item.category == category)
    return list(dict.fromkeys(values))[:MAX_EVIDENCE_ITEMS]


def correlated_findings(
    import_names: set[str], indicators: list[StringIndicator]
) -> list[StaticFinding]:
    names = {name.lower() for name in import_names}
    results = []
    registry_targets = indicator_values(indicators, "registry_persistence")
    startup_targets = indicator_values(indicators, "startup_folder")
    task_commands = indicator_values(indicators, "scheduled_task_creation")
    service_commands = indicator_values(indicators, "service_creation_command")
    debugger_queries = indicator_values(indicators, "debugger_query")
    if names & REGISTRY_WRITE_APIS and registry_targets:
        results.append(
            finding(
                "registry_persistence_correlation",
                "Registry persistence capability and target",
                "Persistence",
                "high",
                22,
                0.84,
                sorted(names & REGISTRY_WRITE_APIS) + registry_targets,
                "Registry-writing APIs occur together with a recognized persistence location.",
            )
        )
    if names & STARTUP_FILE_APIS and startup_targets:
        results.append(
            finding(
                "startup_folder_correlation",
                "Startup-folder target and file-copy capability",
                "Persistence",
                "high",
                16,
                0.76,
                sorted(names & STARTUP_FILE_APIS) + startup_targets,
                "File-copy or move APIs occur with a Startup-folder path; this "
                "suggests, but does not establish, logon persistence.",
            )
        )
    if names & PROCESS_LAUNCH_APIS and task_commands:
        results.append(
            finding(
                "scheduled_task_correlation",
                "Scheduled-task creation capability and command",
                "Persistence",
                "high",
                18,
                0.81,
                sorted(names & PROCESS_LAUNCH_APIS) + task_commands,
                "A task-creation command and process-launch APIs occur together; "
                "actual task registration is not established.",
            )
        )
    if names & PROCESS_LAUNCH_APIS and service_commands:
        results.append(
            finding(
                "service_command_correlation",
                "Service-creation capability and command",
                "Persistence",
                "high",
                18,
                0.80,
                sorted(names & PROCESS_LAUNCH_APIS) + service_commands,
                "A service-creation command and process-launch APIs occur together; "
                "actual service installation is not established.",
            )
        )
    if names & DEBUG_QUERY_APIS and debugger_queries:
        results.append(
            finding(
                "debugger_query_correlation",
                "Debugger-query API and debug-class string",
                "Anti-Analysis",
                "high",
                12,
                0.73,
                sorted(names & DEBUG_QUERY_APIS) + debugger_queries,
                "The import and debug-information class string support a possible "
                "debugger check, but call arguments are not verified.",
            )
        )
    command_names = indicator_values(indicators, "suspicious_command")
    ordinary_commands = [
        name
        for name in command_names
        if not (task_commands and name.lower().startswith("schtasks"))
    ]
    if names & PROCESS_LAUNCH_APIS and ordinary_commands:
        results.append(
            finding(
                "command_execution_correlation",
                "Process launch APIs and command-tool strings",
                "Execution",
                "medium",
                10,
                0.74,
                sorted(names & PROCESS_LAUNCH_APIS) + ordinary_commands,
                "The binary can launch processes and contains a command-tool name.",
            )
        )
    if names & NETWORK_ENDPOINT_APIS and indicator_values(indicators, "url"):
        results.append(
            finding(
                "network_endpoint_correlation",
                "Network APIs and embedded URL",
                "Network",
                "medium",
                8,
                0.70,
                sorted(names & NETWORK_ENDPOINT_APIS) + ["URL string"],
                "The binary contains both a network capability and an apparent endpoint.",
            )
        )
    return results


def capability_findings(import_names: set[str]) -> list[StaticFinding]:
    """Score specific imported capabilities without claiming they execute."""
    names = {name.lower() for name in import_names}
    results = []
    service_apis = names & SERVICE_CREATE_APIS
    if service_apis:
        results.append(
            finding(
                "service_configuration_capability",
                "Service creation or configuration API imports",
                "Persistence",
                "medium",
                9,
                0.68,
                sorted(service_apis),
                "These imports can install or modify a service, but no service "
                "creation or execution is established.",
            )
        )
    direct_debug = names & DIRECT_DEBUGGER_APIS
    if direct_debug:
        results.append(
            finding(
                "debugger_check_capability",
                "Direct debugger-check API imports",
                "Anti-Analysis",
                "low",
                min(9, 5 + 2 * (len(direct_debug) - 1)),
                0.68,
                sorted(direct_debug),
                "These APIs can check for a debugger; an import does not prove "
                "use or a debugger-dependent branch.",
            )
        )
    return results


def uncovered_api_finding(
    flagged: list[FlaggedAPI], scored_findings: Iterable[StaticFinding]
) -> StaticFinding | None:
    """Give remaining flagged imports a small capped score without double counting."""
    covered = {
        value.casefold()
        for finding in scored_findings
        if finding.score
        for value in finding.evidence
    }
    unique = {
        api.function_name.casefold(): api.function_name
        for api in flagged
        if api.function_name.casefold() not in covered
    }
    names = sorted(unique.values(), key=str.casefold)
    if not names:
        return None
    return finding(
        "additional_flagged_imports",
        "Additional flagged API imports",
        "Imported Capabilities",
        "low",
        min(8, len(names)),
        0.55,
        names[:MAX_EVIDENCE_ITEMS],
        "Imported APIs are capability clues only. Additional names have a "
        "small aggregate score; imports already scored in stronger findings "
        "are excluded.",
    )


def structural_findings(
    pe: pefile.PE,
    file_size: int,
    sections: list[SectionEntropy],
    entry_section: Any | None,
    callbacks: list[str],
    resources: list[ResourceInfo],
    overlay: OverlayInfo,
    signature: SignatureInfo,
    total_imports: int,
) -> tuple[list[StaticFinding], list[str]]:
    results, packer = [], []
    if entry_section is None and pe.OPTIONAL_HEADER.AddressOfEntryPoint:
        results.append(
            finding(
                "entry_point_unmapped",
                "Entry point is not mapped to a section",
                "PE Anomaly",
                "high",
                20,
                0.90,
                [hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)],
                "The declared entry-point RVA does not belong to any section.",
            )
        )
    elif (
        entry_section is not None
        and not entry_section.Characteristics & IMAGE_SCN_MEM_EXECUTE
    ):
        results.append(
            finding(
                "entry_point_non_executable",
                "Entry point is in a non-executable section",
                "PE Anomaly",
                "high",
                18,
                0.88,
                [section_name(entry_section)],
                "Normal PE entry points reside in executable sections.",
            )
        )

    raw_ranges = []
    for details, section in zip(sections, pe.sections):
        start, end = (
            section.PointerToRawData,
            section.PointerToRawData + section.SizeOfRawData,
        )
        if details.is_executable and details.is_writable:
            results.append(
                finding(
                    f"rwx_section_{details.name}",
                    "Writable and executable section",
                    "PE Permissions",
                    "high",
                    18,
                    0.90,
                    [details.name],
                    "Writable executable memory can support unpacking or self-modifying code.",
                )
            )
        if end > file_size and section.SizeOfRawData:
            results.append(
                finding(
                    f"section_outside_file_{details.name}",
                    "Section extends beyond end of file",
                    "PE Anomaly",
                    "high",
                    20,
                    0.94,
                    [details.name, hex(start), hex(end)],
                    "The declared raw section range exceeds the file size.",
                )
            )
        if section.SizeOfRawData:
            raw_ranges.append((start, end, details.name))
        if details.is_packed_suspicious:
            packer.extend(
                f"{details.name}: {reason}"
                for reason in details.suspicious_reasons
                if any(word in reason for word in ("entropy", "packer", "no raw data"))
            )

    raw_ranges.sort()
    for previous, current in zip(raw_ranges, raw_ranges[1:]):
        if current[0] < previous[1]:
            results.append(
                finding(
                    "overlapping_sections",
                    "Overlapping raw sections",
                    "PE Anomaly",
                    "high",
                    20,
                    0.92,
                    [previous[2], current[2]],
                    "Two section raw-data ranges overlap.",
                )
            )
            break

    if len(packer) >= 2:
        results.append(
            finding(
                "probable_packing",
                "Multiple packing indicators",
                "Packing",
                "medium",
                14,
                0.78,
                packer[:MAX_EVIDENCE_ITEMS],
                "Several independent section properties suggest packing or protection.",
            )
        )
    elif packer:
        results.append(
            finding(
                "single_packing_indicator",
                "One possible packing indicator",
                "Packing",
                "low",
                5,
                0.56,
                packer,
                "A single section property suggests packing or protection, "
                "but is not conclusive by itself.",
            )
        )
    if callbacks:
        results.append(
            finding(
                "tls_callbacks",
                "TLS callbacks execute before the entry point",
                "Execution",
                "medium",
                8,
                0.70,
                callbacks,
                "TLS callbacks are legitimate but can hide early execution.",
            )
        )

    embedded = [
        f"{item.resource_type}/{item.name}/{item.language}: {', '.join(item.anomalies)}; {'; '.join(item.evidence)}"
        for item in resources
        if any(
            "executable" in anomaly or "shellcode" in anomaly
            for anomaly in item.anomalies
        )
    ]
    if embedded:
        results.append(
            finding(
                "embedded_resource_payload",
                "Embedded file payload in resources",
                "Embedded Content",
                "medium",
                12,
                0.75,
                embedded[:MAX_EVIDENCE_ITEMS],
                "Resources contain executable headers or correlated shellcode byte signatures, "
                "possibly after decoding. This can be legitimate embedded code; execution is not established.",
            )
        )

    high_entropy_resources = [
        f"{item.resource_type}/{item.name}: entropy={item.entropy}"
        for item in resources
        if "unidentified high-entropy data" in item.anomalies
    ]
    if high_entropy_resources:
        results.append(
            finding(
                "high_entropy_resource",
                "High-entropy resource data",
                "Embedded Content",
                "low",
                6,
                0.60,
                high_entropy_resources[:MAX_EVIDENCE_ITEMS],
                "Compressed or encrypted-looking resources may contain hidden payloads.",
            )
        )

    malformed_resources = [
        f"{item.resource_type}/{item.name}/{item.language}: {', '.join(item.anomalies)}"
        for item in resources
        if any("range" in reason or "RVA" in reason for reason in item.anomalies)
    ]
    if malformed_resources:
        results.append(
            finding(
                "malformed_resource_data",
                "Invalid resource data range",
                "PE Anomaly",
                "medium",
                8,
                0.9,
                malformed_resources[:MAX_EVIDENCE_ITEMS],
                "Resource data does not map to complete file-backed section bytes.",
            )
        )

    if overlay.present and overlay.file_signatures:
        results.append(
            finding(
                "overlay_payload",
                "Recognizable file embedded in the PE overlay",
                "Embedded Content",
                "medium",
                12,
                0.78,
                overlay.file_signatures,
                "Data after the PE image contains a recognizable file format.",
            )
        )
    elif overlay.present and overlay.size >= 4096 and overlay.entropy >= 7.2:
        results.append(
            finding(
                "high_entropy_overlay",
                "Large high-entropy overlay",
                "Packing",
                "low",
                7,
                0.62,
                [f"size={overlay.size}", f"entropy={overlay.entropy}"],
                "The binary has a sizeable compressed or encrypted-looking overlay.",
            )
        )
    if total_imports <= 5 and len(packer) >= 2:
        results.append(
            finding(
                "sparse_imports_packed",
                "Sparse imports plus packing indicators",
                "Packing",
                "medium",
                10,
                0.76,
                [f"imports={total_imports}"],
                "Packed programs often resolve most APIs after unpacking.",
            )
        )

    timestamp = pe.FILE_HEADER.TimeDateStamp
    now = int(datetime.now(timezone.utc).timestamp())
    reproducible = any(
        item.struct.Type == 16 for item in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])
    )
    if (
        timestamp not in (0, 0xFFFFFFFF)
        and not reproducible
        and (timestamp < 631152000 or timestamp > now + 86400)
    ):
        results.append(
            finding(
                "implausible_timestamp",
                "Implausible compilation timestamp",
                "Metadata",
                "low",
                4,
                0.68,
                [str(timestamp)],
                "The header timestamp is before 1990 or in the future.",
            )
        )
    try:
        checksum = pe.OPTIONAL_HEADER.CheckSum
        if checksum and checksum != pe.generate_checksum():
            results.append(
                finding(
                    "checksum_mismatch",
                    "PE checksum does not match",
                    "Integrity",
                    "low",
                    3,
                    0.58,
                    [hex(checksum)],
                    "The stored nonzero checksum differs from the calculated checksum.",
                )
            )
    except (AttributeError, ValueError):
        pass
    if not signature.present:
        results.append(
            finding(
                "unsigned_binary",
                "No Authenticode signature present",
                "Trust",
                "informational",
                0,
                0.50,
                [],
                "Unsigned software is common; this is context, not malicious evidence.",
            )
        )
    elif signature.verification_status.startswith("malformed_"):
        outside_file = signature.verification_status == "malformed_outside_file"
        results.append(
            finding(
                "malformed_certificate_table",
                (
                    "Certificate table extends outside the file"
                    if outside_file
                    else "Malformed certificate table"
                ),
                "PE Anomaly",
                "high",
                18,
                0.94,
                [
                    signature.file_offset or "unknown",
                    f"size={signature.size}",
                    signature.verification_status,
                ],
                "The Authenticode data-directory range is structurally invalid.",
            )
        )
    return results, packer


PAYLOAD_RULES = {
    "embedded_resource_payload",
    "overlay_payload",
    "embedded_pe",
    "region_payload",
}


def extended_findings(extended):
    return (
        loader_findings(extended.structure)
        + entropy_findings(extended.entropy_regions)
        + payload_findings(extended)
        + signature_findings(extended.stages["authenticode"])
        + packer_findings(extended.stages["die"])
    )


def loader_findings(structure):
    results = []
    for kind, rule, title, score in (
        (
            "directory_range",
            "invalid_directories",
            "Data directories are not fully file-backed",
            8,
        ),
        ("tls_target", "invalid_tls_targets", "Invalid TLS callback targets", 12),
        ("tls_table", "invalid_tls_table", "Invalid TLS callback table", 8),
    ):
        issues = [
            f"{item['source']}: {item['detail']}"
            for item in structure
            if item["kind"] == kind
        ]
        if issues:
            results.append(
                finding(
                    rule,
                    title,
                    "PE Anomaly",
                    "medium",
                    score,
                    0.85,
                    issues,
                    "Structural inconsistency; execution is not established.",
                )
            )
    return results


def entropy_findings(entropy_regions):
    regions = [
        f"{item.source} at {item.file_offset}, {item.size} bytes, entropy {item.peak_entropy}"
        for item in entropy_regions
        if item.executable
    ]
    if not regions:
        return []
    return [
        finding(
            "local_entropy",
            "High-entropy regions in executable sections",
            "Packing",
            "low",
            5,
            0.55,
            regions,
            "Localized compression or encryption is possible; entropy alone is not conclusive.",
        )
    ]


def payload_findings(extended):
    results = []
    if extended.embedded_pes:
        results.append(
            finding(
                "embedded_pe",
                "Validated embedded PE images",
                "Embedded Content",
                "medium",
                12,
                0.9,
                [
                    f"{item.sha256}: {', '.join(item.sources)}"
                    for item in extended.embedded_pes
                ],
                "Complete child headers and file-backed section ranges were validated. Installers can legitimately embed executables.",
            )
        )
    region_evidence = [
        f"{item['origin']} {item['file_offset']}: {', '.join(item['anomalies'])}"
        for item in extended.regions
        if any(
            "executable" in value or "shellcode" in value for value in item["anomalies"]
        )
    ]
    if region_evidence:
        results.append(
            finding(
                "region_payload",
                "Executable-like content in additional regions",
                "Embedded Content",
                "medium",
                12,
                0.75,
                region_evidence,
                "Embedded headers or correlated shellcode signatures; not proof of execution.",
            )
        )
    return results


def signature_findings(signature):
    results = []
    mismatches = [
        item
        for item in signature.details.get("signatures", [])
        if item["file_digest"] == "mismatch"
    ]
    if mismatches:
        results.append(
            finding(
                "authenticode_digest_mismatch",
                "Signed file digest does not match",
                "Integrity",
                "high",
                18,
                0.98,
                [
                    f"Signature {index + 1}: {item['digest_algorithm']}"
                    for index, item in enumerate(mismatches)
                ],
                "At least one embedded signature covers a different file digest. This is an integrity failure, not a malware verdict.",
            )
        )
    failure_flags = (
        "BAD_SIGNATURE",
        "BAD_DIGEST",
        "CORRUPTED_AUTH_DATA",
        "CORRUPTED_CONTENT_INFO",
        "INVALID_SIGNER",
        "MISSING_PKCS9_MESSAGE_DIGEST",
        "INCONSISTENT_DIGEST_ALGORITHM",
    )
    failures = [
        item
        for item in signature.details.get("signatures", [])
        if item["file_digest"] == "valid"
        and any(flag in item.get("verification_flags", "") for flag in failure_flags)
    ]
    if failures:
        results.append(
            finding(
                "authenticode_signature_invalid",
                "Embedded signature is invalid",
                "Integrity",
                "high",
                12,
                0.9,
                [item["verification_flags"] for item in failures],
                "LIEF reported a definite embedded-signature failure with a matching file digest.",
            )
        )
    return results


def packer_findings(stage):
    results = []
    detections = stage.details.get("detections", [])
    packers = [
        f"{item.get('type')}: {item['name']} {item.get('version', '')}"
        for item in detections
        if str(item.get("type", "")).lower() in {"packer", "protector", "cryptor"}
    ]
    if packers:
        results.append(
            finding(
                "identified_packer",
                "Packer or protector identified",
                "Packing",
                "low",
                5,
                0.75,
                packers,
                "Signature identification from Detect It Easy; legitimate programs also use protection.",
            )
        )
    return results


def _merge(items, rule_id=None, title=None):
    strongest = max(items, key=lambda item: (item.score, item.confidence))
    evidence = list(dict.fromkeys(value for item in items for value in item.evidence))
    return replace(
        strongest,
        rule_id=rule_id or strongest.rule_id,
        title=title or strongest.title,
        evidence=evidence[:MAX_EVIDENCE_ITEMS],
        description=(
            "Related observations are consolidated here; the score is the largest component score, not their sum. "
            + strongest.description
            if rule_id is not None
            else strongest.description
        ),
    )


def consolidate_findings(findings):
    by_rule = {}
    for item in findings:
        by_rule.setdefault(item.rule_id, []).append(item)
    results = [_merge(items) for items in by_rule.values()]
    for family, rule, title in (
        (PACKING_RULES, "probable_packing", "Packing and protection indicators"),
        (PAYLOAD_RULES, "embedded_payload", "Embedded payload evidence"),
        (
            {"tls_callbacks", "invalid_tls_targets", "invalid_tls_table"},
            "tls_anomalies",
            "TLS callback evidence",
        ),
        (
            {
                "checksum_mismatch",
                "authenticode_digest_mismatch",
                "authenticode_signature_invalid",
            },
            "authenticode_digest_mismatch",
            "File integrity mismatch",
        ),
    ):
        members = [item for item in results if item.rule_id in family]
        if len(members) > 1:
            results = [item for item in results if item.rule_id not in family]
            results.append(_merge(members, rule, title))
    return sorted(
        results,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 4),
            -item.score,
            item.rule_id,
        ),
    )
