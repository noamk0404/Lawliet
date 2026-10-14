"""Coordinate PE analysis and combine the results from specialized modules."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pefile

from .analysis_constants import MAX_EVIDENCE_ITEMS, MINIMUM_STRING_LENGTH, PACKING_RULES
from .analysis_models import AnalysisOptions, BinaryAnalysisResult, ExtendedAnalysis, StageResult
from .anti_debug import anti_debug_code_findings
from .content_decoding import DecodeBudget
from .embedded_payloads import PayloadInspector
from .entropy import scan_entropy_regions
from .hashes import api_hash_evidence, calculate_file_hashes, scan_binary_api_hashes
from .metadata import extract_build_metadata, extract_file_metadata
from .optional_engines import run_optional_engines
from .findings import (
    behavior_findings,
    capability_findings,
    consolidate_findings,
    correlated_findings,
    extended_findings,
    finding,
    indicator_findings,
    strong_correlation_evidence,
    structural_findings,
    uncovered_api_finding,
)
from .pe_structure import (
    entropy_ranges,
    extract_debug_paths,
    extract_exports,
    extract_imports,
    extract_overlay_info,
    extract_sections,
    extract_security_features,
    extract_tls_callbacks,
    section_name,
    validate_loader,
)
from .resources import extract_resources, inspect_extra_regions
from .signatures import extract_signature_info
from .strings import (
    analyze_strings,
    decoded_string_indicators,
    enrichment_strings,
    filter_imported_api_indicators,
    unique_indicators,
)
from .yara_scanner import scan_yara_rules


def collect_extended(
    path,
    pe,
    data,
    resources,
    overlay,
    inspector,
    budget,
    options,
    threshold,
    notes,
    notify,
):
    result = ExtendedAnalysis()
    stages = (
        ("build_metadata", lambda: extract_build_metadata(pe, data, resources, notes)),
        ("loader_validation", lambda: validate_loader(pe, data, notes)),
        (
            "local_entropy",
            lambda: scan_entropy_regions(
                entropy_ranges(pe, overlay), data, options.entropy_window, threshold, notes
            ),
        ),
        (
            "additional_regions",
            lambda: inspect_extra_regions(pe, data, overlay, inspector, budget, notes),
        ),
    )
    fields = ("metadata", "structure", "entropy_regions", "regions")
    for (name, collect), field in zip(stages, fields):
        before = len(notes)
        setattr(result, field, collect())
        result.stages[name] = StageResult(
            "partial" if len(notes) > before else "completed"
        )
    result.embedded_pes = list(inspector.payloads.values())
    notes.extend(budget.notes)
    result.stages["embedded_content"] = StageResult(
        "partial"
        if budget.notes
        or any(item.inspection_notes for item in resources)
        or any("Embedded" in note or "Resource inspection" in note for note in notes)
        else "completed",
        details={"unique_pe_count": len(result.embedded_pes)},
    )
    notify(
        "Inspected build metadata, loader ranges, local entropy, and embedded images"
    )
    result.stages.update(
        run_optional_engines(path, options, result.metadata["managed"], notify)
    )
    for name, stage in result.stages.items():
        if stage.status in {"failed", "partial", "unavailable"}:
            notes.extend(f"{name}: {note}" for note in stage.notes)
    return result

def managed_imports(extended):
    return {
        item["function"]
        for item in extended.stages["dotnet"].details.get("pinvokes", [])
    }

def analyze_pe_binary(
    executable_path: str | Path,
    high_entropy_threshold: float = 7.0,
    *,
    minimum_string_length: int | None = None,
    yara_rules_path: str | Path | None = None,
    progress: Callable[[str], None] | None = None,
    analysis_options: AnalysisOptions | None = None,
) -> BinaryAnalysisResult:
    """Perform non-disassembly static analysis of a Windows PE binary."""
    notify = progress if progress is not None else lambda message: None
    options = analysis_options or AnalysisOptions()
    options.validate()
    path = Path(executable_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {executable_path}")
    if not 0.0 <= high_entropy_threshold <= 8.0:
        raise ValueError("high_entropy_threshold must be between 0.0 and 8.0")
    if minimum_string_length is not None and (
        isinstance(minimum_string_length, bool)
        or not isinstance(minimum_string_length, int)
        or minimum_string_length < 1
    ):
        raise ValueError("minimum_string_length must be a positive integer or None")

    file_data = path.read_bytes()
    pe = pefile.PE(str(path), fast_load=False)
    try:
        with ThreadPoolExecutor(
            max_workers=3, thread_name_prefix="pe-analysis"
        ) as workers:
            notify("Loaded file and parsed PE headers")
            # Workers receive only a path or immutable bytes. The mutable PE parser,
            # collected notes, and progress callbacks remain on the calling thread.
            hash_scan_future = workers.submit(scan_binary_api_hashes, path)
            file_hashes_future = workers.submit(calculate_file_hashes, path)
            yara_future = (
                workers.submit(scan_yara_rules, file_data, yara_rules_path)
                if yara_rules_path is not None
                else None
            )
            imports, flagged_apis, total_imports = extract_imports(pe)
            notify(
                f"Extracted imports: {total_imports} functions from {len(imports)} DLLs"
            )
            import_names = {
                name
                for dll in imports.values()
                for name in dll["functions"]
                if not name.startswith("Ordinal_")
            }
            dll_names = [name.removesuffix(" (delay)") for name in imports]
            notes: list[str] = []
            inspector = PayloadInspector(notes)
            decode_budget = DecodeBudget()
            scan_minimum = min(
                MINIMUM_STRING_LENGTH, minimum_string_length or MINIMUM_STRING_LENGTH
            )
            strings, indicators = analyze_strings(file_data, scan_minimum, notes)
            notify(f"Extracted and analyzed strings: {len(strings)} retained")
            metadata = extract_file_metadata(
                path,
                pe,
                dll_names,
                [item.value for item in strings],
                file_hashes=file_hashes_future.result(),
            )
            notify("Computed hashes and extracted file metadata")
            sections = extract_sections(pe, high_entropy_threshold)
            notify(
                f"Analyzed section permissions and entropy: {len(sections)} sections"
            )
            resources = extract_resources(
                pe,
                include_text=True,
                notes=notes,
                on_content=inspector.inspect,
                decode_budget=decode_budget,
            )
            for resource in resources:
                for decoded in resource.decoded:
                    if decoded.text and len(decoded.text) >= MINIMUM_STRING_LENGTH:
                        found = decoded_string_indicators(
                            decoded,
                            f"resource {resource.resource_type}/{resource.name}/{resource.language} ({decoded.encoding})",
                        )
                        indicators.extend(found)
                    if minimum_string_length is None or (
                        decoded.text and len(decoded.text) < minimum_string_length
                    ):
                        decoded.text = None
            indicators = unique_indicators(indicators)
            # Imported names already appear in the import table; only extra API-name
            # strings are separate indicators of possible dynamic resolution.
            indicators = filter_imported_api_indicators(indicators, import_names)
            notify(
                f"Inspected resources and decoded content: {len(resources)} resources"
            )
            signature = extract_signature_info(pe, file_data)
            notify("Checked certificate table structure")
            overlay = extract_overlay_info(pe, file_data, signature)
            notify("Inspected file overlay")
            extended = collect_extended(
                path,
                pe,
                file_data,
                resources,
                overlay,
                inspector,
                decode_budget,
                options,
                high_entropy_threshold,
                notes,
                notify,
            )
            if extended.metadata["managed"]:
                metadata.language_guess = ".NET (CLR)"
            signature_records = extended.stages["authenticode"].details.get(
                "signatures", []
            )
            if signature_records:
                signature.verification_status = (
                    "integrity_verified_trust_separate"
                    if all(
                        item["file_digest"] == "valid"
                        and item["cryptographic_signature"] == "valid"
                        for item in signature_records
                    )
                    else "integrity_failed_or_unsupported"
                )
            indicators.extend(inspector.indicators)
            indicators.extend(enrichment_strings(extended, strings))
            indicators = unique_indicators(indicators)
            import_names.update(managed_imports(extended))
            indicators = filter_imported_api_indicators(indicators, import_names)
            notes.extend(f"PE parser: {warning}" for warning in pe.get_warnings()[:64])
            callbacks = extract_tls_callbacks(pe)
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_section = pe.get_section_by_rva(entry_rva)
            notify("Inspected TLS callbacks and entry point")
            findings = behavior_findings(import_names)
            findings.extend(capability_findings(import_names))
            findings.extend(anti_debug_code_findings(pe, notes))
            notify("Checked imported behavior capabilities")
            structural, packer = structural_findings(
                pe,
                len(file_data),
                sections,
                entry_section,
                callbacks,
                resources,
                overlay,
                signature,
                total_imports,
            )
            findings.extend(structural)
            findings.extend(extended_findings(extended))
            correlations = correlated_findings(import_names, indicators)
            findings.extend(
                indicator_findings(
                    indicators, strong_correlation_evidence(correlations)
                )
            )
            findings.extend(correlations)
            additional_imports = uncovered_api_finding(flagged_apis, findings)
            if additional_imports is not None:
                findings.append(additional_imports)
            api_hash_matches, hash_matches_truncated = hash_scan_future.result()
            if hash_matches_truncated:
                notes.append(
                    "API hash match reporting reached its limit; the whole file was scanned"
                )
            notify(
                f"Completed whole-file API hash scan: {len(api_hash_matches)} matches retained"
            )
            hashed_functions = api_hash_evidence(api_hash_matches, strings)
            if hashed_functions:
                count = len(hashed_functions)
                findings.append(
                    finding(
                        "api_hash_matches",
                        "Possible hashed API functions",
                        "API Hashing",
                        "medium" if count >= 3 else "low",
                        min(30, 10 + 2 * (count - 1)),
                        0.72 if count >= 3 else 0.55,
                        list(hashed_functions.values())[:MAX_EVIDENCE_ITEMS],
                        "File bytes or strings match hashes of flagged API names. "
                        "Matches can be coincidental and do not prove API use; "
                        "repeated matches of one API contribute only once.",
                    )
                )
            notify("Correlated structural findings, packing signals, and indicators")
            yara_scan = yara_future.result() if yara_future is not None else None
            if yara_scan is not None:
                notify(f"Completed YARA scan: {len(yara_scan.matched_rules)} matches")
            if yara_scan is not None and yara_scan.matched_rules:
                findings.append(
                    finding(
                        "yara_rule_matches",
                        "User-supplied YARA rules matched",
                        "YARA",
                        "informational",
                        0,
                        1.0,
                        yara_scan.matched_rules[:MAX_EVIDENCE_ITEMS],
                        "The supplied rules matched the original file bytes. "
                        "A match is not automatically a malicious verdict or a risk score.",
                    )
                )
            findings = consolidate_findings(findings)
            metadata.is_packed = any(
                item.rule_id in PACKING_RULES
                for item in findings
            )
            exports = extract_exports(pe)
            security_features = extract_security_features(pe)
            debug_paths = extract_debug_paths(pe)
            notify("Extracted exports, security mitigations, and debug paths")
            result = BinaryAnalysisResult(
                file_metadata=metadata,
                sections=sections,
                total_dlls=len(imports),
                total_imports=total_imports,
                all_imports=imports,
                flagged_apis=flagged_apis,
                findings=findings,
                string_indicators=indicators,
                exports=exports,
                resources=resources,
                overlay=overlay,
                signature=signature,
                entry_point_rva=hex(entry_rva),
                entry_point_section=section_name(entry_section)
                if entry_section
                else None,
                tls_callbacks=callbacks,
                packer_indicators=packer,
                security_features=security_features,
                debug_paths=debug_paths,
                strings=strings,
                minimum_string_length=minimum_string_length,
                analysis_notes=list(dict.fromkeys(notes)),
                yara_scan=yara_scan,
                api_hash_matches=api_hash_matches,
                extended=extended,
            )
            notify(f"Analysis complete: {len(findings)} findings")
            return result
    finally:
        pe.close()
