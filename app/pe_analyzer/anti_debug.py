"""Bounded executable-byte heuristics for possible PEB debugger checks."""

import pefile

from .analysis_constants import (
    IMAGE_SCN_MEM_EXECUTE,
    MAX_EVIDENCE_ITEMS,
    MAX_EXECUTABLE_CODE_SCAN_BYTES,
    PEB_DEBUG_FLAG_PATTERNS,
    PEB_DEBUG_READ_PATTERNS,
)
from .analysis_models import StaticFinding
from .findings import finding
from .pe_structure import section_name


def peb_debug_check_offsets(code: bytes, machine: int) -> list[int]:
    """Locate narrow PEB BeingDebugged instruction pairs within one code span."""
    read = PEB_DEBUG_READ_PATTERNS.get(machine)
    if read is None:
        return []
    offsets = []
    start = 0
    while (position := code.find(read, start)) >= 0:
        following = code[position + len(read) : position + len(read) + 24]
        if any(pattern in following for pattern in PEB_DEBUG_FLAG_PATTERNS):
            offsets.append(position)
            if len(offsets) >= MAX_EVIDENCE_ITEMS:
                break
        start = position + len(read)
    return offsets


def anti_debug_code_findings(pe: pefile.PE, notes: list[str]) -> list[StaticFinding]:
    """Inspect bounded executable bytes; never treat a raw byte pair as proof."""
    if pe.FILE_HEADER.Machine not in PEB_DEBUG_READ_PATTERNS:
        return []
    remaining = MAX_EXECUTABLE_CODE_SCAN_BYTES
    evidence = []
    for section in pe.sections:
        if not section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            continue
        if remaining <= 0:
            notes.append("Executable-code anti-debug scan reached byte limit")
            break
        raw_size = section.SizeOfRawData
        amount = min(raw_size, remaining)
        code = section.get_data(length=amount)
        remaining -= len(code)
        evidence.extend(
            f"{section_name(section)} RVA {hex(section.VirtualAddress + offset)}"
            for offset in peb_debug_check_offsets(code, pe.FILE_HEADER.Machine)
        )
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            notes.append("PEB debugger-check scan reached match limit")
            break
        if amount < raw_size:
            notes.append("Executable-code anti-debug scan reached byte limit")
            break
    if not evidence:
        return []
    return [
        finding(
            "possible_peb_debug_check",
            "Possible PEB BeingDebugged check",
            "Anti-Analysis",
            "medium",
            9,
            0.72,
            evidence[:MAX_EVIDENCE_ITEMS],
            "Nearby executable-byte patterns read the PEB and its BeingDebugged "
            "field. This heuristic does not establish execution or control flow.",
        )
    ]
