"""Inspect PE sections, imports, exports, overlays, and loader metadata."""

import struct
from collections.abc import Iterable
from typing import Any

import pefile

from .analysis_constants import (
    DLL_CHARACTERISTICS,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    MAX_TLS_CALLBACKS,
    PACKER_SECTION_NAMES,
    SUSPICIOUS_APIS,
)
from .content_decoding import file_signatures
from .entropy import calculate_entropy
from .analysis_models import FileRegion, FlaggedAPI, OverlayInfo, SectionEntropy, SignatureInfo


_FLAGGED_IMPORT_CATEGORIES = {
    name.lower(): category
    for category, names in SUSPICIOUS_APIS.items()
    for name in names
}


def section_name(section: Any) -> str:
    return section.Name.rstrip(b"\0").decode("utf-8", "replace")


def entropy_ranges(pe: pefile.PE, overlay: OverlayInfo):
    """Yield file ranges and executability for the local entropy scanner."""
    for index, section in enumerate(pe.sections):
        yield (
            f"section {index}: {section_name(section)}",
            section.PointerToRawData,
            section.SizeOfRawData,
            bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE),
        )
    for region in overlay.regions:
        yield "overlay", int(region.offset, 16), region.size, False


def extract_sections(pe: pefile.PE, threshold: float) -> list[SectionEntropy]:
    results = []
    for section in pe.sections:
        name, entropy = section_name(section), round(section.get_entropy(), 3)
        executable = bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
        writable = bool(section.Characteristics & IMAGE_SCN_MEM_WRITE)
        reasons = []
        if executable and writable:
            reasons.append("section is writable and executable")
        if entropy >= threshold:
            reasons.append(f"high entropy ({entropy})")
        if name.lower() in PACKER_SECTION_NAMES:
            reasons.append("name is associated with a packer/protector")
        if executable and section.Misc_VirtualSize and not section.SizeOfRawData:
            reasons.append("executable section has virtual data but no raw data")
        packed = (
            name.lower() in PACKER_SECTION_NAMES
            or (executable and entropy >= threshold)
            or (
                executable
                and section.Misc_VirtualSize > 0
                and section.SizeOfRawData == 0
            )
        )
        results.append(
            SectionEntropy(
                name=name,
                virtual_address=hex(section.VirtualAddress),
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=entropy,
                is_packed_suspicious=packed,
                characteristics=section.Characteristics,
                is_readable=bool(section.Characteristics & IMAGE_SCN_MEM_READ),
                is_writable=writable,
                is_executable=executable,
                suspicious_reasons=reasons,
            )
        )
    return results


def parse_import_entries(
    entries: Iterable[Any],
    api_map: dict[str, str],
    imports: dict[str, dict[str, Any]],
    flagged: list[FlaggedAPI],
    delayed: bool = False,
) -> int:
    count = 0
    for entry in entries:
        dll = entry.dll.decode("utf-8", "replace").lower()
        key = dll if dll not in imports else f"{dll} (delay)"
        functions = {}
        for symbol in entry.imports:
            name = (
                symbol.name.decode("utf-8", "replace")
                if symbol.name
                else f"Ordinal_{symbol.ordinal}"
            )
            functions[name] = hex(symbol.address)
            category = api_map.get(name.lower())
            if category:
                flagged.append(FlaggedAPI(dll, name, category))
        thunk = getattr(entry.struct, "FirstThunk", getattr(entry.struct, "pIAT", 0))
        imports[key] = {
            "dll_address": hex(thunk) if thunk else "0x0",
            "functions": functions,
            "delayed": delayed,
        }
        count += len(functions)
    return count


def extract_imports(
    pe: pefile.PE,
) -> tuple[dict[str, dict[str, Any]], list[FlaggedAPI], int]:
    imports: dict[str, dict[str, Any]] = {}
    flagged: list[FlaggedAPI] = []
    count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        count += parse_import_entries(
            pe.DIRECTORY_ENTRY_IMPORT, _FLAGGED_IMPORT_CATEGORIES, imports, flagged
        )
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        count += parse_import_entries(
            pe.DIRECTORY_ENTRY_DELAY_IMPORT, _FLAGGED_IMPORT_CATEGORIES, imports, flagged, True
        )
    return imports, flagged, count


def extract_exports(pe: pefile.PE) -> list[str]:
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not directory:
        return []
    return [
        (
            symbol.name.decode("utf-8", "replace")
            if symbol.name
            else f"Ordinal_{symbol.ordinal}"
        )
        for symbol in directory.symbols
    ]


def extract_overlay_info(
    pe: pefile.PE, data: bytes, signature: SignatureInfo
) -> OverlayInfo:
    offset = pe.get_overlay_data_start_offset()
    if offset is None or offset >= len(data):
        return OverlayInfo()

    ranges = [(offset, len(data))]
    if (
        signature.table_valid
        and signature.file_offset is not None
        and signature.end_offset is not None
    ):
        certificate_start = int(signature.file_offset, 16)
        certificate_end = int(signature.end_offset, 16)
        separated_ranges = []
        for start, end in ranges:
            if certificate_end <= start or certificate_start >= end:
                separated_ranges.append((start, end))
                continue

            if start < certificate_start:
                prefix_end = certificate_start
                prefix = data[start:prefix_end]
                if len(prefix) > 7 or any(prefix):
                    separated_ranges.append((start, prefix_end))
            if certificate_end < end:
                separated_ranges.append((certificate_end, end))
        ranges = separated_ranges

    ranges = [(start, end) for start, end in ranges if start < end]
    if not ranges:
        return OverlayInfo()

    content = b"".join(data[start:end] for start, end in ranges)
    signatures = []
    for start, end in ranges:
        for name in file_signatures(data[start:end]):
            if name not in signatures:
                signatures.append(name)
    return OverlayInfo(
        present=True,
        offset=hex(ranges[0][0]),
        size=len(content),
        entropy=calculate_entropy(content),
        file_signatures=signatures,
        regions=[
            FileRegion(offset=hex(start), size=end - start) for start, end in ranges
        ],
    )


def extract_security_features(pe: pefile.PE) -> dict[str, bool]:
    flags = pe.OPTIONAL_HEADER.DllCharacteristics
    return {
        feature: bool(flags & mask) for feature, mask in DLL_CHARACTERISTICS.items()
    }


def extract_debug_paths(pe: pefile.PE) -> list[str]:
    """Use pefile's parsed CodeView record rather than decoding its bytes again."""
    paths = []
    for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        raw_name = getattr(getattr(debug, "entry", None), "PdbFileName", None)
        if not isinstance(raw_name, bytes):
            continue
        value = raw_name.split(b"\0", 1)[0].decode("utf-8", "replace")
        if value and value not in paths:
            paths.append(value)
    return paths


def extract_tls_callbacks(pe: pefile.PE) -> list[str]:
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if not tls or not tls.struct.AddressOfCallBacks:
        return []
    results = []
    try:
        for _index, address, status in _tls_table_events(pe, pe.__data__, strict=False):
            if status is not None:
                break
            results.append(hex(address))
    except (pefile.PEFormatError, ValueError, struct.error):
        pass
    return results


def mapped_offset(pe, rva: int, size: int, file_size: int) -> int | None:
    """Map a whole RVA range to bytes backed by the file."""
    if rva < 0 or size < 0:
        return None
    if rva + size <= min(pe.OPTIONAL_HEADER.SizeOfHeaders, file_size):
        return rva
    for section in pe.sections:
        delta = rva - section.VirtualAddress
        if 0 <= delta and delta + size <= section.SizeOfRawData:
            offset = section.PointerToRawData + delta
            if offset + size <= file_size:
                return offset
    return None


def directory_issues(pe, file_size: int) -> list[dict[str, str]]:
    issues = []
    for index, entry in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        if index == 4 or not (entry.VirtualAddress or entry.Size):
            continue  # Security directory uses file offsets, checked separately.
        if (
            not entry.VirtualAddress
            or not entry.Size
            or mapped_offset(pe, entry.VirtualAddress, entry.Size, file_size) is None
        ):
            issues.append(
                {
                    "kind": "directory_range",
                    "source": entry.name,
                    "detail": f"RVA {hex(entry.VirtualAddress)}, size {entry.Size} is not fully file-backed",
                }
            )
    return issues


def _tls_table_events(pe, data: bytes, *, strict: bool):
    """Yield TLS table addresses plus termination or mapping status.

    Strict mode maps each pointer entry through raw file-backed ranges. Display
    mode maps the table start once and tolerates a short contiguous read.
    """
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is None or not tls.struct.AddressOfCallBacks:
        return
    width = 8 if pe.PE_TYPE == (0x20B if strict else pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS) else 4
    base = pe.OPTIONAL_HEADER.ImageBase
    table_rva = tls.struct.AddressOfCallBacks - base
    contiguous_offset = None
    if not strict:
        contiguous_offset = pe.get_offset_from_rva(table_rva)
    fmt = "<Q" if width == 8 else "<I"
    for index in range(MAX_TLS_CALLBACKS):
        if strict:
            offset = mapped_offset(pe, table_rva + index * width, width, len(data))
            if offset is None:
                yield index, None, "unmapped"
                return
        else:
            offset = contiguous_offset + index * width
        raw = data[offset : offset + width]
        if len(raw) != width:
            yield index, None, "truncated"
            return
        address = struct.unpack(fmt, raw)[0]
        if not address:
            yield index, None, "terminated"
            return
        yield index, address, None
    yield MAX_TLS_CALLBACKS, None, "limit"


def tls_issues(pe, data: bytes, notes: list[str]) -> list[dict[str, str]]:
    issues = []
    for _index, address, status in _tls_table_events(pe, data, strict=True):
        if status == "unmapped" or status == "truncated":
            issues.append(
                {
                    "kind": "tls_table",
                    "source": "TLS",
                    "detail": "Callback table is truncated or unmapped",
                }
            )
            return issues
        if status == "terminated":
            return issues
        if status == "limit":
            notes.append(
                "TLS callback validation stopped at callback limit without a terminator"
            )
            return issues
        rva = address - pe.OPTIONAL_HEADER.ImageBase
        section = pe.get_section_by_rva(rva) if rva >= 0 else None
        if section is None or mapped_offset(pe, rva, 1, len(data)) is None:
            detail = "Callback target is not file-backed"
        elif not section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            detail = "Callback target is in a non-executable section"
        else:
            continue
        issues.append({"kind": "tls_target", "source": hex(address), "detail": detail})
    return issues


def validate_loader(pe, data: bytes, notes: list[str]) -> list[dict[str, str]]:
    return directory_issues(pe, len(data)) + tls_issues(pe, data, notes)
