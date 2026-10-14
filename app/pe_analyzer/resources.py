"""Inspect PE resources, unreferenced data, and additional file regions."""

from dataclasses import asdict
from typing import Any

import pefile

from .analysis_constants import (
    HIGH_ENTROPY_RESOURCE_THRESHOLD,
    MAX_DECODE_BYTES,
    MAX_REGION_BYTES,
    MAX_REGIONS,
    MAX_RESOURCE_BYTES,
    MAX_RESOURCE_NODES,
    MAX_RESOURCE_TOTAL_BYTES,
    MAX_RESOURCES,
    REGION_SCAN_BYTES,
)
from .content_decoding import classify_content, decode_content, file_signatures
from .entropy import calculate_entropy
from .analysis_models import ResourceInfo
from .pe_structure import section_name


def resource_label(entry: Any, resource_type: bool = False) -> str:
    if entry.name is not None:
        return str(entry.name)
    return (
        pefile.RESOURCE_TYPE.get(entry.id, str(entry.id))
        if resource_type
        else str(entry.id)
    )


def inspect_resource(
    data: bytes,
    info: ResourceInfo,
    include_text: bool,
    *,
    on_content=None,
    decode_budget=None,
) -> None:
    kind, role, evidence = classify_content(data, info.resource_type)
    info.detected_type, info.suspected_role, info.evidence = kind, role, evidence
    source = f"{info.origin}: {info.resource_type}/{info.name}/{info.language}"
    if on_content is not None:
        on_content(data, source, info.file_offset)

    def decoded_content(item, content):
        if on_content is not None:
            on_content(
                content,
                f"{source} decoded {item.encoding} (parent {item.source_offset_unit} +{item.source_offset})",
                None,
            )

    if kind in {"unknown", "gzip stream", "zlib stream"}:
        info.decoded = decode_content(
            data,
            allow_xor=True,
            include_text=include_text,
            on_decoded=decoded_content,
            budget=decode_budget,
        )
        if len(data) > MAX_DECODE_BYTES:
            info.inspection_notes.append(
                "Decoding skipped: input exceeds decoding byte budget"
            )
        elif kind in {"gzip stream", "zlib stream"} and not info.decoded:
            info.inspection_notes.append(
                "Compressed stream invalid, incomplete, or exceeds decoding budget"
            )
    # Scan known content for embedded file headers but do not try to decode it.
    info.file_signatures = file_signatures(data)
    if "PE executable" in info.file_signatures:
        info.anomalies.append("embedded executable")
    if kind == "possible shellcode":
        info.anomalies.append("possible shellcode")
    for item in info.decoded:
        if item.detected_type == "PE executable":
            info.anomalies.append("encoded embedded executable")
        elif item.detected_type == "possible shellcode":
            info.anomalies.append("encoded possible shellcode")
    if info.decoded:
        payload = next(
            (
                item
                for item in reversed(info.decoded)
                if item.detected_type in {"PE executable", "possible shellcode"}
            ),
            info.decoded[-1],
        )
        info.suspected_role = payload.suspected_role
        info.evidence.append(
            f"decoded using {payload.encoding}: {payload.detected_type}"
        )
    if (
        kind == "unknown"
        and not info.decoded
        and info.entropy >= HIGH_ENTROPY_RESOURCE_THRESHOLD
    ):
        info.anomalies.append("unidentified high-entropy data")
        info.suspected_role = "possible compressed or encrypted data"
    info.anomalies = list(dict.fromkeys(info.anomalies))
    info.suspected_name = (
        f"{info.name} ({info.suspected_role}; language {info.language})"
    )


def extract_resources(
    pe: pefile.PE,
    *,
    include_text: bool = False,
    notes: list[str] | None = None,
    on_content=None,
    decode_budget=None,
) -> list[ResourceInfo]:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    notes = notes if notes is not None else []
    if not root:
        return scan_resource_gaps(
            pe,
            [],
            [],
            MAX_RESOURCE_TOTAL_BYTES,
            include_text,
            notes,
            on_content=on_content,
            decode_budget=decode_budget,
        )
    results = []
    names = []
    initial_note_count = len(notes)
    directory_offset = root.struct.get_file_offset()
    total_bytes = 0
    visited = 0
    stack = [(iter(getattr(root, "entries", [])), [])]
    while stack:
        entry = next(stack[-1][0], None)
        if entry is None:
            stack.pop()
            continue
        visited += 1
        if visited > MAX_RESOURCE_NODES or len(results) >= MAX_RESOURCES:
            notes.append("Resource traversal stopped at node/resource count limit")
            break
        labels = stack[-1][1] + [resource_label(entry, not stack[-1][1])]
        if entry.name is not None:
            start = directory_offset + (entry.struct.Name & 0x7FFFFFFF)
            if 0 <= start <= len(pe.__data__) - 2:
                end = (
                    start
                    + 2
                    + 2 * int.from_bytes(pe.__data__[start : start + 2], "little")
                )
                names.append((start, end))
        if hasattr(entry, "directory"):
            if len(labels) < 3:
                stack.append((iter(getattr(entry.directory, "entries", [])), labels))
            else:
                notes.append(
                    "Skipped resource directory deeper than type/name/language"
                )
            continue
        item = getattr(getattr(entry, "data", None), "struct", None)
        if item is None:
            notes.append("Skipped malformed resource entry without data")
            continue
        padded = (labels + ["unknown"] * 3)[:3]
        info = ResourceInfo(
            resource_type=padded[0],
            name=padded[1],
            language=padded[2],
            size=item.Size,
            entropy=0.0,
            rva=hex(item.OffsetToData),
        )
        try:
            offset = pe.get_offset_from_rva(item.OffsetToData)
            section = pe.get_section_by_rva(item.OffsetToData)
            if (
                section is None
                or offset < section.PointerToRawData
                or offset + item.Size > section.PointerToRawData + section.SizeOfRawData
                or offset + item.Size > len(pe.__data__)
            ):
                info.anomalies.append(
                    "resource range is not backed by complete section data"
                )
                data = b""
            else:
                info.file_offset = hex(offset)
                amount = min(
                    item.Size,
                    MAX_RESOURCE_BYTES,
                    MAX_RESOURCE_TOTAL_BYTES - total_bytes,
                )
                data = bytes(pe.__data__[offset : offset + amount])
                total_bytes += len(data)
                if amount < item.Size:
                    info.inspection_notes.append(
                        "Resource inspection truncated by byte budget"
                    )
            info.entropy = calculate_entropy(data)
            inspect_resource(
                data,
                info,
                include_text,
                on_content=on_content,
                decode_budget=decode_budget,
            )
        except (ValueError, pefile.PEFormatError):
            info.anomalies.append("invalid resource RVA")
            info.suspected_name = (
                f"{info.name} (unreadable resource; language {info.language})"
            )
        results.append(info)
    if len(notes) == initial_note_count:
        results.extend(
            scan_resource_gaps(
                pe,
                results,
                names,
                MAX_RESOURCE_TOTAL_BYTES - total_bytes,
                include_text,
                notes,
                on_content=on_content,
                decode_budget=decode_budget,
            )
        )
    return results


def scan_resource_gaps(
    pe: pefile.PE,
    resources: list[ResourceInfo],
    names: list[tuple[int, int]],
    budget: int,
    include_text: bool,
    notes: list[str],
    *,
    on_content=None,
    decode_budget=None,
) -> list[ResourceInfo]:
    """Inspect unreferenced section bytes, excluding parsed directory tables and names."""
    occupied = list(names)
    for item in pe.__structures__:
        if item.name.startswith("IMAGE_RESOURCE_"):
            occupied.append(
                (item.get_file_offset(), item.get_file_offset() + item.sizeof())
            )
    occupied.extend(
        (int(item.file_offset, 16), int(item.file_offset, 16) + item.size)
        for item in resources
        if item.file_offset is not None
    )
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    root_offset = root.struct.get_file_offset() if root else -1
    results = []
    for section in pe.sections:
        start = section.PointerToRawData
        end = min(start + section.SizeOfRawData, len(pe.__data__))
        if not (
            start <= root_offset < end
            or section_name(section).lower() in {".rsrc", ".resource"}
        ):
            continue
        cursor = start
        gaps = []
        for first, last in sorted(occupied):
            if last <= cursor or first >= end:
                continue
            if cursor < first:
                gaps.append((cursor, first))
            cursor = max(cursor, min(last, end))
        if cursor < end:
            gaps.append((cursor, end))
        for first, last in gaps:
            if budget <= 0 or len(resources) + len(results) >= MAX_RESOURCES:
                notes.append(
                    "Unreferenced resource-section scan stopped at byte/count limit"
                )
                return results
            amount = min(last - first, budget, MAX_RESOURCE_BYTES)
            data = bytes(pe.__data__[first : first + amount])
            budget -= amount
            if not any(data):
                if amount < last - first:
                    notes.append(
                        "Unreferenced resource-section scan truncated by byte budget"
                    )
                continue
            # Ignore alignment zeros; preserve all bytes starting at the first nonzero byte.
            leading = len(data) - len(data.lstrip(b"\0"))
            data = data[leading:]
            first += leading
            if len(data) < 16:
                continue
            info = ResourceInfo(
                resource_type="UNREFERENCED",
                name=f"{section_name(section)}+{hex(first - start)}",
                language="unknown",
                size=last - first,
                entropy=calculate_entropy(data),
                file_offset=hex(first),
                rva=hex(section.VirtualAddress + first - start),
                origin="unreferenced section data",
            )
            inspect_resource(
                data,
                info,
                include_text,
                on_content=on_content,
                decode_budget=decode_budget,
            )
            if amount < last - (first - leading):
                info.inspection_notes.append(
                    "Unreferenced region inspection truncated by byte budget"
                )
            results.append(info)
    return results


def extra_ranges(pe, overlay, file_size):
    """Yield unclaimed gaps between sections and overlay ranges."""
    cursor = min(pe.OPTIONAL_HEADER.SizeOfHeaders, file_size)
    for section in sorted(pe.sections, key=lambda item: item.PointerToRawData):
        if not section.SizeOfRawData:
            continue
        start = min(section.PointerToRawData, file_size)
        if cursor < start:
            yield "section gap", cursor, start - cursor
        cursor = max(cursor, min(start + section.SizeOfRawData, file_size))
    for region in overlay.regions:
        yield "overlay", int(region.offset, 16), region.size


def inspect_extra_regions(pe, data, overlay, inspector, budget, notes):
    """Inspect section gaps and overlay content through the resource inspector."""
    results = []
    remaining = REGION_SCAN_BYTES
    for index, (source, start, size) in enumerate(
        extra_ranges(pe, overlay, len(data))
    ):
        if index >= MAX_REGIONS or remaining <= 0:
            notes.append("Additional region inspection stopped at byte/count limit")
            break
        amount = min(size, MAX_REGION_BYTES, remaining)
        remaining -= amount
        content = data[start : start + amount]
        if amount < size:
            notes.append(f"{source} at {hex(start)} truncated at region byte budget")
        leading = len(content) - len(content.lstrip(b"\0"))
        content = content[leading:]
        if not content:
            continue
        info = ResourceInfo(
            source.upper(),
            hex(start + leading),
            "unknown",
            size - leading,
            calculate_entropy(content),
            file_offset=hex(start + leading),
            origin=source,
        )
        inspect_resource(
            content, info, False, on_content=inspector.inspect, decode_budget=budget
        )
        record = asdict(info)
        record["inspected_size"] = len(content)
        results.append(record)
    return results
