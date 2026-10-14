"""Collect file identity, native build, and manifest metadata."""

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

import pefile

from .analysis_constants import (
    LANGUAGE_HINTS,
    LANGUAGE_STRINGS,
    MACHINE_NAMES,
    MAX_METADATA_BYTES,
    MAX_METADATA_ITEMS,
    SUBSYSTEM_NAMES,
)
from .analysis_models import FileMetadata


def machine_name(value: int) -> str:
    return MACHINE_NAMES.get(value, f"unknown ({hex(value)})")


def subsystem_name(value: int) -> str:
    return SUBSYSTEM_NAMES.get(value, f"Unknown ({value})")


def guess_programming_language(
    pe: pefile.PE, dlls: list[str], strings: Iterable[str]
) -> str | None:
    scores: dict[str, int] = {}
    lowered = [value.lower() for value in strings]
    for language, hints in LANGUAGE_HINTS.items():
        scores[language] = sum(1 for dll in dlls if any(h in dll for h in hints)) * 3
    for language, hints in LANGUAGE_STRINGS.items():
        scores[language] = scores.get(language, 0) + sum(
            1 for value in lowered if any(h in value for h in hints)
        )
    if scores and max(scores.values()) > 0:
        return max(scores, key=scores.get)  # type: ignore[arg-type]
    return {2: "C/C++ (GUI)", 3: "C/C++ (Console)"}.get(pe.OPTIONAL_HEADER.Subsystem)


def has_reproducible_build(pe) -> bool:
    """Return whether the PE debug directory includes reproducible-build type 16."""
    return any(
        item.struct.Type == 16 for item in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])
    )


def extract_file_metadata(
    path: Path,
    pe: pefile.PE,
    dlls: list[str],
    strings: Iterable[str],
    *,
    file_hashes: tuple[str, str, str],
) -> FileMetadata:
    md5, sha1, sha256 = file_hashes
    try:
        compilation = (
            datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            if pe.FILE_HEADER.TimeDateStamp not in (0, 0xFFFFFFFF)
            and not has_reproducible_build(pe)
            else None
        )
    except (ValueError, OSError, OverflowError):
        compilation = None
    stat = path.stat()
    created = datetime.fromtimestamp(
        getattr(stat, "st_birthtime", stat.st_ctime), timezone.utc
    ).isoformat()
    try:
        imphash = pe.get_imphash() or None
    except Exception:
        imphash = None
    return FileMetadata(
        filename=path.name,
        file_size=stat.st_size,
        md5_hash=md5,
        sha1_hash=sha1,
        sha256_hash=sha256,
        language_guess=guess_programming_language(pe, dlls, strings),
        creation_time=created,
        compilation_time=compilation,
        architecture=machine_name(pe.FILE_HEADER.Machine),
        subsystem=subsystem_name(pe.OPTIONAL_HEADER.Subsystem),
        imphash=imphash,
    )


def text_value(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").rstrip("\0")[:1024]
    return str(value)[:1024]


def version_information(pe, notes: list[str]) -> list[dict[str, str]]:
    records = []
    remaining = MAX_METADATA_ITEMS
    for group in getattr(pe, "FileInfo", []):
        for item in group:
            for table in getattr(item, "StringTable", []):
                record = {"language": text_value(getattr(table, "LangID", "unknown"))}
                for key, value in table.entries.items():
                    if remaining <= 0:
                        notes.append("Version metadata truncated at item limit")
                        return records + [record]
                    record[text_value(key)] = text_value(value)
                    remaining -= 1
                if record not in records:
                    records.append(record)
    return records


def parse_manifest(data: bytes) -> dict[str, object]:
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError("Manifest exceeds byte budget")
    # Reject entity declarations even when XML is UTF-16 encoded.
    normalized = data.replace(b"\0", b"").upper()
    if b"<!DOCTYPE" in normalized or b"<!ENTITY" in normalized:
        raise ValueError("Manifest DTD/entity declarations are not supported")
    root = ElementTree.fromstring(data)
    result = {}
    for index, element in enumerate(root.iter()):
        if index >= MAX_METADATA_ITEMS:
            raise ValueError("Manifest exceeds element limit")
        name = element.tag.rsplit("}", 1)[-1]
        if name == "requestedExecutionLevel":
            result["requested_execution_level"] = element.get("level", "unknown")
            result["ui_access"] = element.get("uiAccess", "false")
        elif name == "assemblyIdentity" and "assembly_identity" not in result:
            result["assembly_identity"] = dict(element.attrib)
    return result


def manifest_information(data: bytes, resources, notes: list[str]) -> list[dict]:
    results = []
    budget = MAX_METADATA_BYTES
    for resource in resources:
        if resource.resource_type != "RT_MANIFEST" or resource.file_offset is None:
            continue
        if resource.size > budget:
            notes.append("Manifest inspection stopped at byte budget")
            break
        start = int(resource.file_offset, 16)
        budget -= resource.size
        try:
            record = parse_manifest(data[start : start + resource.size])
            record.update(name=resource.name, language=resource.language)
            results.append(record)
        except (ValueError, ElementTree.ParseError) as error:
            notes.append(f"Manifest {resource.name}: {error}")
    return results


def extract_build_metadata(pe, data: bytes, resources, notes: list[str]) -> dict:
    rich = getattr(pe, "RICH_HEADER", None)
    values = getattr(rich, "values", [])
    builds = [
        {"product_id": value >> 16, "build": value & 0xFFFF, "count": count}
        for value, count in zip(values[::2], values[1::2])
    ][:MAX_METADATA_ITEMS]
    if len(values) > MAX_METADATA_ITEMS * 2:
        notes.append("Rich metadata truncated at item limit")
    reproducible = has_reproducible_build(pe)
    return {
        "version_information": version_information(pe, notes),
        "manifests": manifest_information(data, resources, notes),
        "rich_builds": builds,
        "reproducible_build": reproducible,
        "managed": len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14
        and bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress),
    }
