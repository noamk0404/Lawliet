"""Validate embedded PE images and retain bounded, non-executing summaries."""

import hashlib
import struct

import pefile

from .analysis_models import EmbeddedPE
from .metadata import machine_name
from .analysis_constants import (
    MAX_CHILD_CANDIDATES,
    MAX_CHILD_PES,
    MAX_STRING_INDICATORS,
    MINIMUM_STRING_LENGTH,
    REGION_SCAN_BYTES,
)
from .pe_structure import extract_imports
from .strings import extract_raw_strings, extract_string_indicators


def image_extent(data: bytes, start: int) -> int | None:
    """Require a complete PE header and all declared raw sections."""
    if start + 64 > len(data):
        return None
    header = start + struct.unpack_from("<I", data, start + 60)[0]
    if (
        header < start + 64
        or header + 24 > len(data)
        or data[header : header + 4] != b"PE\0\0"
    ):
        return None
    count = struct.unpack_from("<H", data, header + 6)[0]
    optional_size = struct.unpack_from("<H", data, header + 20)[0]
    optional = header + 24
    table = optional + optional_size
    if not 1 <= count <= 96 or optional_size < 64 or table + count * 40 > len(data):
        return None
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B) or optional_size < (96 if magic == 0x10B else 112):
        return None
    extent = struct.unpack_from("<I", data, optional + 60)[0]
    if extent < table + count * 40 - start or start + extent > len(data):
        return None
    for index in range(count):
        raw_size, raw_offset = struct.unpack_from("<II", data, table + index * 40 + 16)
        if raw_size and (
            raw_offset < extent and raw_offset < table + count * 40 - start
        ):
            return None
        if start + raw_offset + raw_size > len(data):
            return None
        extent = max(extent, raw_offset + raw_size)
    return extent


def summarize_child(content: bytes) -> EmbeddedPE:
    pe = pefile.PE(data=content, fast_load=True)
    try:
        pe.parse_data_directories(directories=[1, 13])
        imports, _, _ = extract_imports(pe)
        names = sorted({name for dll in imports.values() for name in dll["functions"]})
        anomalies = []
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        section = pe.get_section_by_rva(entry) if entry else None
        if entry and (section is None or not section.Characteristics & 0x20000000):
            anomalies.append("Child entry point is unmapped or non-executable")
        if len(names) > 128:
            anomalies.append("Child import summary truncated at 128 names")
        return EmbeddedPE(
            hashlib.sha256(content).hexdigest(),
            len(content),
            machine_name(pe.FILE_HEADER.Machine),
            len(pe.sections),
            hex(entry),
            imports=names[:128],
            anomalies=anomalies,
        )
    finally:
        pe.close()


class PayloadInspector:
    def __init__(self, notes: list[str]):
        self.notes = notes
        self.remaining = REGION_SCAN_BYTES
        self.attempts = 0
        self.payloads: dict[str, EmbeddedPE] = {}
        self.seen: dict[bytes, list[tuple[str, int]]] = {}
        self.indicators = []

    def inspect(self, data: bytes, source: str, file_offset: str | None) -> None:
        digest = hashlib.sha256(data).digest()
        if digest in self.seen:
            for key, offset in self.seen[digest]:
                self._source(self.payloads[key], source, file_offset, offset)
            return
        scanned = data[: self.remaining]
        self.remaining -= len(scanned)
        if len(scanned) < len(data):
            self.notes.append("Embedded-content scan truncated at shared byte budget")
        self.seen[digest] = []
        if file_offset is None:
            self._indicators(scanned, source)
        self._images(scanned, source, file_offset, digest)

    def _indicators(self, data: bytes, source: str) -> None:
        if len(self.indicators) >= MAX_STRING_INDICATORS:
            self.notes.append("Decoded-content indicators truncated at count limit")
            return
        strings = extract_raw_strings(data, MINIMUM_STRING_LENGTH)[:1000]
        for item in extract_string_indicators(strings):
            item.source = source
            item.decoded_offset, item.offset = item.offset, None
            self.indicators.append(item)
            if len(self.indicators) >= MAX_STRING_INDICATORS:
                break

    def _images(self, data, source, file_offset, digest):
        position = data.find(b"MZ")
        while position >= 0:
            if (
                self.attempts >= MAX_CHILD_CANDIDATES
                or len(self.payloads) >= MAX_CHILD_PES
            ):
                self.notes.append(
                    "Embedded PE inspection stopped at candidate/object limit"
                )
                return
            self.attempts += 1
            size = image_extent(data, position)
            if size is not None:
                self._retain(
                    data[position : position + size],
                    source,
                    file_offset,
                    position,
                    digest,
                )
            position = data.find(b"MZ", position + 2)

    def _retain(self, content, source, file_offset, position, digest):
        key = hashlib.sha256(content).hexdigest()
        if key not in self.payloads:
            try:
                self.payloads[key] = summarize_child(content)
            except (pefile.PEFormatError, ValueError, struct.error):
                return
        self.seen[digest].append((key, position))
        self._source(self.payloads[key], source, file_offset, position)

    @staticmethod
    def _source(payload, source, file_offset, position):
        location = (
            f"file {hex(int(file_offset, 16) + position)}"
            if file_offset is not None
            else f"decoded byte +{hex(position)}"
        )
        label = f"{source}: {location}"
        if label not in payload.sources and len(payload.sources) < 32:
            payload.sources.append(label)
