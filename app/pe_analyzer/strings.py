"""Extract strings, decode their content, and collect indicators."""

import base64
import binascii
import ipaddress
import re
from collections.abc import Iterable

from .analysis_constants import (
    IGNORED_URL_PREFIXES,
    IOC_PATTERNS,
    MAX_EXTRACTED_STRINGS,
    MAX_INDICATOR_LENGTH,
    MAX_STRING_DECODE_ATTEMPTS,
    MAX_STRING_INDICATORS,
    MAX_STRING_LENGTH,
    MAX_STRING_SCAN_BYTES,
    MINIMUM_STRING_LENGTH,
)
from .content_decoding import decode_content
from .entropy import calculate_entropy
from .api_functions import iter_api_name_matches
from .analysis_models import DecodedContent, ExtractedString, StringIndicator
from .hashes import suspect_hashes


def extract_raw_strings(
    data: bytes, minimum: int = MINIMUM_STRING_LENGTH
) -> list[tuple[str, int, str]]:
    found = []
    if minimum > len(data):
        return found
    for match in re.compile(rb"[\x20-\x7e]{%d,}" % minimum).finditer(data):
        found.append((match.group().decode("ascii", "ignore"), match.start(), "ascii"))
        if len(found) >= MAX_EXTRACTED_STRINGS:
            return found
    for match in re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum).finditer(data):
        found.append(
            (match.group().decode("utf-16le", "ignore"), match.start(), "utf-16le")
        )
        if len(found) >= MAX_EXTRACTED_STRINGS:
            return found
    return found


def extract_string_indicators(
    strings: Iterable[tuple[str, int | None, str]],
) -> list[StringIndicator]:
    results, seen = [], set()
    for text, base_offset, encoding in strings:
        for api_name, character_position in iter_api_name_matches(text):
            if api_name is None or ("flagged_api_name", api_name.lower()) in seen:
                continue
            seen.add(("flagged_api_name", api_name.lower()))
            offset = (
                None
                if base_offset is None
                else hex(
                    base_offset
                    + character_position * (2 if encoding == "utf-16le" else 1)
                )
            )
            results.append(
                StringIndicator(
                    value=api_name,
                    category="flagged_api_name",
                    offset=offset,
                    encoding=encoding,
                )
            )
            if len(results) >= MAX_STRING_INDICATORS:
                return results
        for category, pattern in IOC_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group().rstrip(".,;:)]}")
                if category == "url" and value.lower().startswith(IGNORED_URL_PREFIXES):
                    continue
                if category == "ipv4":
                    try:
                        ipaddress.IPv4Address(value)
                    except ipaddress.AddressValueError:
                        continue
                if category == "base64_blob":
                    # Long runs of padding or hex digits match the alphabet too.
                    # Require varied characters and enough decoded bytes.
                    if calculate_entropy(value.encode("ascii")) < 3.8:
                        continue
                    try:
                        decoded_blob = base64.b64decode(
                            value + "=" * (-len(value) % 4), validate=True
                        )
                    except binascii.Error:
                        continue
                    if len(decoded_blob) < 24:
                        continue
                if (
                    category == "hex_blob"
                    and calculate_entropy(value.encode("ascii")) < 3.3
                ):
                    continue
                key = (category, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                offset = (
                    None
                    if base_offset is None
                    else hex(
                        base_offset
                        + match.start() * (2 if encoding == "utf-16le" else 1)
                    )
                )
                results.append(
                    StringIndicator(
                        value=value[:MAX_INDICATOR_LENGTH],
                        category=category,
                        offset=offset,
                        encoding=encoding,
                    )
                )
                if len(results) >= MAX_STRING_INDICATORS:
                    return results
    return results


def decoded_string_indicators(
    content: DecodedContent, source: str
) -> list[StringIndicator]:
    """Preserve decoded provenance without inventing a file-byte offset."""
    if not content.text:
        return []
    found = extract_string_indicators([(content.text, None, content.encoding)])
    for indicator in found:
        indicator.source = source
        indicator.decoded_offset = hex(content.text.find(indicator.value))
    return found


def analyze_strings(
    data: bytes, minimum: int, notes: list[str]
) -> tuple[list[ExtractedString], list[StringIndicator]]:
    scanned = data[:MAX_STRING_SCAN_BYTES]
    raw = extract_raw_strings(scanned, minimum)
    if len(data) > len(scanned):
        notes.append("String extraction truncated by file byte budget")
    if len(raw) >= MAX_EXTRACTED_STRINGS:
        notes.append("String extraction reached string count limit")
    results = []
    indicators = []
    seen_indicators = set()
    decode_attempts = 0
    for value, offset, encoding in raw[:MAX_EXTRACTED_STRINGS]:
        shown = value[: max(MAX_STRING_LENGTH, minimum)]
        item = ExtractedString(
            value=shown,
            offset=hex(offset) if offset is not None else None,
            encoding=encoding,
            truncated=len(value) > len(shown),
        )
        item.suspected_hashes = suspect_hashes(shown)
        if len(indicators) < MAX_STRING_INDICATORS:
            _append_unique_indicators(
                indicators,
                seen_indicators,
                extract_string_indicators([(shown, offset, encoding)]),
            )
        if decode_attempts < MAX_STRING_DECODE_ATTEMPTS:
            decode_attempts += 1
            item.decoded = decode_content(shown.encode("utf-8"))
            # Threshold applies to decoded text too. Binary payload metadata stays visible.
            item.decoded = [
                decoded
                for decoded in item.decoded
                if decoded.text is None or len(decoded.text) >= minimum
            ]
            for decoded in item.decoded:
                if decoded.text:
                    for candidate in suspect_hashes(decoded.text):
                        candidate.source = f"decoded {decoded.encoding}"
                        item.suspected_hashes.append(candidate)
                        if len(item.suspected_hashes) >= 8:
                            break
                if decoded.text and len(indicators) < MAX_STRING_INDICATORS:
                    decoded_indicators = decoded_string_indicators(
                        decoded,
                        f"decoded string at {item.offset or 'unknown offset'} ({decoded.encoding})",
                    )
                    _append_unique_indicators(
                        indicators, seen_indicators, decoded_indicators
                    )
        results.append(item)
    if any(item.truncated for item in results):
        notes.append("Long strings truncated for reporting and analysis")
    if len(results) > MAX_STRING_DECODE_ATTEMPTS:
        notes.append("String decoding stopped at attempt limit")
    if len(indicators) >= MAX_STRING_INDICATORS:
        notes.append("String indicator collection reached count limit")
    return results, indicators


def _append_unique_indicators(indicators, seen, candidates) -> None:
    for item in candidates:
        key = (item.category, item.value.lower(), item.source)
        if key not in seen:
            seen.add(key)
            indicators.append(item)
        if len(indicators) >= MAX_STRING_INDICATORS:
            break


def unique_indicators(indicators: list[StringIndicator]) -> list[StringIndicator]:
    results = []
    _append_unique_indicators(results, set(), indicators)
    return results


def filter_imported_api_indicators(
    indicators: list[StringIndicator], imported_names: Iterable[str]
) -> list[StringIndicator]:
    """Drop string indicators for API names already represented by imports."""
    imported_lower = {name.lower() for name in imported_names}
    return [
        item
        for item in indicators
        if item.category != "flagged_api_name" or item.value.lower() not in imported_lower
    ]


def enrichment_strings(extended, strings):
    """Return engine string indicators while preserving non-file provenance."""
    indicators = []
    seen = {item.value for item in strings}
    for engine, key in (("floss", "recovered_strings"), ("dotnet", "user_strings")):
        stage = extended.stages[engine]
        for record in stage.details.get(key, []):
            value = record["value"]
            source = f"{engine}: {record.get('kind', 'user string')}"
            if engine == "dotnet":
                source += f" at heap {record.get('heap_offset', 'unknown')}"
            elif record.get("function") is not None:
                source += f" in function {record['function']}"
            found = extract_string_indicators([(value, None, engine)])
            for item in found:
                item.source = source
            indicators.extend(found)
            if value not in seen:
                seen.add(value)
                strings.append(ExtractedString(value=value, offset=None, encoding=source))
    return indicators
