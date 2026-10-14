"""API-name hash catalogs, byte/string hash detection, and file digests."""

import hashlib
import re
import zlib
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from .api_functions import API_NAME_CATEGORIES
# Preserve access to the shared API collections from the consolidated module.
from .api_functions import ADDITIONAL_HASHED_APIS as ADDITIONAL_HASHED_APIS
from .api_functions import SUSPICIOUS_APIS as SUSPICIOUS_APIS
from .analysis_constants import HASH_CHUNK_SIZE, MAX_BINARY_HASH_MATCHES
from .analysis_models import (
    ApiHashMatch,
    ApiHashOccurrence,
    ExtractedString,
    NameHash,
    SuspectedHash,
)


def _djb2(data: bytes) -> int:
    value = 5381
    for byte in data:
        value = ((value * 33) + byte) & 0xFFFFFFFF
    return value


def _fnv1a(data: bytes) -> int:
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def _ror13_add(data: bytes) -> int:
    value = 0
    for byte in data:
        value = (((value >> 13) | (value << 19)) + byte) & 0xFFFFFFFF
    return value


def _hash_bytes(data: bytes) -> list[tuple[str, str]]:
    return [
        ("CRC32", f"{zlib.crc32(data):08x}"),
        ("DJB2", f"{_djb2(data):08x}"),
        ("FNV-1a", f"{_fnv1a(data):08x}"),
        ("ROR13-add", f"{_ror13_add(data):08x}"),
        ("MD5", hashlib.md5(data).hexdigest()),
        ("SHA-1", hashlib.sha1(data).hexdigest()),
        ("SHA-256", hashlib.sha256(data).hexdigest()),
    ]


def name_hashes(name: str) -> list[NameHash]:
    """Hash each distinct case form as ASCII and UTF-16LE text."""
    result: list[NameHash] = []
    for spelling in dict.fromkeys((name, name.lower(), name.upper())):
        for encoding in ("ascii", "utf-16le"):
            for algorithm, value in _hash_bytes(spelling.encode(encoding)):
                result.append(
                    NameHash(
                        algorithm=algorithm,
                        value=value,
                        hashed_name=spelling,
                        encoding=encoding,
                    )
                )
    return result


# Function name -> list of hashes with the algorithm, spelling, and encoding.
API_NAME_HASHES: dict[str, list[NameHash]] = {
    name: name_hashes(name) for name in sorted(API_NAME_CATEGORIES)
}


def _digests(name: str) -> dict[str, str]:
    """Compatibility helper for callers needing algorithm-to-digest values."""
    return {
        item.algorithm: item.value
        for item in name_hashes(name)
        if item.hashed_name == name and item.encoding == "ascii"
    }


def _build_catalog() -> dict[str, tuple[ApiHashMatch, ...]]:
    catalog: dict[str, list[ApiHashMatch]] = {}
    for name, hashes in API_NAME_HASHES.items():
        category = API_NAME_CATEGORIES[name]
        for item in hashes:
            catalog.setdefault(item.value, []).append(
                ApiHashMatch(
                    api_name=name,
                    category=category,
                    algorithm=item.algorithm,
                    hashed_name=item.hashed_name,
                    encoding=item.encoding,
                )
            )
    return {digest: tuple(matches) for digest, matches in catalog.items()}


# The catalog covers the same complete API set used by import flagging.
API_HASH_CATALOG = _build_catalog()


def match_api_hash(value: str) -> tuple[ApiHashMatch, ...]:
    """Look up an exact hexadecimal digest; return every collision candidate."""
    normalized = value.lower().removeprefix("0x")
    return API_HASH_CATALOG.get(normalized, ())


def _binary_lookup() -> dict[bytes, list[tuple[str, ApiHashMatch]]]:
    lookup: dict[bytes, list[tuple[str, ApiHashMatch]]] = {}
    # Preserve the original little-endian-first ordering for ambiguous tokens.
    for byte_order in ("little-endian", "big-endian"):
        for digest, candidates in API_HASH_CATALOG.items():
            if len(digest) != 8:
                continue
            raw = bytes.fromhex(digest)
            token = raw[::-1] if byte_order == "little-endian" else raw
            entries = lookup.setdefault(token, [])
            seen = {(order, item.api_name, item.algorithm) for order, item in entries}
            for candidate in candidates:
                key = (byte_order, candidate.api_name, candidate.algorithm)
                if key not in seen:
                    seen.add(key)
                    entries.append((byte_order, candidate))
    return lookup


_BINARY_HASHES = _binary_lookup()


def _scan_stream(
    stream: BinaryIO, chunk_size: int
) -> tuple[list[ApiHashOccurrence], bool]:
    matches: list[ApiHashOccurrence] = []
    truncated = False
    tail = b""
    bytes_read = 0
    while chunk := stream.read(chunk_size):
        data = tail + chunk
        base_offset = bytes_read - len(tail)
        # The three carried bytes cannot contain a complete four-byte token.
        # Every start position is therefore examined exactly once, even when
        # chunks are smaller than four bytes or the final read is short.
        for offset in range(len(data) - 3):
            token = data[offset : offset + 4]
            candidates = _BINARY_HASHES.get(token)
            if not candidates:
                continue
            for byte_order, candidate in candidates:
                if len(matches) >= MAX_BINARY_HASH_MATCHES:
                    truncated = True
                    break
                digest = token[::-1].hex() if byte_order == "little-endian" else token.hex()
                matches.append(
                    ApiHashOccurrence(
                        offset=hex(base_offset + offset),
                        value=digest,
                        byte_order=byte_order,
                        api_name=candidate.api_name,
                        category=candidate.category,
                        algorithm=candidate.algorithm,
                        hashed_name=candidate.hashed_name,
                        encoding=candidate.encoding,
                    )
                )
        bytes_read += len(chunk)
        tail = data[-3:]
    return matches, truncated


def scan_binary_api_hashes(
    data: bytes | str | Path, *, chunk_size: int = HASH_CHUNK_SIZE
) -> tuple[list[ApiHashOccurrence], bool]:
    """Scan a path through EOF; bytes remain supported for in-memory callers.

    The boolean reports omitted matches, not incomplete file coverage. Retain
    at most MAX_BINARY_HASH_MATCHES occurrences, but always scan the whole file.
    """
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
        raise ValueError("chunk_size must be a positive integer")
    stream = BytesIO(data) if isinstance(data, bytes) else Path(data).open("rb")
    with stream:
        return _scan_stream(stream, chunk_size)


_HEX_TOKEN = re.compile(r"(?<![A-Za-z0-9])(?:0[xX])?[0-9a-fA-F]{8,64}(?![A-Za-z0-9])")
_ALGORITHMS = {
    8: ["CRC32", "DJB2", "FNV-1a", "ROR13-add"],
    32: ["MD5"],
    40: ["SHA-1"],
    64: ["SHA-256"],
}
MAX_HASH_CANDIDATES_PER_STRING = 8


def api_hash_evidence(
    binary_matches: list[ApiHashOccurrence], strings: list[ExtractedString]
) -> dict[str, str]:
    """Keep one piece of evidence per possible API, including string hashes."""
    found: dict[str, str] = {}
    for match in binary_matches:
        found.setdefault(
            match.api_name,
            f"{match.api_name} at {match.offset} ({match.algorithm}, {match.byte_order})",
        )
    for item in strings:
        for candidate in item.suspected_hashes:
            for match in candidate.api_matches:
                source = f" at {item.offset}" if item.offset else ""
                found.setdefault(
                    match.api_name,
                    f"{match.api_name}{source} ({match.algorithm}, string hash)",
                )
    return found


def _looks_like_digest(value: str) -> bool:
    lowered = value.lower()
    return len(set(lowered)) >= 5 and max(lowered.count(char) for char in set(lowered)) <= len(lowered) // 2


def suspect_hashes(text: str) -> list[SuspectedHash]:
    """Identify bounded hash-shaped tokens, then compare with the API catalog."""
    found: list[SuspectedHash] = []
    for match in _HEX_TOKEN.finditer(text):
        token = match.group()
        digest = token[2:] if token.lower().startswith("0x") else token
        algorithms = _ALGORITHMS.get(len(digest))
        if algorithms is None:
            continue
        matches = match_api_hash(digest)
        # Eight hex digits also commonly represent addresses and constants.
        if len(digest) == 8 and not matches:
            continue
        if not matches and not _looks_like_digest(digest):
            continue
        found.append(
            SuspectedHash(
                value=token,
                possible_algorithms=list(algorithms),
                api_matches=list(matches),
            )
        )
        if len(found) >= MAX_HASH_CANDIDATES_PER_STRING:
            break
    return found


def calculate_file_hashes(path: Path) -> tuple[str, str, str]:
    """Stream one file pass to compute MD5, SHA-1, and SHA-256 together."""
    hashes = (hashlib.md5(), hashlib.sha1(), hashlib.sha256())
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(HASH_CHUNK_SIZE), b""):
            for digest in hashes:
                digest.update(chunk)
    md5, sha1, sha256 = hashes
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
