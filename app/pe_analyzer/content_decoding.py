"""Identify embedded formats and decode bounded content without execution."""

import base64
import binascii
import codecs
import hashlib
import json
import re
import struct
import zlib
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import unquote_to_bytes

from .analysis_constants import (
    CONTENT_SIGNATURES,
    ENCODING_PATTERNS,
    FILE_SIGNATURES,
    MAX_DECODE_BYTES,
    MAX_DECODE_DEPTH,
    MAX_DECODE_RESULTS,
    MAX_ENCODING_CANDIDATES,
    MAX_STRING_LENGTH,
    MAX_XOR_BYTES,
    RESOURCE_ROLES,
    SHELLCODE_PEB_PATTERNS,
    SHELLCODE_RESOLVER_PATTERNS,
)
from .analysis_models import DecodedContent

_TEXT_DECODERS: dict[str, Callable[[str], bytes]] = {
    "hex": bytes.fromhex,
    "hex-escape": lambda value: codecs.escape_decode(value.encode("ascii"))[0],
    "unicode-escape": lambda value: codecs.decode(
        value.encode("ascii"), "unicode_escape"
    ).encode("utf-8"),
    "percent": unquote_to_bytes,
    "base32": lambda value: base64.b32decode(value + "=" * (-len(value) % 8)),
    "base64": lambda value: base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    ),
}


@dataclass
class DecodeBudget:
    remaining: int = 4 * MAX_DECODE_BYTES
    seen: set[bytes] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)


def file_signatures(data: bytes, skip_leading_pe: bool = False) -> list[str]:
    found = []
    for name, magic in FILE_SIGNATURES:
        start = 2 if skip_leading_pe and name == "PE executable" else 0
        position = data.find(magic, start)
        while position >= 0:
            if name != "PE executable":
                found.append(name)
                break
            # A bare two-byte MZ match is noisy. Confirm its e_lfanew and PE signature.
            if position + 0x40 <= len(data):
                pe_offset = struct.unpack_from("<I", data, position + 0x3C)[0]
                signature = position + pe_offset
                if (
                    signature + 4 <= len(data)
                    and data[signature : signature + 4] == b"PE\0\0"
                ):
                    found.append(name)
                    break
            position = data.find(magic, position + 2)
    return found


def readable_text(data: bytes) -> str | None:
    """Accept text only when almost all characters are printable or whitespace."""
    encodings = ["utf-8-sig"]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.insert(0, "utf-16")
    elif len(data) >= 4 and len(data) % 2 == 0:
        if data[1::2].count(0) > len(data) // 8:
            encodings.insert(0, "utf-16le")
        elif data[::2].count(0) > len(data) // 8:
            encodings.insert(0, "utf-16be")
    for encoding in encodings:
        try:
            text = data.decode(encoding).strip("\x00\ufeff")
        except UnicodeDecodeError:
            continue
        if (
            text
            and sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) >= 0.95
        ):
            return text
    return None


def classify_content(
    data: bytes, resource_type: str = ""
) -> tuple[str, str, list[str]]:
    """Identify content before attempting transformations; labels alone are not proof."""
    for name, magic, role in CONTENT_SIGNATURES:
        if data.startswith(magic):
            return name, role, []
    if data.startswith(b"RIFF") and len(data) >= 12:
        kind = data[8:12]
        if kind in (b"WEBP", b"WAVE", b"AVI "):
            return kind.decode("ascii").strip(), "media asset", []
    # RT_BITMAP/RT_ICON often contain a DIB, which has no BM file header.
    if resource_type in {"RT_BITMAP", "RT_ICON", "RT_CURSOR"}:
        dib = data[4:] if resource_type == "RT_CURSOR" else data
        if len(dib) >= 40 and int.from_bytes(dib[:4], "little") in {
            40,
            52,
            56,
            108,
            124,
        }:
            width, height, planes, bits = struct.unpack_from("<iiHH", dib, 4)
            if (
                width > 0
                and height != 0
                and planes == 1
                and bits in {1, 4, 8, 16, 24, 32}
            ):
                return "DIB image", "image asset", []
    signatures = file_signatures(data)
    if "PE executable" in signatures:
        return (
            "PE executable",
            "embedded executable payload",
            ["validated MZ and PE headers"],
        )
    if signatures and signatures[0] != "gzip stream":
        return (
            signatures[0],
            "embedded archive or document",
            ["file signature inside resource data"],
        )
    # Two independent byte-pattern families must appear close together.
    for pattern in SHELLCODE_PEB_PATTERNS:
        position = data.find(pattern)
        if position >= 0:
            window = data[max(0, position - 512) : position + 4096]
            if any(marker in window for marker in SHELLCODE_RESOLVER_PATTERNS):
                return (
                    "possible shellcode",
                    "possible in-memory code payload",
                    [
                        f"PEB-access byte signature at +{hex(position)}",
                        "nearby API-hash resolver byte signature",
                    ],
                )
    if data.startswith(b"\x1f\x8b\x08"):
        return "gzip stream", "compressed data", []
    if (
        len(data) >= 2
        and data[0] & 15 == 8
        and data[0] >> 4 <= 7
        and int.from_bytes(data[:2], "big") % 31 == 0
    ):
        return "zlib stream", "compressed data", []
    text = readable_text(data)
    if resource_type == "RT_VERSION" and len(data) >= 6:
        length = int.from_bytes(data[:2], "little")
        if 6 <= length <= len(data) and data[6:].startswith(
            "VS_VERSION_INFO\0".encode("utf-16le")
        ):
            return "Windows version info", "version metadata", []
    if text:
        stripped = text.lstrip()
        if stripped.startswith(("<?xml", "<assembly", "<assemblyIdentity")):
            return (
                "XML text",
                RESOURCE_ROLES.get(resource_type, "configuration or document"),
                [],
            )
        if stripped.startswith(("{", "[")):
            try:
                json.loads(stripped)
            except (ValueError, RecursionError):
                pass
            else:
                return "JSON text", "configuration or structured data", []
    return "unknown", RESOURCE_ROLES.get(resource_type, "unknown data"), []


def decode_candidates(data: bytes, allow_xor: bool) -> Iterable[tuple[str, bytes, int]]:
    """Decode syntax-matched candidates only. Never execute or unpack archives."""
    if len(data) > MAX_DECODE_BYTES:
        return
    kind, _, _ = classify_content(data)
    if kind in {"gzip stream", "zlib stream"}:
        try:
            decoder = zlib.decompressobj(31 if kind == "gzip stream" else 15)
            output = decoder.decompress(data, MAX_DECODE_BYTES + 1)
            if decoder.eof and len(output) <= MAX_DECODE_BYTES:
                yield kind.split()[0], output, 0
        except zlib.error:
            pass
    text = readable_text(data)
    if text:
        # Also accept line-wrapped whole Base64/Base32 blobs.
        variants = [(text, False)]
        compact = "".join(text.split())
        if compact != text and re.fullmatch(r"[A-Za-z0-9+/_=-]+", compact):
            variants.append((compact, True))
        attempts = 0
        for value, compacted in variants:
            for encoding, pattern in ENCODING_PATTERNS:
                for match in pattern.finditer(value):
                    attempts += 1
                    if attempts > MAX_ENCODING_CANDIDATES:
                        return
                    token = match.group()
                    try:
                        decoded = _TEXT_DECODERS[encoding](token)
                    except (ValueError, binascii.Error, UnicodeError):
                        continue
                    if decoded and decoded != data and len(decoded) <= MAX_DECODE_BYTES:
                        # Position is relative to the immediate decoded parent, not the file.
                        yield (
                            encoding + ("-wrapped" if compacted else ""),
                            decoded,
                            (0 if compacted else match.start()),
                        )
    if allow_xor and data and len(data) <= MAX_XOR_BYTES:
        # Recover single-byte XOR only when a known header/signature validates it.
        magics = (
            [magic for _, magic, _ in CONTENT_SIGNATURES]
            + [b"MZ", b"\x1f\x8b\x08"]
            + list(SHELLCODE_PEB_PATTERNS)
        )
        tried = set()
        for magic in magics:
            key = data[0] ^ magic[0]
            if not key or key in tried:
                continue
            if bytes(value ^ key for value in data[: len(magic)]) != magic:
                continue
            tried.add(key)
            decoded = bytes(value ^ key for value in data)
            if classify_content(decoded)[0] != "unknown":
                yield f"xor-0x{key:02x}", decoded, 0


def decode_content(
    data: bytes,
    *,
    allow_xor: bool = False,
    include_text: bool = True,
    on_decoded: Callable[[DecodedContent, bytes], None] | None = None,
    budget: DecodeBudget | None = None,
) -> list[DecodedContent]:
    results = []
    queue = deque([(data, "", 0)])
    seen = {hashlib.sha256(data).digest()}
    total_bytes = 0
    while queue and len(results) < MAX_DECODE_RESULTS:
        content, chain, depth = queue.popleft()
        if depth >= MAX_DECODE_DEPTH:
            if budget is not None:
                budget.notes.append("Resource/region decoding reached depth limit")
            continue
        for encoding, decoded, position in decode_candidates(content, allow_xor):
            digest = hashlib.sha256(decoded).digest()
            if digest in seen:
                continue
            seen.add(digest)
            total_bytes += len(decoded)
            if total_bytes > MAX_DECODE_BYTES:
                if budget is not None:
                    budget.notes.append(
                        "Resource/region decoding stopped at per-item byte budget"
                    )
                return results
            kind, role, evidence = classify_content(decoded)
            text = readable_text(decoded)
            # Alphabet matches alone frequently decode into meaningless binary.
            if kind == "unknown" and text is None and encoding not in {"gzip", "zlib"}:
                continue
            if budget is not None:
                if digest not in budget.seen:
                    if len(decoded) > budget.remaining:
                        budget.notes.append(
                            "Shared resource/region decoding byte budget exhausted"
                        )
                        return results
                    budget.remaining -= len(decoded)
                    budget.seen.add(digest)
            label = f"{chain} -> {encoding}" if chain else encoding
            results.append(
                DecodedContent(
                    encoding=label,
                    size=len(decoded),
                    sha256=digest.hex(),
                    detected_type=(
                        kind
                        if kind != "unknown"
                        else ("text" if text else "unknown binary")
                    ),
                    suspected_role=(
                        role
                        if kind != "unknown"
                        else (
                            "decoded text or configuration"
                            if text
                            else "unknown decoded binary"
                        )
                    ),
                    source_offset=hex(position),
                    source_offset_unit=(
                        "bytes"
                        if encoding in {"gzip", "zlib"} or encoding.startswith("xor-")
                        else "characters"
                    ),
                    text=text[:MAX_STRING_LENGTH] if text and include_text else None,
                    text_truncated=bool(
                        text and include_text and len(text) > MAX_STRING_LENGTH
                    ),
                    evidence=evidence,
                )
            )
            if on_decoded is not None:
                on_decoded(results[-1], decoded)
            if len(results) >= MAX_DECODE_RESULTS:
                if budget is not None:
                    budget.notes.append(
                        "Resource/region decoding reached per-item result limit"
                    )
                break
            if kind in {"unknown", "gzip stream", "zlib stream"}:
                queue.append((decoded, label, depth + 1))
    return results
