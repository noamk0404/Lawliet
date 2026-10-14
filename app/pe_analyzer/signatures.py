"""Inspect Authenticode table structure, cryptography, and local trust policy."""

import ctypes
import os
import struct
import uuid
from ctypes import wintypes
from importlib.metadata import version

import pefile

from .analysis_models import SignatureInfo, StageResult


def extract_signature_info(pe: pefile.PE, data: bytes) -> SignatureInfo:
    """Validate certificate-table file framing without claiming signature trust."""
    try:
        item = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if not item.VirtualAddress and not item.Size:
            return SignatureInfo()

        offset = item.VirtualAddress
        size = item.Size
        end = offset + size
        details = {
            "present": True,
            "file_offset": hex(offset),
            "end_offset": hex(end),
            "size": size,
        }
        if not offset or not size or offset >= len(data) or end > len(data):
            return SignatureInfo(
                **details,
                verification_status="malformed_outside_file",
                table_valid=False,
            )

        overlay_start = pe.get_overlay_data_start_offset()
        if offset % 8 or (overlay_start is not None and offset < overlay_start):
            return SignatureInfo(
                **details,
                verification_status="malformed_certificate_table",
                table_valid=False,
            )

        cursor = offset
        certificate_count = 0
        while cursor < end:
            if end - cursor < 8:
                break
            length, _revision, _certificate_type = struct.unpack_from(
                "<IHH", data, cursor
            )
            if length < 8 or cursor + length > end:
                break
            certificate_count += 1
            cursor += (length + 7) & ~7

        if not certificate_count or cursor != end:
            return SignatureInfo(
                **details,
                certificate_count=certificate_count,
                verification_status="malformed_certificate_table",
                table_valid=False,
            )
        return SignatureInfo(
            **details,
            certificate_count=certificate_count,
            table_valid=True,
            verification_status="present_not_verified",
        )
    except (AttributeError, IndexError, KeyError):
        pass
    return SignatureInfo()


def inspect_authenticode(path: str) -> StageResult:
    """Check embedded signature integrity and report local trust separately."""
    import lief

    binary = lief.PE.parse(path)
    if binary is None:
        raise ValueError("LIEF could not parse the PE")
    signatures = list(binary.signatures)
    if not signatures:
        table = binary.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
        state = "unparseable" if table.size else "absent"
        return StageResult(
            "completed",
            version("lief"),
            {
                "embedded_signature": state,
                "signatures": [],
                "trust": {"status": "not_checked", "catalog_signatures": "not_checked"},
            },
        )
    records = [
        _signature_record(binary, signature, lief) for signature in signatures[:16]
    ]
    notes = ["Signature list truncated at 16 entries"] if len(signatures) > 16 else []
    return StageResult(
        "partial" if notes else "completed",
        version("lief"),
        {
            "embedded_signature": "present",
            "signatures": records,
            "trust": verify_windows_trust(path),
        },
        notes,
    )


def _signature_record(binary, signature, lief):
    computed = bytes(binary.authentihash(signature.digest_algorithm))
    expected = bytes(signature.content_info.digest)
    # A certificate's current expiry is separate from cryptographic integrity.
    checks = lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME
    status = signature.check(checks)
    certificates = list(signature.certificates)
    signers = []
    for signer in signature.signers:
        certificate = next(
            (
                item
                for item in certificates
                if item.issuer == signer.issuer
                and bytes(item.serial_number) == bytes(signer.serial_number)
            ),
            None,
        )
        signers.append(
            {
                "issuer": str(signer.issuer),
                "subject": str(certificate.subject)
                if certificate is not None
                else None,
            }
        )
    return {
        "digest_algorithm": str(signature.digest_algorithm),
        "file_digest": "valid" if computed == expected else "mismatch",
        "cryptographic_signature": "valid"
        if status == lief.PE.Signature.VERIFICATION_FLAGS.OK
        else "invalid_or_unsupported",
        "verification_flags": str(status),
        "signers": signers,
        "certificate_time": "evaluated_by_local_trust_policy_when_available",
    }


def verify_windows_trust(path: str) -> dict:
    """Ask Windows for cached local trust without network or revocation checks."""
    if os.name != "nt":
        return {"status": "not_checked", "reason": "Windows trust provider unavailable"}

    class FileInfo(ctypes.Structure):
        _fields_ = [
            ("size", wintypes.DWORD),
            ("path", wintypes.LPCWSTR),
            ("file", wintypes.HANDLE),
            ("subject", ctypes.c_void_p),
        ]

    class TrustData(ctypes.Structure):
        _fields_ = [
            ("size", wintypes.DWORD),
            ("policy", ctypes.c_void_p),
            ("sip", ctypes.c_void_p),
            ("ui", wintypes.DWORD),
            ("revocation", wintypes.DWORD),
            ("choice", wintypes.DWORD),
            ("file", ctypes.POINTER(FileInfo)),
            ("action", wintypes.DWORD),
            ("state", wintypes.HANDLE),
            ("url", wintypes.LPCWSTR),
            ("flags", wintypes.DWORD),
            ("context", wintypes.DWORD),
            ("settings", ctypes.c_void_p),
        ]

    file_info = FileInfo(ctypes.sizeof(FileInfo), path, None, None)
    request = TrustData()
    request.size = ctypes.sizeof(request)
    request.ui, request.choice, request.action = 2, 1, 1
    request.file = ctypes.pointer(file_info)
    request.flags = 0x1000 | 0x10  # CACHE_ONLY_URL_RETRIEVAL | REVOCATION_CHECK_NONE
    action = ctypes.create_string_buffer(
        uuid.UUID("00aac56b-cd44-11d0-8cc2-00c04fc295ee").bytes_le
    )
    verify = ctypes.WinDLL("wintrust").WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.POINTER(TrustData)]
    verify.restype = wintypes.LONG
    try:
        code = verify(None, action, ctypes.byref(request)) & 0xFFFFFFFF
    finally:
        request.action = (
            2  # Release provider state, including after verification failure.
        )
        verify(None, action, ctypes.byref(request))
    return {
        "status": "trusted_under_local_policy"
        if code == 0
        else "not_trusted_or_unavailable",
        "result_code": f"0x{code:08x}",
        "network": "disabled",
        "revocation": "not_checked",
        "catalog_signatures": "not_checked",
    }
