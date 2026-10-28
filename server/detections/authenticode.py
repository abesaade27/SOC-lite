"""Authenticode digital signature verification with in-memory caching."""

import logging
import os
import subprocess
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# In-memory cache: filepath -> {"is_valid": bool, "signer": Optional[str], "status": str}
_SIGNATURE_CACHE: Dict[str, Dict[str, Any]] = {}


def verify_authenticode(
    file_path: Optional[str], raw: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Verifies the digital signature of a binary file.
    Uses WinVerifyTrust/Get-AuthenticodeSignature on Windows,
    with fallback to event metadata in raw dictionary (for tests/replay).
    """
    raw_dict = raw or {}

    # Check for test/event metadata override
    if "SignatureStatus" in raw_dict or "Signer" in raw_dict:
        status_raw = str(raw_dict.get("SignatureStatus", "")).lower()
        signer_raw = raw_dict.get("Signer")
        is_valid = status_raw in ("valid", "true", "trusted") or bool(signer_raw)
        return {
            "is_valid": is_valid,
            "signer": signer_raw,
            "status": "Valid" if is_valid else "NotSigned",
        }

    if not file_path:
        return {"is_valid": False, "signer": None, "status": "NoPath"}

    clean_path = os.path.normpath(str(file_path).strip().strip('"'))

    if clean_path in _SIGNATURE_CACHE:
        return _SIGNATURE_CACHE[clean_path]

    # If non-Windows or file does not exist, return unverified default
    if sys.platform != "win32" or not os.path.exists(clean_path):
        res = {"is_valid": False, "signer": None, "status": "FileNotFoundOrNonWindows"}
        _SIGNATURE_CACHE[clean_path] = res
        return res

    try:
        # Use PowerShell Get-AuthenticodeSignature which handles embedded and catalog signatures
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$sig = Get-AuthenticodeSignature -LiteralPath '{clean_path}'; "
            "[string]$sig.Status + ':::' + [string]$sig.SignerCertificate.Subject",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        if ":::" in out:
            status_part, subject_part = out.split(":::", 1)
            status_str = status_part.strip()
            subject_str = subject_part.strip() if subject_part.strip() else None
            is_valid = status_str.lower() == "valid"
            res = {
                "is_valid": is_valid,
                "signer": subject_str,
                "status": status_str,
            }
        else:
            res = {"is_valid": False, "signer": None, "status": "CheckFailed"}
    except Exception as e:
        logger.debug(f"Signature check failed for {clean_path}: {e}")
        res = {"is_valid": False, "signer": None, "status": "Error"}

    _SIGNATURE_CACHE[clean_path] = res
    return res


def is_signed_by_vendor(
    file_path: Optional[str],
    trusted_vendors: tuple = ("Microsoft", "Google"),
    raw: Optional[Dict[str, Any]] = None,
) -> bool:
    """Checks whether the file is validly signed by one of the specified vendors."""
    sig = verify_authenticode(file_path, raw=raw)
    if not sig["is_valid"]:
        return False
    signer = sig["signer"] or ""
    return any(v.lower() in signer.lower() for v in trusted_vendors)
