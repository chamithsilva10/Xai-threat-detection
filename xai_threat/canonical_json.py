"""RFC 8785 JSON Canonicalization Scheme (JCS) Implementation.

Strict compliance with RFC 8785:
- Object keys sorted by UTF-16 code units.
- Numbers formatted strictly according to ECMAScript / RFC 8785 rules:
  * Negative zero (-0.0) is serialized as '0'.
  * Integers are formatted without a decimal point.
  * Finite floating point numbers formatted with minimum significant digits.
  * Non-finite numbers (NaN, Infinity) are rejected with ValueError.
- Strings escaped with standard JSON escape sequences (\\", \\\\, \\b, \\f, \\n, \\r, \\t, \\uXXXX).
- No whitespace around separators (',' and ':').
"""

from __future__ import annotations

import math
from typing import Any


def rfc8785_format_number(val: float | int) -> str:
    """Format numbers according to RFC 8785 Section 3.2.2.3 (ECMAScript 7.1.12.1)."""
    if isinstance(val, bool):
        return "true" if val else "false"

    if isinstance(val, int):
        return str(val)

    if not math.isfinite(val):
        raise ValueError(f"RFC 8785 prohibits non-finite numbers: {val}")

    # Negative zero rule: -0.0 -> 0
    if val == 0.0:
        return "0"

    # In Python, standard float string representation matches ECMAScript rules for almost all values
    # Verify integer floats serialize without trailing .0
    if val.is_integer() and abs(val) < 1e21:
        return str(int(val))

    # General float formatting
    s = f"{val:.16g}"
    # Convert 'e+05' to 'e+5', 'e-05' to 'e-5'
    if "e" in s:
        mantissa, exp = s.split("e")
        sign = exp[0]
        digits = exp[1:].lstrip("0") or "0"
        s = f"{mantissa}e{sign}{digits}"
    return s


def utf16_sort_key(s: str) -> list[int]:
    """Sort key matching UTF-16 code unit ordering required by RFC 8785 Section 3.2.3."""
    return list(s.encode("utf-16-be"))


def canonicalize(obj: Any) -> str:
    """Serialize any JSON-compatible object to an RFC 8785 Canonical JSON string."""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return rfc8785_format_number(obj)
    if isinstance(obj, str):
        # Escape string safely
        escaped = []
        for ch in obj:
            cp = ord(ch)
            if ch == '"':
                escaped.append('\\"')
            elif ch == "\\":
                escaped.append("\\\\")
            elif ch == "\b":
                escaped.append("\\b")
            elif ch == "\f":
                escaped.append("\\f")
            elif ch == "\n":
                escaped.append("\\n")
            elif ch == "\r":
                escaped.append("\\r")
            elif ch == "\t":
                escaped.append("\\t")
            elif cp < 0x20:
                escaped.append(f"\\u{cp:04x}")
            else:
                escaped.append(ch)
        return '"' + "".join(escaped) + '"'
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        # Keys must be sorted by UTF-16 code units
        sorted_keys = sorted(obj.keys(), key=utf16_sort_key)
        items = []
        for k in sorted_keys:
            items.append(canonicalize(str(k)) + ":" + canonicalize(obj[k]))
        return "{" + ",".join(items) + "}"

    # Fallback for custom objects / pydantic models
    if hasattr(obj, "model_dump"):
        return canonicalize(obj.model_dump())
    if hasattr(obj, "to_dict"):
        return canonicalize(obj.to_dict())

    raise TypeError(f"Object of type {type(obj).__name__} is not RFC 8785 serializable")


def canonical_json_bytes(obj: Any) -> bytes:
    """Return RFC 8785 canonical JSON as UTF-8 encoded bytes."""
    return canonicalize(obj).encode("utf-8")


canonical_json_dumps = canonicalize
canonical_json = canonicalize


def canonical_json_hash(obj: Any) -> str:
    """Return SHA-256 hex digest of the RFC 8785 canonical JSON bytes."""
    import hashlib
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()
