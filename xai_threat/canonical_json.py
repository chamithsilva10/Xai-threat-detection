"""RFC 8785 JSON Canonicalization Scheme (JCS) Implementation.

Strict compliance with RFC 8785:
- Uses the official `rfc8785` reference engine.
- Negative zero (-0.0) serialized as '0'.
- Integers formatted without trailing '.0'.
- Numbers formatted strictly according to ECMAScript / RFC 8785 Section 3.2.2.3 rules.
- Object keys sorted by UTF-16 code units (RFC 8785 Section 3.2.3).
- Duplicate keys in JSON payloads are strictly rejected.
- Non-finite numbers (NaN, Infinity) are strictly rejected with ValueError.
- Explicit serialization version tag: "RFC8785-v1.0".
"""

from __future__ import annotations

import json
from typing import Any
import rfc8785

CANONICAL_SERIALIZATION_SCHEME = "RFC8785-v1.0"


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Rejects duplicate dictionary keys during JSON decoding per RFC 8785."""
    res = {}
    for k, v in pairs:
        if k in res:
            raise ValueError(f"RFC 8785 violation: duplicate key '{k}' in JSON object")
        res[k] = v
    return res


def safe_json_loads(data: str | bytes) -> Any:
    """Parse JSON while strictly rejecting duplicate object keys."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(data, object_pairs_hook=reject_duplicate_keys)


def _prepare_for_canonical(obj: Any) -> Any:
    """Convert custom objects, pydantic models, sets, or paths into native JSON-serializable types."""
    if obj is None or isinstance(obj, (bool, int, str)):
        return obj
    if isinstance(obj, float):
        if obj == 0.0:
            return 0
        return obj
    if hasattr(obj, "model_dump"):
        return _prepare_for_canonical(obj.model_dump(mode="json"))
    if hasattr(obj, "to_dict"):
        return _prepare_for_canonical(obj.to_dict())
    if isinstance(obj, dict):
        return {str(k): _prepare_for_canonical(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_prepare_for_canonical(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted([_prepare_for_canonical(v) for v in obj], key=str)
    return str(obj)


def canonicalize(obj: Any) -> str:
    """Serialize object to strictly conforming RFC 8785 Canonical JSON string."""
    prepared = _prepare_for_canonical(obj)
    try:
        canonical_bytes = rfc8785.dumps(prepared)
    except rfc8785.FloatDomainError as err:
        raise ValueError(f"RFC 8785 prohibits non-finite numbers: {err}") from err
    return canonical_bytes.decode("utf-8")


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize object to strictly conforming RFC 8785 Canonical JSON bytes."""
    prepared = _prepare_for_canonical(obj)
    try:
        return rfc8785.dumps(prepared)
    except rfc8785.FloatDomainError as err:
        raise ValueError(f"RFC 8785 prohibits non-finite numbers: {err}") from err


canonical_json_dumps = canonicalize
canonical_json = canonicalize


def canonical_json_hash(obj: Any) -> str:
    """Return SHA-256 hex digest of the RFC 8785 canonical JSON bytes."""
    import hashlib
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()
