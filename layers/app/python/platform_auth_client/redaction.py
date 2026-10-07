from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_SENSITIVE_FRAGMENTS = {
    "authorization",
    "token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "target_url",
    "url",
    "raw_content",
    "captured_content",
}


def redact_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    def clean(value: Any, *, key: str = "", depth: int = 0) -> Any:
        if depth > 5:
            return "[TRUNCATED]"
        normalized = key.lower().replace("-", "_")
        if any(fragment in normalized for fragment in _SENSITIVE_FRAGMENTS):
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {
                str(child_key): clean(child, key=str(child_key), depth=depth + 1)
                for child_key, child in list(value.items())[:100]
            }
        if isinstance(value, list):
            return [clean(child, depth=depth + 1) for child in value[:50]]
        if isinstance(value, str | int | float | bool) or value is None:
            if isinstance(value, str):
                lowered = value.strip().lower()
                looks_like_jwt = value.count(".") == 2 and value.startswith("eyJ")
                if (
                    lowered.startswith(("bearer ", "basic ", "http://", "https://"))
                    or looks_like_jwt
                ):
                    return "[REDACTED]"
                return value[:1000]
            return value
        return str(value)[:1000]

    source = dict(metadata) if isinstance(metadata, Mapping) else {}
    return clean(source)
