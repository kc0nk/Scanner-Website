from __future__ import annotations

from urllib.parse import urlparse


def validate_target(url: str, mode: str | None = None) -> tuple[bool, str]:
    """Validate a target URL without requiring a target-mode selection.

    Any syntactically valid HTTP(S) URL is accepted. The optional ``mode``
    argument is retained for backwards compatibility with existing callers.
    Authorization/scope decisions remain the responsibility of the operator
    and the challenge environment.
    """
    raw = url.strip()
    try:
        p = urlparse(raw)
    except ValueError as exc:
        return False, f"Invalid URL: {exc}"

    if p.scheme not in {"http", "https"} or not p.hostname:
        return False, "URL must use http:// or https:// and include a hostname."

    return True, "Valid HTTP(S) target"
