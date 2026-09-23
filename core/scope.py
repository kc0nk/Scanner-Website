from __future__ import annotations

from urllib.parse import urlsplit


def normalize_scope(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        return ""
    default = (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)
    authority = host if not port or default else f"{host}:{port}"
    return f"{parts.scheme.lower()}://{authority}"


def is_in_scope(url: str, scope: str) -> bool:
    scope = normalize_scope(scope)
    if not scope or not url:
        return False
    try:
        target = urlsplit(url)
        root = urlsplit(scope)
    except Exception:
        return False
    if target.scheme.lower() != root.scheme.lower():
        return False
    if (target.hostname or "").lower().rstrip(".") != (root.hostname or "").lower().rstrip("."):
        return False
    try:
        target_port = target.port
        root_port = root.port
    except ValueError:
        return False
    target_port = target_port or (443 if target.scheme.lower() == "https" else 80)
    root_port = root_port or (443 if root.scheme.lower() == "https" else 80)
    return target_port == root_port
