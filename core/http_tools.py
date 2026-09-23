from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import html
import json
import re
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True)
class ScopeRule:
    pattern: str
    include: bool = True


def normalize_url(value: str, default_scheme: str = "https") -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("URL is empty")
    if not re.match(r"^https?://", value, re.I):
        value = f"{default_scheme}://{value}"
    return value.rstrip("/")


def parse_http_request(raw: str, fallback_url: str = "") -> tuple[str, str, dict[str, str], str, str]:
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    head, body = (text.split("\n\n", 1) + [""])[:2] if "\n\n" in text else (text, "")
    lines = head.splitlines()
    if not lines:
        raise ValueError("Empty request")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("Invalid request line")
    method = parts[0].upper()
    target = parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    host = next((v for k, v in headers.items() if k.lower() == "host"), "")
    if re.match(r"^https?://", target, re.I):
        url = target
    elif host:
        scheme = urllib.parse.urlsplit(fallback_url or "https://example.invalid").scheme or "https"
        url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
    elif fallback_url:
        base = normalize_url(fallback_url)
        url = urllib.parse.urljoin(base + "/", target)
    else:
        raise ValueError("No absolute URL, Host header, or fallback URL")
    return method, url, headers, body, version


def request_to_raw(method: str, url: str, headers: dict[str, str], body: str = "", version: str = "HTTP/1.1") -> str:
    sp = urllib.parse.urlsplit(url)
    target = sp.path or "/"
    if sp.query:
        target += "?" + sp.query
    request_line = f"{method.upper()} {target} {version}"
    out = [request_line]
    out.extend(f"{k}: {v}" for k, v in headers.items() if not k.startswith(":") and k.lower() != "content-length")
    if body:
        out.extend(["", body])
    return "\n".join(out)


def response_to_raw(http_version: str, status: int, reason: str, headers: dict[str, str], body: str) -> str:
    out = [f"{http_version} {status} {reason}".strip()]
    out.extend(f"{k}: {v}" for k, v in headers.items())
    if body:
        out.extend(["", body])
    return "\n".join(out)


def parse_query_pairs(url: str):
    sp = urllib.parse.urlsplit(url)
    return urllib.parse.parse_qsl(sp.query, keep_blank_values=True)


def replace_query_parameter(url: str, name: str, value: str) -> str:
    sp = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    changed = False
    out = []
    for key, old in pairs:
        if key == name and not changed:
            out.append((key, value))
            changed = True
        else:
            out.append((key, old))
    if not changed:
        out.append((name, value))
    return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path or "/", urllib.parse.urlencode(out), ""))


def is_in_scope(url: str, rules: list[ScopeRule]) -> bool:
    if not rules:
        return False
    matched = False
    decision = False
    for rule in rules:
        if fnmatch.fnmatchcase(url, rule.pattern):
            matched = True
            decision = bool(rule.include)
    return matched and decision


def b64_encode(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def b64_decode(value: str) -> str:
    return base64.b64decode((value or "") + "=" * (-len(value) % 4)).decode("utf-8", errors="replace")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value or "") + "=" * (-len(value) % 4))


def decode_jwt(token: str) -> dict:
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        raise ValueError("Not a JWT")
    return {"header": json.loads(b64url_decode(parts[0])), "payload": json.loads(b64url_decode(parts[1])), "signature": parts[2]}


def hash_text(value: str, algorithm: str) -> str:
    algorithm = algorithm.lower().replace("-", "")
    if algorithm in {"sha256", "sha1", "md5", "sha512"}:
        return hashlib.new(algorithm, value.encode()).hexdigest()
    if algorithm == "sha384":
        return hashlib.sha384(value.encode()).hexdigest()
    raise ValueError(f"Unsupported hash: {algorithm}")


def html_encode(value: str) -> str:
    return html.escape(value)
