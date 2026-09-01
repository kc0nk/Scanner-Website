from __future__ import annotations

import re


def normalize_flag_format(fmt: str) -> str:
    """Normalize a human flag template such as picoCTF{...}."""
    fmt = fmt.strip()
    if not fmt:
        raise ValueError("Flag format cannot be empty.")
    if "..." not in fmt:
        raise ValueError("Flag format must contain ... as the placeholder, e.g. picoCTF{...}")
    return fmt


def flag_to_regex(fmt: str) -> re.Pattern[str]:
    fmt = normalize_flag_format(fmt)
    escaped = re.escape(fmt)
    # Prefer the shortest single-line match so one flag does not consume
    # unrelated content in a page. Works with picoCTF{...}, flag{...},
    # CTF2026[...], MYFLAG-..., etc.
    escaped = escaped.replace(r"\.\.\.", r"[^\r\n]*?")
    return re.compile(escaped, re.IGNORECASE)


def extract_flags(text: str, pattern: re.Pattern[str]) -> list[str]:
    if not text:
        return []
    matches = pattern.findall(text)
    if not matches:
        return []
    return list(dict.fromkeys(matches))
