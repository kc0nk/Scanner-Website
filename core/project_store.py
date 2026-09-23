from __future__ import annotations

import json
from pathlib import Path

SCHEMA_VERSION = 1


def export_project(path: str | Path, *, scopes: list[str], saved_requests: list[dict], events: list[str], records: list[dict]) -> None:
    payload = {
        "schema": SCHEMA_VERSION,
        "scopes": scopes,
        "saved_requests": saved_requests,
        "events": events[-1000:],
        "records": records[-500:],
    }
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def import_project(path: str | Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema") != SCHEMA_VERSION:
        raise ValueError("Unsupported project schema")
    return payload
