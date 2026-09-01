from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class Target:
    url: str
    flag_format: str

@dataclass
class Artifact:
    key: str
    value: Any
    source: str

@dataclass
class ExploitResult:
    module: str
    status: str
    message: str
    artifacts: list[Artifact] = field(default_factory=list)
    evidence: str = ""
    flags: list[str] = field(default_factory=list)

@dataclass
class SessionSnapshot:
    cookies: list[dict[str, Any]] = field(default_factory=list)
    local_storage: dict[str, dict[str, str]] = field(default_factory=dict)
    current_url: str = ""
    page_html: str = ""
    page_title: str = ""
    navigation_history: list[str] = field(default_factory=list)
    network_requests: list[dict[str, Any]] = field(default_factory=list)
    network_responses: list[dict[str, Any]] = field(default_factory=list)
    def cookie_header(self) -> str:
        return "; ".join(f"{c['name']}={c['value']}" for c in self.cookies)
