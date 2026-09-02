from __future__ import annotations

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class WebSocketModule(ExploitModule):
    name = "WebSocket"
    category = "api"

    async def run(self, ctx):
        payloads = get_payloads(self.name)
        rows = ctx.artifacts.get("recon.requests", []) or []
        ws_rows = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            headers = {str(k).lower(): str(v) for k, v in (r.get("headers") or {}).items()}
            if "websocket" in headers.get("upgrade", "").lower() or str(r.get("url", "")).lower().startswith(("ws://", "wss://")):
                ws_rows.append(r)
        evidence = []
        for idx, payload in enumerate(payloads, 1):
            applicable = bool(ws_rows)
            ctx.mark_payload(self.name, payload, "not-applicable" if not applicable else "tested",
                             "no WebSocket handshake captured" if not applicable else "handshake observed; manual message confirmation required")
            ctx.logger(f"[payload {idx}/{len(payloads)}] WebSocket: {payload}")
            evidence.append(f"{payload} -> {'not-applicable' if not applicable else 'captured; manual-confirmation'}")
        status = "signal" if ws_rows else "no-signal"
        return ExploitResult(self.name, status, "WebSocket surface inventory completed (message probes require manual confirmation)", evidence="\n".join(evidence))
