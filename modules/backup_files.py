from __future__ import annotations

from urllib.parse import urljoin

from core.module import ExploitModule
from core.models import ExploitResult
from core.payloads import get_payloads


class BackupSensitiveFilesModule(ExploitModule):
    name = "Backup / Sensitive Files"
    category = "discovery"

    async def run(self, ctx):
        evidence = []
        hit = False
        base = ctx.target.url.rsplit("/", 1)[0] + "/"
        for payload in get_payloads(self.name):
            url = urljoin(base, payload.lstrip("/"))
            try:
                r = await ctx.http.request("GET", url, follow_redirects=False)
                evidence.append(f"{url} -> {r.status_code}, {len(r.text)} bytes")
                low = r.text.lower()
                markers = ("[core", "db_password", "begin rsa private key", "<?php", "documentroot", "app_key=")
                if r.status_code == 200 and any(m in low for m in markers):
                    ctx.add_finding(url, payload, self.name, f"HTTP 200; sensitive-file marker observed", confidence="high")
                    hit = True
                    evidence.append(f"[finding] {url} -> sensitive-file marker observed")
            except Exception as exc:
                evidence.append(str(exc))
        return ExploitResult(self.name, "signal" if hit else "no-signal", "Backup/sensitive-file probes completed", evidence="\n".join(evidence[:20]))
