from __future__ import annotations

"""Curated payload/method knowledge base for v3.0.

The knowledge base is intentionally bundled and normalized from public CTF/write-up
references rather than scraping arbitrary repositories at runtime. Each family carries
safe-to-replay test cases plus applicability hints and source references.
"""

PAYLOAD_SOURCES = [
    {
        "name": "w181496/Web-CTF-Cheatsheet",
        "url": "https://github.com/w181496/Web-CTF-Cheatsheet",
        "topics": ["SSRF", "XSS", "web CTF"],
    },
    {
        "name": "Shiva108/CTF-notes",
        "url": "https://github.com/Shiva108/CTF-notes",
        "topics": ["LFI", "web CTF", "write-ups"],
    },
    {
        "name": "riramar/Web-Attack-Cheat-Sheet",
        "url": "https://github.com/riramar/Web-Attack-Cheat-Sheet",
        "topics": ["SSRF", "web attack techniques"],
    },
    {
        "name": "0xsyr0/Awesome-Cybersecurity-Handbooks",
        "url": "https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks",
        "topics": ["RFI", "SSRF", "web analysis"],
    },
    {
        "name": "Berkanktk/CyberSecurity",
        "url": "https://github.com/Berkanktk/CyberSecurity",
        "topics": ["SQL injection"],
    },
    {
        "name": "OWASP Cheat Sheet Series",
        "url": "https://github.com/OWASP/CheatSheetSeries",
        "topics": ["JWT", "authentication", "authorization", "business logic", "web security"],
    },
]

# Family definitions. Entries are intentionally framed as controlled probes or
# passive-analysis signatures; the analyzer must still require concrete evidence
# before a vulnerability becomes CONFIRMED. Payloads are intentionally short, controlled probes.
PAYLOAD_CATALOG = {
    "SQL Injection": {
        "payloads": ["'", '"', "' OR '1'='1", "' AND '1'='2", "1 ORDER BY 1-- -"],
        "parameter_hints": ["id", "uid", "user", "account", "sort", "order", "filter", "search", "q", "query"],
        "content_types": [],
        "source_names": ["Berkanktk/CyberSecurity", "w181496/Web-CTF-Cheatsheet"],
    },
    "XSS": {
        "payloads": ["<xss-test>", "<script>alert(1)</script>", '\"><xss-test>', "' onmouseover=alert(1) x='"],
        "parameter_hints": ["q", "query", "search", "name", "message", "comment", "title", "text", "input", "value"],
        "content_types": ["text/html", "application/xhtml+xml"],
        "source_names": ["w181496/Web-CTF-Cheatsheet"],
    },
    "SSTI": {
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
        "parameter_hints": ["template", "tpl", "name", "subject", "title", "message", "content", "render"],
        "content_types": ["text/html", "application/xhtml+xml", "text/plain"],
        "source_names": ["w181496/Web-CTF-Cheatsheet", "0xsyr0/Awesome-Cybersecurity-Handbooks"],
    },
    "LFI / Traversal": {
        "payloads": ["../", "../../etc/passwd", "..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd"],
        "parameter_hints": ["file", "path", "filename", "page", "include", "template", "resource", "document", "download"],
        "content_types": ["text/html", "text/plain", "application/json", "application/octet-stream"],
        "source_names": ["Shiva108/CTF-notes", "0xsyr0/Awesome-Cybersecurity-Handbooks"],
    },
    "SSRF": {
        "payloads": ["http://127.0.0.1/", "http://localhost/", "http://[::1]/"],
        "parameter_hints": ["url", "uri", "target", "dest", "destination", "callback", "webhook", "redirect", "next", "fetch"],
        "content_types": ["application/json", "application/x-www-form-urlencoded", "text/html", "text/plain"],
        "source_names": ["w181496/Web-CTF-Cheatsheet", "riramar/Web-Attack-Cheat-Sheet", "0xsyr0/Awesome-Cybersecurity-Handbooks"],
    },
    "NoSQL Injection": {
        "payloads": ['{"$ne":null}', '{"$gt":""}', "' || '1'=='1"],
        "parameter_hints": ["id", "user", "username", "email", "query", "filter", "search"],
        "content_types": ["application/json", "application/x-www-form-urlencoded"],
        "source_names": ["w181496/Web-CTF-Cheatsheet"],
    },
    "Open Redirect": {
        "payloads": ["https://example.com/", "//example.com/", "\\\\example.com\\"],
        "parameter_hints": ["redirect", "next", "return", "returnUrl", "url", "continue", "callback", "dest", "destination"],
        "content_types": ["application/x-www-form-urlencoded", "application/json", "text/html"],
        "source_names": ["w181496/Web-CTF-Cheatsheet"],
    },
    "Command Injection": {
        "payloads": [";id", "&&id", "|id"],
        "parameter_hints": ["cmd", "command", "exec", "execute", "ping", "host", "query", "target"],
        "content_types": ["application/x-www-form-urlencoded", "application/json", "text/plain"],
        "source_names": ["0xsyr0/Awesome-Cybersecurity-Handbooks"],
    },
    "XXE": {
        "payloads": ["<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/hostname'>]>", "<!DOCTYPE x [<!ENTITY e SYSTEM 'http://127.0.0.1/'>]>"],
        "parameter_hints": [],
        "content_types": ["application/xml", "text/xml"],
        "source_names": ["0xsyr0/Awesome-Cybersecurity-Handbooks"],
    },
    "JWT Analysis": {
        "payloads": ["JWT-DECODE-ONLY", "JWT-CLAIMS-INSPECTION"],
        "parameter_hints": ["token", "access_token", "id_token", "jwt", "authorization", "auth"],
        "content_types": ["application/json", "application/x-www-form-urlencoded", "text/plain"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "Auth & Access Control": {
        "payloads": ["AUTH-MISSING-CHECK", "SESSION-MISSING-CHECK"],
        "parameter_hints": ["role", "user_id", "uid", "account", "admin", "profile"],
        "content_types": ["application/json", "application/x-www-form-urlencoded"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "methods": ["GET", "HEAD", "OPTIONS"],
    },
    "Business Logic / Shop": {
        "payloads": ["0", "1", "999999", "test"],
        "parameter_hints": ["price", "amount", "total", "quantity", "qty", "discount", "coupon", "promo", "product_id", "item_id", "cart_id"],
        "content_types": ["application/json", "application/x-www-form-urlencoded", "text/html"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "methods": ["GET", "HEAD"],
    },
    "CORS": {
        "payloads": ["CORS-ORIGIN-CHECK"],
        "parameter_hints": [],
        "content_types": ["application/json", "text/html", "text/plain"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "Mass Assignment": {
        "payloads": ["__role_test__", "__is_admin_test__"],
        "parameter_hints": ["role", "is_admin", "admin", "permissions", "price", "discount"],
        "content_types": ["application/json", "application/x-www-form-urlencoded"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "methods": ["GET", "HEAD"],
        "passive_only": True,
    },
    "GraphQL": {
        "payloads": ["GRAPHQL-INTROSPECTION-OBSERVE", "GRAPHQL-QUERY-OBSERVE"],
        "parameter_hints": ["query", "operationName", "variables"],
        "content_types": ["application/json", "application/graphql"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "File Upload": {
        "payloads": ["UPLOAD-SURFACE-OBSERVE"],
        "parameter_hints": ["file", "upload", "attachment", "document"],
        "content_types": ["multipart/form-data"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "IDOR / BOLA": {
        "payloads": ["IDOR-OBJECT-ID-OBSERVE", "IDOR-PEER-OBJECT-OBSERVE"],
        "parameter_hints": ["id", "user_id", "uid", "account_id", "profile_id", "order_id", "invoice_id", "document_id", "file_id", "item_id", "product_id", "cart_id"],
        "content_types": ["application/json", "application/x-www-form-urlencoded", "text/html"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "CSRF": {
        "payloads": ["CSRF-TOKEN-PRESENCE-OBSERVE", "CSRF-SAME-SITE-OBSERVE"],
        "parameter_hints": [],
        "content_types": ["application/x-www-form-urlencoded", "multipart/form-data", "application/json"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "methods": ["POST", "PUT", "PATCH", "DELETE"],
        "passive_only": True,
    },
    "Rate Limiting": {
        "payloads": ["RATE-LIMIT-OBSERVE"],
        "parameter_hints": ["login", "otp", "code", "token", "reset", "search"],
        "content_types": ["application/json", "application/x-www-form-urlencoded"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "HTTP Parameter Pollution": {
        "payloads": ["HPP-DUPLICATE-PARAM-OBSERVE"],
        "parameter_hints": ["id", "q", "search", "sort", "filter", "redirect", "next"],
        "content_types": [],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "Host Header Injection": {
        "payloads": ["HOST-HEADER-OBSERVE"],
        "parameter_hints": [],
        "content_types": ["text/html", "application/json"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "Prototype Pollution": {
        "payloads": ["__proto__-OBSERVE", "constructor.prototype-OBSERVE"],
        "parameter_hints": ["__proto__", "prototype", "constructor", "config", "options"],
        "content_types": ["application/json", "application/x-www-form-urlencoded"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
    "Cache Behavior": {
        "payloads": ["CACHE-KEY-OBSERVE", "CACHE-CONTROL-OBSERVE"],
        "parameter_hints": ["q", "query", "url", "path", "id"],
        "content_types": ["text/html", "application/json", "text/plain"],
        "source_names": ["OWASP Cheat Sheet Series"],
        "passive_only": True,
    },
}


PAYLOADS = {family: data["payloads"] for family, data in PAYLOAD_CATALOG.items()}


def applicable_families(parameter: str, content_type: str = "", *, body: str = "") -> list[str]:
    """Return payload families that are sensible for an observed input surface."""
    p = (parameter or "").strip().lower()
    ct = (content_type or "").lower()
    is_xml = "xml" in ct or body.lstrip().startswith(("<?xml", "<!doctype"))
    is_json = "json" in ct

    selected: list[str] = []
    for family, meta in PAYLOAD_CATALOG.items():
        if family == "XXE" and not is_xml:
            continue
        hints = set(meta["parameter_hints"])
        type_match = bool(meta["content_types"] and any(x in ct for x in meta["content_types"]))
        hint_match = p in hints or any(p.endswith("_" + h) or p.endswith("-" + h) for h in hints)
        if hint_match or type_match:
            selected.append(family)

    # Keep a conservative fallback for generic text parameters.
    if not selected and not is_xml:
        if any(x in ct for x in ("text/", "form-urlencoded", "json")):
            selected.extend(["XSS", "SQL Injection"])

    return list(dict.fromkeys(selected))


def source_urls_for(family: str) -> list[str]:
    names = set(PAYLOAD_CATALOG.get(family, {}).get("source_names", []))
    return [item["url"] for item in PAYLOAD_SOURCES if item["name"] in names]
