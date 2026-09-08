from core.analyzer import WebAnalyzer

A = WebAnalyzer()

def expect(family, payload, b, t, bs=200, ts=200, headers=None):
    state, _ = A._evidence_for(family, payload, b, t, bs, ts, headers or {}, "https://target.test/x")
    return state

assert expect("SQL Injection", "'", "hello", "hello SQL syntax error") == "CONFIRMED"
assert expect("SQL Injection", "'", "hello SQL syntax error", "hello SQL syntax error") == "TESTED"
assert expect("SSTI", "{{7*7}}", "hello", "hello 49") == "CONFIRMED"
assert expect("LFI / Traversal", "../../etc/passwd", "hello", "root:x:0:0:root:/root:/bin/bash") == "CONFIRMED"
assert expect("LFI / Traversal", "../../etc/passwd", "localhost", "localhost") == "TESTED"
assert expect("Command Injection", ";id", "hello", "uid=1000 gid=1000") == "CONFIRMED"
assert expect("Command Injection", ";id", "uid=1000", "uid=1000") == "TESTED"
assert expect("Open Redirect", "https://example.com/", "ok", "redirect", 302, 302, {"location": "https://example.com/"}) == "CONFIRMED"
assert expect("Open Redirect", "https://example.com/", "ok", "redirect", 200, 200, {}) == "TESTED"
assert expect("SSRF", "http://127.0.0.1/", "ok", "localhost") == "TESTED"
assert expect("XSS", "<script>alert(1)</script>", "ok", "<script>alert(1)</script>") == "TESTED"
print("evidence tests: PASS")
