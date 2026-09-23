# KCONK Suite v28 — Single Scope

Proxy now uses exactly **one active scope** shared by Browser Capture, Intercept, and HTTP History.

## Scope semantics

- Scope is an HTTP/HTTPS origin: `scheme://host[:port]`.
- Paths below the same origin are automatically in scope.
- A path entered in the UI is normalized to the origin.
- Different hosts, schemes, or ports are out of scope.
- `chrome://`, `data:`, and other non-HTTP(S) URLs are never processed.

## Pipeline

```text
Chrome/CDP
    |
    v
Single Scope Validator
    |
    +-- OUT OF SCOPE -> browser continues normally
    |                  no Intercept / no HTTP History
    |
    +-- IN SCOPE ----> Proxy processing
                         |
                         +-- Intercept ON  -> wait for Forward/Drop
                         +-- Intercept OFF -> normal flow
                         |
                         v
                     HTTP History
```

## Example

Scope:

```text
https://example.com
```

In scope:

```text
https://example.com/
https://example.com/login
https://example.com/api/user
https://example.com/static/app.js
```

Out of scope:

```text
https://google.com/
https://github.com/
http://example.com/
```
