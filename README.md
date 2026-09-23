# KCONK Suite v27 — Proxy Intercept

UI and proxy interception workflow for authorized web-security testing.

## Intercept workflow

1. Click the web browser icon to open the KCONK Chrome capture window.
2. Go to **PROXY → INTERCEPT**.
3. Turn **Intercept ON**.
4. Navigate in the KCONK browser.
5. Requests appear in the waiting queue and are held before the browser sends them.
6. Select a request and click **Forward** to release it.
7. The request continues in Chrome; after the response completes it appears in **HTTP HISTORY**.
8. Click **Drop** to block a request.
9. Turn **Intercept OFF** to release any currently paused requests and return to normal flow.

## Scope

The implementation is intended for authorized testing and local lab environments. HTTPS traffic is observed through Chrome DevTools Protocol; this release does not implement a custom TLS CA MITM.
