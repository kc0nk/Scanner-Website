# KCONK Suite v27 — Proxy Intercept

Proxy interception now uses Chrome DevTools Protocol Fetch interception for the KCONK browser.

- Intercept OFF: browser traffic flows normally and completed HTTP/HTTPS requests appear in HTTP History.
- Intercept ON: HTTP/HTTPS browser requests pause before being sent.
- The Intercept page shows pending requests and the selected request details.
- Forward releases the selected request; the browser continues and its eventual response is added to HTTP History.
- Drop blocks the selected request.
- Turning Intercept OFF automatically releases requests that are currently paused.
- The browser is still captured through CDP; HTTPS remains decrypted inside the browser capture layer rather than by a custom CA MITM.
