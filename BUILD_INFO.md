# KCONK Suite 5.0.0

Functional Burp-style desktop workbench with a fixed 1500×920 UI canvas.

## Functional parity implemented
- Dashboard task/traffic view
- Target scope + site map + passive/controlled scanner analysis
- Proxy HTTP history + local HTTP listener + intercept release/drop
- Browser CDP network capture for decrypted browser HTTPS
- Repeater request replay
- Intruder controlled payload replay
- Collaborator-style local canary generation
- Sequencer entropy analysis
- Decoder: Base64, URL, Hex, HTML, JWT, SHA-256/SHA-1/MD5/SHA-512
- Comparer diff
- Logger
- Organizer / saved requests
- Extensions loader
- Discover: site map, forms, technologies, secrets, JWT, findings, payload catalog
- Project save/load JSON
- Context menu: Send to Repeater / Intruder, add host to scope, copy URL
- CSRF PoC generation from current Repeater request

The Burp reference upload was inspected as an installation/launcher wrapper; KCONK implements these workflows independently rather than copying proprietary Burp internals or licensing components.
