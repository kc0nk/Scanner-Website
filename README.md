# CTF Exploit Workbench v1.0.0

Desktop web analysis baseline.

Main areas: Dashboard, Web Analyzer, Workflow, Repeater.

The Web Analyzer keeps payload testing as an integrated feature. The target URL is supplied from the Dashboard project scope; the Analyzer itself focuses on artifact metrics, network data, payloads, and controlled handoff to Repeater.


## v1.0 Workflow
The Workflow page uses a desktop visual node editor with a node library, canvas, branches, and properties panel inspired by the supplied reference.

## Repeater UX refresh
The Repeater is now arranged around a Burp-style manual testing flow: numbered request tabs, Send/Cancel/navigation controls, editable Pretty/Raw/Hex request views, Pretty/Raw/Hex/Render response views, request/response metadata footers, and request parsing from a raw HTTP message including Host/path handling.
