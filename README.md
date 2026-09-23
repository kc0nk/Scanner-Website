# KCONK Suite 5.0 — Functional Web Security Workbench

KCONK Suite is an independent PySide6 desktop workbench whose workflow mirrors the major Burp-style testing stages: dashboard/task control, target scope and site mapping, proxy history/interception, browser traffic capture, repeater, intruder, sequencing, decoding, comparison, extensions and project data. The current implementation is independent of Burp Suite internals.

## Fixed UI

The entire visual workbench is rendered inside a fixed 1500×920 design canvas. A larger desktop leaves unused space around the canvas; a smaller desktop scrolls the canvas instead of reflowing or scaling the design.

## Modules

- Dashboard — tasks, live browser traffic and traffic-driven analysis.
- Target — scope, site map and controlled passive/active analysis.
- Proxy — HTTP history, local HTTP listener, intercept/release/drop and context actions. HTTPS browser traffic is captured through Chrome DevTools Protocol, which keeps the browser session decrypted for inspection.
- Intruder — controlled parameter/payload replay with response metrics.
- Repeater — manual HTTP request editing/replay and saved-request workflow.
- Collaborator — local canary generation for authorized out-of-band correlation notes.
- Sequencer — token sample entropy inspection.
- Decoder — encoding/decoding and common hashes.
- Comparer — message/text diff.
- Logger — unified event log.
- Organizer — saved request templates.
- Extensions — local Python `register(app)` extensions.
- Discover — analysis artifacts and finding evidence.

## Proxy model

The built-in listener supports cleartext HTTP forwarding and intercept. HTTP CONNECT is transparently tunnelled. For browser HTTPS, KCONK uses CDP network events to inspect decrypted requests and responses rather than implementing its own TLS interception CA.

## Run

```bash
./run.sh
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Use the project only against systems and traffic you are authorized to assess.
