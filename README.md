# KCONK Suite 4.0 — Functional Burp-style Workbench

KCONK Suite is a PySide6 desktop security workbench with a fixed 1500×920 design canvas so resizing the desktop does not reflow the UI. The navigation and workflow model are inspired by common Burp Suite concepts, while the implementation is independent.

## Modules

- Dashboard — target launch, live capture summary, recent traffic.
- Target — scope management and site-map / passive analysis.
- Proxy — Chrome DevTools network capture and traffic inspection.
- Intruder — controlled sequential payload replay against a selected request.
- Repeater — manual HTTP request editing and replay, with response views.
- Collaborator — local canary generation for OOB correlation workflows.
- Sequencer — token randomness / entropy inspection from samples.
- Decoder — Base64, URL, Hex, HTML entity and JWT decode/encode helpers.
- Comparer — request/response/text diffing.
- Logger — unified application and traffic event log.
- Organizer — saved request collection.
- Extensions — local Python extension discovery and loading.
- Discover — CTF-oriented passive/controlled web analysis.

## Fixed UI behavior

The application uses a fixed 1500×920 canvas inside a scroll area. Large windows keep the same visual geometry; smaller windows scroll rather than scale or rearrange the UI.

## Run

```bash
./run.sh
```

Install dependencies with:

```bash
python -m pip install -r requirements.txt
```

The uploaded Burp reference repository is a launcher/installation wrapper rather than Burp Suite source. This project therefore implements independent, Burp-style workflows instead of copying proprietary internals.
