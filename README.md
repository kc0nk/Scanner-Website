# CTF Exploit Workbench v2.0.0

Desktop web-analysis workbench built with PySide6.

## v2.0 browser capture

The Dashboard **Open** button launches a dedicated Google Chrome/Chromium profile with Chrome DevTools Protocol (CDP) enabled. Network activity from pages opened in that dedicated browser profile is captured into **HTTP History**.

Clicking a captured row displays the reconstructed raw HTTP request and response in the Request/Response panes.

The browser profile is intentionally isolated from the user's normal browser profile so the workbench can attach to it reliably without inspecting unrelated Chrome sessions.

## Run

```bash
python -m pip install -r requirements.txt
./run.sh
```

Google Chrome or Chromium must be available in `PATH` (`google-chrome`, `google-chrome-stable`, `chromium`, or `chromium-browser`).
