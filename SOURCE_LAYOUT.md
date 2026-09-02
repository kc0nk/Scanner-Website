# Source Layout

The v3.45.0 source is intentionally kept as a single Python/PySide6 desktop application.
The desktop UI, scanner behavior, repeater behavior, browser/session handling, and module
set are unchanged by the source-cleanup pass.

## Packages

- `app/` — application entry point and version metadata.
- `core/` — models, session transport, scanner context, engine, and payload catalog.
- `modules/` — vulnerability-testing modules.
- `ui/` — the complete PySide6 desktop interface, including Dashboard, Terminal,
  Exploitation, Repeater, JWT, Render, and interception views.

## Maintenance rule

Keep UI behavior and scanner semantics separate from cosmetic refactors. When changing
logic, make it in a dedicated functional patch rather than mixing it into source cleanup.
