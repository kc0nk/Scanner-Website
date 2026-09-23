# KCONK Suite

UI/UX shell for the KCONK security suite, redesigned as a Burp Suite-inspired desktop interface using the supplied KCONK emblem.

## Current scope

This revision intentionally removes the previous scanner/analyzer/network functionality. It is a visual UI foundation only.

## Run

```bash
./run.sh
```

or:

```bash
python -m app.main
```

## Structure

- `app/` — application entry point and version
- `ui/` — UI shell
- `assets/kconk_logo.png` — supplied KCONK emblem
