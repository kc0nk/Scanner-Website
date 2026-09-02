# Desktop v3.42.2 fixed

## Critical fixes
- Fixed a runtime-breaking `SessionHttpClient._build_request_snapshot()` call mismatch: scanner requests were passing `captured_raw=` to a function that did not accept it, causing request/snapshot generation to fail before or during probes.
- Fixed request snapshot correctness: after a payload mutates URL/body/headers, the Repeater snapshot is reconstructed from the effective request instead of incorrectly reusing the unmodified captured raw request.
- Fixed application-version drift: `app/main.py` now reads `app.version.__version__` instead of hard-coding an older v3.40 value.
- Removed the JWT candidate string `flag` so the weak-secret list is not confused with challenge-flag hunting.

## Existing v3.42 safeguards retained
- Removed legacy flag-hunting infrastructure (`core/flag.py`, `Target.flag_format`, `ExploitResult.flags`, legacy flag UI hook).
- FULL ORIGINAL REQUEST remains the default scanner transport; captured request context is retained and effective request snapshots are replayable.
- Duplicate nested project tree removed; archive has one project root.
- Payload coverage ledger records executed/not-observed states and is reconciled at module completion.
- Findings never stop the scan; each selected module has a bounded execution deadline.
- RCE findings route to Terminal and never auto-execute commands.
