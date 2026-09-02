# CTF Exploit Workbench v3.40.1

Patch focus: full scanner completion and strict separation of vulnerability scanning from flag extraction.

- Findings never stop a module or the global scan.
- All selected modules run to a terminal state, with bounded module timeout/cleanup.
- Scanner flag extraction/output is disabled.
- Repeater displays raw target responses without flag filtering.
- Scanner findings retain full request snapshots for Repeater.
- RCE findings remain terminal-only and are never auto-executed.
