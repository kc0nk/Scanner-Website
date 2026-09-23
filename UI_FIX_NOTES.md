# KCONK Suite v6 UI Fixes

- Reference canvas: 1366x704 client area, matching the 1366x736 desktop screenshot with the window-manager title bar.
- Top navigation is no longer hidden by the outer scroll position at startup.
- The outer canvas is fixed; larger desktops center it and smaller desktops scroll it instead of reflowing/scaling the UI.
- Sidebar width is 402px to match the original workbench proportions.
- Dashboard is compacted to fit the reference viewport without clipped cards.
- Dashboard traffic table uses a 5-column Burp-like compact layout and no horizontal scrollbar.
- Individual modules are wrapped in an internal vertical scroll area, so long modules do not break the fixed chrome.
- Request/response row selection remains compatible with the compact dashboard table and full proxy history table.
- All Python sources were syntax-checked.
