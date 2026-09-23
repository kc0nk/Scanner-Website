# Proxy Browser Capture v26

- Added a web/globe button beside the theme controls in the main navbar.
- Clicking it launches a dedicated Chrome/Chromium profile with CDP enabled.
- Browser network events are captured by `ChromeCaptureThread`.
- Only `http://` and `https://` URLs are added to HTTP History; `data:` and other internal resources are ignored.
- Selecting a history row populates the resizable Request/Response inspectors.
- Response status, length, MIME type, headers and response body are updated as CDP events arrive.
- Chrome capture is stopped when KCONK closes.
