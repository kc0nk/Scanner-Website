# CTF Exploit Workbench v2.1

## Repeater improvements

- HTTP History context menu: **Send to Repeater**
- Double-clicking a browser-captured history row opens it in Repeater.
- Captured requests preserve method, URL, headers and body.
- Repeater **Send** executes the edited HTTP request.
- Repeater **Cancel** requests cooperative cancellation while streaming.
- Repeater **< / >** navigate previous/next sent response snapshots.
- Navigation restores request + response + metadata without re-sending.
- Supports GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS.

## Run

```bash
python -m pip install -r requirements.txt
./run.sh
```
