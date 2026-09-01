from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def endpoint_params(url: str):
    p = urlsplit(url)
    return p, parse_qsl(p.query, keep_blank_values=True)


def mutate_query(url: str, idx: int, value: str) -> str:
    p = urlsplit(url)
    params = parse_qsl(p.query, keep_blank_values=True)
    if idx >= len(params):
        return url
    params[idx] = (params[idx][0], value)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(params), p.fragment))


def likely_param_names(url: str, names: set[str]) -> list[tuple[int, str, str]]:
    p, params = endpoint_params(url)
    out = []
    for i, (name, value) in enumerate(params):
        if name.lower() in names or not names:
            out.append((i, name, value))
    return out
