"""Cliente REST genérico dos conectores (SSRF validado, TLS configurável, autenticação por tipo)."""
from __future__ import annotations

import requests

from ..models import Connector
from ..security import check_outbound_url
from .catalog import KINDS
from .store import get_secrets

UA = {"User-Agent": "OMXPatch/1.0"}


def auth_for(c: Connector) -> tuple[dict, tuple | None]:
    spec = KINDS.get(c.kind, {})
    style = spec.get("auth", "none")
    s = get_secrets(c)
    headers: dict = {}
    basic = None
    secret = next(iter(s.values()), "") if s else ""
    if style == "bearer":
        headers["Authorization"] = f"Bearer {s.get('token') or secret}"
    elif style == "splunk":
        headers["Authorization"] = f"Splunk {s.get('token') or secret}"
    elif style == "apikey":
        headers["Authorization"] = f"ApiKey {s.get('api_key') or secret}"
    elif style.startswith("header:"):
        name = style.split(":", 1)[1]
        value = s.get("api_key") or secret
        if c.kind == "sentinelone":
            headers["Authorization"] = f"ApiToken {value}"
        else:
            headers[name] = value
    elif style == "basic":
        basic = (c.username, s.get("password") or secret)
    return headers, basic


def request(c: Connector, method: str, path: str = "", *, json_body=None, params=None, data=None, timeout: int = 30,
            extra_headers: dict | None = None) -> requests.Response:
    base = c.base_url.rstrip("/")
    url = base + (path if path.startswith("/") or not path else "/" + path)
    check_outbound_url(url)
    headers, basic = auth_for(c)
    resp = requests.request(method, url, json=json_body, params=params, data=data, auth=basic, timeout=timeout,
                            verify=bool(c.verify_tls), headers={**UA, **headers, **(extra_headers or {})})
    return resp
