"""Boas práticas de configuração (hardening) com simulação, aplicação e reversão.

Catálogo: ``tls_protocols`` (TLS 1.2/1.3), ``hsts``, ``hide_version`` e ``security_headers`` em **nginx**, **Apache** e **IIS**.
``simulate`` devolve o que seria feito (ações com *diff*, verificações e resultado previsto) sem alterar nada; ``apply`` só é
chamado pelo servidor depois da aprovação do utilizador."""
from __future__ import annotations

from ..config import platform_family
from . import common

PRACTICES = ("tls_protocols", "hsts", "hide_version", "security_headers", "ssh_hardening", "windows_hardening")
OS_PRACTICES = ("ssh_hardening", "windows_hardening")


def _servers(params: dict):
    from .webservers import APACHE, NGINX
    want = (params or {}).get("server", "auto")
    out = []
    if platform_family() == "windows":
        if want in ("auto", "iis"):
            out.append("iis")
    else:
        if want in ("auto", "nginx"):
            out.append(NGINX)
        if want in ("auto", "apache"):
            out.append(APACHE)
    return out


def detect_webservers() -> list[dict]:
    """Servidores web instalados (para o inventário e para a aplicabilidade das boas práticas)."""
    found = []
    for s in _servers({}):
        try:
            if s == "iis":
                from . import iis
                info = iis.detect()
            else:
                info = s.detect()
        except Exception:  # noqa: BLE001
            info = None
        if info:
            found.append({k: info[k] for k in ("type", "version", "config", "running", "ports") if k in info})
    return found


def _plan(server, practice: str, params: dict) -> dict:
    if server == "iis":
        from . import iis
        return iis.plan(practice, params)
    p = server.plan(practice, params)
    p["actions"] = [e.action() for e in p["edits"] if e.changed]
    return p


def simulate(practice: str, params: dict | None = None) -> dict:
    """Plano sem alterar nada: {checks[], actions[], predicted{}}."""
    params = params or {}
    if practice in OS_PRACTICES:
        from . import oshardening
        return oshardening.simulate(practice, params)
    if practice not in PRACTICES:
        return {"checks": [{"id": "practice", "label": "Boa prática conhecida", "status": "block", "detail": practice}], "actions": [], "predicted": {}}
    checks, actions, servers = [], [], []
    for s in _servers(params):
        p = _plan(s, practice, params)
        name = "iis" if s == "iis" else s.name
        if p.get("info") is None:
            continue
        checks += [{**c, "id": f"{name}:{c['id']}", "label": f"[{name}] {c['label']}"} for c in p["checks"]]
        actions += [{**a, "server": name} for a in p["actions"]]
        servers.append({"server": name, **{k: p["predicted"].get(k) for k in ("compliant", "files", "changes", "reload", "reboot")}})
    if not servers:
        return {"checks": [{"id": "server", "label": "Servidor web (nginx / Apache / IIS) detetado", "status": "block",
                            "detail": "Nenhum servidor web encontrado neste equipamento"}], "actions": [], "predicted": {"servers": []}}
    noop = all(s.get("compliant") for s in servers)
    return {"checks": checks, "actions": actions,
            "predicted": {"servers": servers, "noop": noop, "compliant": noop, "reboot": any(s.get("reboot") for s in servers),
                          "summary": "Já em conformidade" if noop else f"{len(actions)} alteração(ões) em {sum(1 for s in servers if not s.get('compliant'))} servidor(es)"}}


def apply(practice: str, params: dict | None, item: str) -> dict:
    """Aplica a boa prática (com teste, verificação e reversão automática em caso de falha)."""
    params = params or {}
    if practice in OS_PRACTICES:
        from . import oshardening
        return oshardening.apply(practice, params, item)
    results, ok, rolled, reboot = [], True, False, False
    for s in _servers(params):
        if s == "iis":
            from . import iis
            if iis.detect() is None:
                continue
            r = iis.apply(practice, params, item)
            name = "iis"
        else:
            if s.detect() is None:
                continue
            r = s.apply(practice, params, item)
            name = s.name
        results.append({"server": name, **r})
        ok = ok and r["status"] == "succeeded"
        rolled = rolled or r.get("rolled_back", False)
        reboot = reboot or r.get("reboot_pending", False)
    if not results:
        return {"status": "failed", "output": "Nenhum servidor web detetado", "actions": [], "rolled_back": False}
    return {"status": "succeeded" if ok else "failed", "rolled_back": rolled, "reboot_pending": reboot,
            "actions": [a for r in results for a in r.get("actions", [])], "verification": {r["server"]: r.get("verification") for r in results},
            "output": "\n".join(f"[{r['server']}] {r['output']}" for r in results), "servers": [r["server"] for r in results]}


def rollback(item: str, params: dict | None = None) -> dict:
    p = params or {}
    if p.get("practice") in OS_PRACTICES:
        from . import oshardening
        return oshardening.rollback(p["practice"], item)
    done = []
    for s in _servers(params or {}):
        try:
            if s == "iis":
                from . import iis
                done += iis.rollback(item)
            else:
                done += s.rollback(item)
        except (OSError, ValueError, KeyError):
            continue
    return {"status": "succeeded" if done else "failed", "output": f"{len(done)} elemento(s) restaurado(s)", "restored": done}


__all__ = ["common"]
