"""Módulo 11 — Security Operations Integration: SIEM, SOAR, ITSM e EDR.

* ``emit``: envia eventos (exposição crítica, patch aplicado, validação, fluxo autónomo) para SIEM e SOAR;
* ``open_ticket``: abre pedido no ITSM (ServiceNow, Jira, Freshservice) quando é preciso decisão humana;
* ``apply_control``: aplica controlos compensatórios — IOC no EDR (Defender, CrowdStrike, SentinelOne), desativação
  de conta (Entra ID) — e delega no SOAR/ITSM o que não tem API segura (regras de deteção, WAF, NGFW).
Todas as ligações são best-effort: uma falha nunca bloqueia o fluxo de remediação.
"""
from __future__ import annotations

import json
import logging
import socket
from datetime import datetime

import requests

from ..models import Connector, ControlAction, Tenant, jloads, utcnow
from .catalog import KINDS
from .http import request
from .store import ConnectorError, of_group

log = logging.getLogger("omxpatch.outbound")


def _leef(event: dict) -> str:
    attrs = "\t".join(f"{k}={str(v).replace(chr(9), ' ')}" for k, v in event.items() if not isinstance(v, (dict, list)))
    return f"LEEF:2.0|Oramix|OMXPatch|1.0|{event.get('type', 'event')}|^|{attrs}"


def syslog_send(host: str, port: int, protocol: str, message: str) -> None:
    pri = f"<{16 * 8 + 6}>"
    line = f"{pri}{datetime.now():%b %d %H:%M:%S} omxpatch {message}"
    if protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(line.encode()[:60000], (host, port))
    else:
        with socket.create_connection((host, port), timeout=10) as s:
            s.sendall(line.encode() + b"\n")


def send_event(c: Connector, event: dict) -> str:
    """Envia o evento para um conector SIEM/SOAR; devolve uma descrição do resultado (ou lança erro)."""
    o = c.opts
    if c.kind == "qradar":
        syslog_send(o.get("host") or "", int(o.get("port") or 514), (o.get("protocol") or "udp").lower(), _leef(event))
        return "syslog LEEF enviado"
    if c.kind == "splunk":
        body = {"event": event, "sourcetype": "omxpatch:event", "index": o.get("index") or "security"}
        r = request(c, "POST", o.get("path") or "/services/collector/event", json_body=body)
    elif c.kind == "elastic":
        r = request(c, "POST", f"/{o.get('index') or 'omxpatch-events'}/_doc", json_body=event)
    elif c.kind == "sentinel":
        r = request(c, "POST", o.get("path") or "", json_body=[event])
    elif c.kind == "xsoar":
        r = request(c, "POST", o.get("path") or "/incident",
                    json_body={"name": f"OMXPatch: {event.get('type')} {event.get('cve', '')}".strip(),
                               "type": o.get("incident_type") or "OMXPatch", "details": json.dumps(event, default=str),
                               "CustomFields": {"omxpatchevent": json.dumps(event, default=str)}})
    else:                                           # sentinel_automation, tines (webhooks)
        r = request(c, "POST", o.get("path") or "", json_body=event)
    r.raise_for_status()
    return f"HTTP {r.status_code}"


def emit(tenant: Tenant, event_type: str, payload: dict) -> int:
    """Envia a todos os SIEM e SOAR ativos da organização. Devolve o n.º de envios bem-sucedidos."""
    event = {"type": event_type, "tenant": tenant.slug, "time": utcnow().isoformat(), "source": "omxpatch", **payload}
    ok = 0
    for c in of_group(tenant.id, "siem") + of_group(tenant.id, "soar"):
        try:
            send_event(c, event)
            ok += 1
            c.last_ok, c.last_sync_at, c.last_detail = True, utcnow(), f"{event_type} enviado"
        except (requests.RequestException, ConnectorError, OSError, ValueError) as exc:
            c.last_ok, c.last_detail = False, str(exc)[:500]
            log.warning("Evento %s -> %s: %s", event_type, c.kind, exc)
    return ok


def open_ticket(tenant: Tenant, title: str, description: str, urgency: str = "high") -> str | None:
    """Abre um pedido no primeiro ITSM ativo. Devolve a referência (n.º do ticket) ou None."""
    for c in of_group(tenant.id, "itsm"):
        o = c.opts
        try:
            if c.kind == "servicenow":
                r = request(c, "POST", "/api/now/table/incident",
                            json_body={"short_description": title[:160], "description": description,
                                       "urgency": {"high": "1", "medium": "2", "low": "3"}.get(urgency, "2"),
                                       "impact": {"high": "1", "medium": "2", "low": "3"}.get(urgency, "2"),
                                       "category": "Security", "caller_id": c.username},
                            extra_headers={"Accept": "application/json"})
                r.raise_for_status()
                return r.json().get("result", {}).get("number", "")
            if c.kind == "jira":
                r = request(c, "POST", "/rest/api/3/issue", json_body={"fields": {
                    "project": {"key": o.get("project") or "SEC"}, "summary": title[:250],
                    "issuetype": {"name": o.get("issue_type") or "Task"},
                    "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [
                        {"type": "text", "text": description[:30000]}]}]}}})
                r.raise_for_status()
                return r.json().get("key", "")
            if c.kind == "freshservice":
                r = request(c, "POST", "/api/v2/tickets", json_body={
                    "subject": title[:250], "description": description, "email": o.get("requester_email") or "secops@localhost",
                    "priority": {"high": 3, "medium": 2, "low": 1}.get(urgency, 2), "status": 2})
                r.raise_for_status()
                return str(r.json().get("ticket", {}).get("id", ""))
        except (requests.RequestException, ConnectorError, ValueError) as exc:
            log.warning("Ticket %s: %s", c.kind, exc)
    return None


# --------------------------------------------------------------------------- controlos compensatórios


def _ioc_type(ioc: str) -> str:
    import ipaddress
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if len(ioc) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in ioc):
        return "sha256"
    return "domain"


def apply_control(tenant: Tenant, ctl: ControlAction) -> tuple[bool, str]:
    """(aplicado, detalhe). ``aplicado=False`` quando ficou delegado/pendente (o detalhe explica)."""
    p = ctl.params_data
    title = f"OMXPatch {ctl.cve_id}: {ctl.action}"
    try:
        if ctl.action in ("block_ioc", "edr_block") and p.get("ioc"):
            ioc, kind = p["ioc"], _ioc_type(p["ioc"])
            for c in of_group(tenant.id, "edr"):
                if c.kind == "defender":
                    t = {"ip": "IpAddress", "domain": "DomainName", "sha256": "FileSha256"}[kind]
                    r = request(c, "POST", "/api/indicators", json_body={
                        "indicatorValue": ioc, "indicatorType": t, "action": "Block", "title": title[:200],
                        "description": f"Controlo compensatório {ctl.cve_id}", "severity": "High", "generateAlert": True})
                elif c.kind == "crowdstrike":
                    t = {"ip": "ipv4", "domain": "domain", "sha256": "sha256"}[kind]
                    r = request(c, "POST", "/iocs/entities/indicators/v1", json_body={"indicators": [{
                        "type": t, "value": ioc, "action": "prevent", "severity": "high", "applied_globally": True,
                        "platforms": ["windows", "mac", "linux"], "description": f"OMXPatch {ctl.cve_id}"}]})
                elif c.kind == "sentinelone" and kind == "sha256":
                    r = request(c, "POST", "/web/api/v2.1/restrictions", json_body={
                        "data": {"type": "black_hash", "value": ioc, "osType": "windows",
                                 "description": f"OMXPatch {ctl.cve_id}"}, "filter": {"tenantScope": True}})
                else:
                    continue
                r.raise_for_status()
                return True, f"{c.kind}: IOC {ioc} bloqueado"
        if ctl.action == "disable_account" and p.get("account"):
            for c in of_group(tenant.id, "discovery"):
                if c.kind == "entra":
                    r = request(c, "PATCH", f"/v1.0/users/{p['account']}", json_body={"accountEnabled": False})
                    r.raise_for_status()
                    return True, f"entra: conta {p['account']} desativada"
        # sem API segura: delega o artefacto no SOAR / ITSM
        body = (f"Controlo compensatório pedido pelo OMXPatch.\nCVE: {ctl.cve_id}\nAtivo: {ctl.asset.name if ctl.asset else '—'}\n"
                f"Ação: {ctl.action} ({ctl.category})\nParâmetros: {json.dumps(p)}\n\nArtefacto:\n{ctl.artifact}")
        for c in of_group(tenant.id, "soar"):
            send_event(c, {"type": "control_request", "cve": ctl.cve_id, "action": ctl.action, "category": ctl.category,
                           "asset": ctl.asset.name if ctl.asset else "", "params": p, "artifact": ctl.artifact})
            return False, f"{c.kind}: pedido enviado ao playbook SOAR"
        ref = open_ticket(tenant, title, body)
        if ref:
            return False, f"ITSM: pedido {ref} aberto"
    except (requests.RequestException, ConnectorError, ValueError, OSError) as exc:
        return False, f"erro: {exc}"
    return False, "Sem conector configurado para esta ação"


def test(c: Connector) -> tuple[bool, str]:
    try:
        if c.kind in KINDS and KINDS[c.kind]["group"] in ("siem", "soar"):
            return True, send_event(c, {"type": "test", "message": "Ligação OMXPatch"})
        r = request(c, "GET", "/")
        return r.status_code < 500, f"HTTP {r.status_code}"
    except (requests.RequestException, ConnectorError, ValueError, OSError) as exc:
        return False, str(exc)[:300]


__all__ = ["jloads"]
