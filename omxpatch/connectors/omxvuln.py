"""Integração com o OMXVuln (ferramenta irmã) através da sua API REST ``/api/v1``.

* **Entrada** — ``pull_findings``: importa as vulnerabilidades abertas do OMXVuln como ativos + exposições
  (software, versão instalada, versão corrigida, CVE, risco). O OMXVuln é a fonte de verdade da deteção; o
  OMXPatch trata da mitigação, do patch e da validação.
* **Saída** — ``push_status``: quando a validação em ciclo fechado confirma o patch, o OMXPatch marca a
  vulnerabilidade como *remediada* no OMXVuln (``POST /findings/<id>/status``) e pede um novo scan ao ativo
  (``POST /scans``) para que o OMXVuln feche a deteção com verificação independente.
"""
from __future__ import annotations

import json
import logging
import re

import requests

from ..extensions import db
from ..models import Asset, CveIntel, Exposure, Tenant, utcnow
from ..engine import correlate, inventory
from .http import request
from .store import ConnectorError, effective

log = logging.getLogger("omxpatch.omxvuln")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
SEV_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}


def _headers(c) -> dict:
    tid = c.opts.get("tenant_id")
    return {"X-Tenant-ID": str(tid)} if tid else {}


def fetch_findings(c, limit: int = 500, max_pages: int = 20) -> list[dict]:
    out: list[dict] = []
    for page in range(max_pages):
        r = request(c, "GET", "/api/v1/findings", params={"limit": limit, "offset": page * limit},
                    extra_headers=_headers(c), timeout=60)
        r.raise_for_status()
        data = r.json()
        out += data
        if len(data) < limit:
            break
    return out


def ingest_findings(tenant: Tenant, findings: list[dict]) -> dict:
    """Converte findings do OMXVuln em ativos + exposições (idempotente)."""
    new_assets = new_exp = skipped = 0
    seen: set[int] = set()
    open_states = ("open", "assigned", "in_progress", "fp_review")
    for f in findings:
        cves = [c.upper() for c in (f.get("cves") or []) if CVE_RE.fullmatch(str(c))]
        host = (f.get("host") or "").strip()
        if not cves or not host or f.get("status") not in open_states:
            skipped += 1
            continue
        import ipaddress
        try:
            ipaddress.ip_address(host)
            ip, name = host, host
        except ValueError:
            ip, name = "", host
        asset, created = inventory.upsert_asset(tenant, {"uid": host, "name": name, "ip": ip, "fqdn": name if not ip else "",
                                                         "managed": False}, source="omxvuln")
        if created:
            new_assets += 1
        if f.get("port"):
            ports = set(asset.ports) | ({int(f["port"])} if str(f["port"]).isdigit() else set())
            asset.open_ports = ",".join(str(p) for p in sorted(ports))
        component = (f.get("component") or "")[:255]
        for cve_id in cves:
            row = CveIntel.query.filter_by(cve_id=cve_id).first()
            if row is None:
                row = CveIntel(cve_id=cve_id, title=(f.get("title") or "")[:500], sources="omxvuln")
                db.session.add(row)
            if row.cvss is None:
                row.cvss = f.get("cvss_score") or SEV_CVSS.get(f.get("severity", ""), 5.0)
            if f.get("kev"):
                row.kev = True
            risk = f.get("risk") or {}
            if risk.get("epss") is not None and row.epss is None:
                row.epss = float(risk["epss"])
            if risk.get("ransomware"):
                row.ransomware = True
            ex = Exposure.query.filter_by(tenant_id=tenant.id, asset_id=asset.id, cve_id=cve_id, software_name=component).first()
            if ex is None:
                ex = Exposure(tenant_id=tenant.id, asset_id=asset.id, cve_id=cve_id, software_name=component,
                              source="omxvuln", installed_version=(f.get("installed_version") or "")[:120],
                              fixed_version=(f.get("fixed_version") or "")[:120],
                              port=int(f["port"]) if str(f.get("port") or "").isdigit() else None)
                db.session.add(ex)
                db.session.flush()
                new_exp += 1
            elif ex.status in ("closed", "remediated") and ex.source == "omxvuln":
                ex.status, ex.closed_at = "open", None
            ex.omxvuln_finding_id = f.get("id")
            ex.last_seen = utcnow()
            seen.add(ex.id)
            correlate.refresh(ex, tenant, row)
    return {"findings": len(findings), "new_assets": new_assets, "new_exposures": new_exp, "skipped": skipped,
            "seen": seen}


def pull_findings(tenant: Tenant) -> dict:
    c = effective(tenant.id, "omxvuln")
    if c is None:
        raise ConnectorError("OMXVuln não configurado (Integrações → OMXVuln, ou [omxvuln] no ficheiro de configuração)")
    res = ingest_findings(tenant, fetch_findings(c))
    # exposições vindas do OMXVuln que deixaram de constar como abertas: remediadas (validar)
    seen = res.pop("seen")
    from ..engine import validation
    gone = 0
    for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.source == "omxvuln",
                                    Exposure.status.in_(("open", "mitigated", "patching"))):
        if ex.id not in seen:
            ex.status, ex.patched_at = "remediated", utcnow()
            validation.schedule(ex, tenant)
            gone += 1
    res["closed_upstream"] = gone
    if c.id:
        c.last_sync_at, c.last_ok, c.last_detail = utcnow(), True, f"{res['findings']} findings, {res['new_exposures']} novas exposições"
    db.session.commit()
    return res


def push_status(tenant: Tenant, ex: Exposure, status: str = "remediated", note: str = "") -> bool:
    c = effective(tenant.id, "omxvuln")
    if c is None or not ex.omxvuln_finding_id or str(c.opts.get("push_status", "true")).lower() not in ("1", "true", "yes", "sim"):
        return False
    try:
        r = request(c, "POST", f"/api/v1/findings/{ex.omxvuln_finding_id}/status", extra_headers=_headers(c),
                    json_body={"status": status, "note": note or f"OMXPatch: {ex.cve_id} remediado e validado"})
        ok = r.status_code < 300
        if ok and str(c.opts.get("rescan", "true")).lower() in ("1", "true", "yes", "sim"):
            rescan(c, ex.asset)
        return ok
    except (requests.RequestException, ConnectorError) as exc:
        log.warning("OMXVuln push_status: %s", exc)
        return False


def rescan(c, asset: Asset) -> bool:
    """Pede ao OMXVuln novo scan ao ativo (procura o alvo registado com o mesmo valor)."""
    try:
        r = request(c, "GET", "/api/v1/targets", extra_headers=_headers(c))
        r.raise_for_status()
        wanted = {asset.ip, asset.name, asset.fqdn} - {""}
        for t in r.json():
            if wanted & set(t.get("value") or []):
                r2 = request(c, "POST", "/api/v1/scans", extra_headers=_headers(c),
                             json_body={"target_id": t["id"], "profile": "auto"})
                return r2.status_code < 300
    except (requests.RequestException, ConnectorError, ValueError) as exc:
        log.warning("OMXVuln rescan: %s", exc)
    return False


def test(c) -> tuple[bool, str]:
    try:
        r = request(c, "GET", "/api/v1/me", extra_headers=_headers(c))
        return r.status_code == 200, (f"Autenticado como {r.json().get('email')}" if r.status_code == 200 else f"HTTP {r.status_code}")
    except (requests.RequestException, ConnectorError, ValueError) as exc:
        return False, str(exc)[:300]


__all__ = ["json"]
