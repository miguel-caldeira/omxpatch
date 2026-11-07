"""Ponto único das sincronizações com sistemas externos (OMXVuln, OMXGRC, ITSM, SIEM/SOAR, CMDB) e dos sinais."""
from __future__ import annotations

import logging

import requests

from ..engine import correlate
from ..extensions import db
from ..models import Asset, AutonomousRun, CveIntel, Exposure, Signal, Tenant, Validation, utcnow
from . import omxgrc, omxvuln, outbound
from .http import request
from .store import ConnectorError, for_tenant

log = logging.getLogger("omxpatch.sync")


def apply_signals(tenant: Tenant) -> int:
    """Sinais de vulnerabilidade de outras plataformas viram exposições (se o ativo e o CVE forem conhecidos)
    e todas as exposições do CVE são reavaliadas com o veredicto multi-vendor."""
    touched: set[str] = set()
    created = 0
    for s in Signal.query.filter_by(tenant_id=tenant.id).filter(Signal.cve_id != "").order_by(Signal.id.desc()).limit(5000):
        touched.add(s.cve_id)
        if s.kind == "vuln" and s.asset_id:
            ex = Exposure.query.filter_by(tenant_id=tenant.id, asset_id=s.asset_id, cve_id=s.cve_id).first()
            if ex is None:
                cve = CveIntel.query.filter_by(cve_id=s.cve_id).first()
                if cve is None:
                    cve = CveIntel(cve_id=s.cve_id, sources=s.source)
                    db.session.add(cve)
                    db.session.flush()
                ex = Exposure(tenant_id=tenant.id, asset_id=s.asset_id, cve_id=s.cve_id, software_name=(s.value or "")[:255],
                              source="signal")
                db.session.add(ex)
                db.session.flush()
                created += 1
    for ex in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.cve_id.in_(touched or {"-"}),
                                    Exposure.status.in_(("open", "mitigated", "patching"))):
        correlate.refresh(ex, tenant)
    db.session.commit()
    return created


def pull_signal_sources(tenant: Tenant) -> dict:
    from . import signals
    from .store import of_group
    out = {}
    for group in ("edr", "vm", "cspm", "fw"):
        for c in of_group(tenant.id, group):
            try:
                if c.opts.get("path") or c.opts.get("vuln_path"):
                    out[c.kind] = signals.pull(c, tenant)["new"]
            except (ConnectorError, requests.RequestException) as exc:
                c.last_ok, c.last_detail = False, str(exc)[:300]
                out[c.kind] = f"erro: {exc}"
    apply_signals(tenant)
    return out


def _safe(label: str, fn, *args, **kw):
    """Cada integração é isolada: uma falha (ou resposta inesperada) nunca impede as restantes nem o fecho."""
    try:
        return fn(*args, **kw)
    except Exception as exc:  # noqa: BLE001
        log.warning("%s: %s", label, exc)
        return None


def on_exposure_closed(tenant: Tenant, ex: Exposure) -> None:
    """Exposição fechada e validada: OMXVuln, OMXGRC (evidência), SIEM/SOAR e CMDB externa."""
    v = Validation.query.filter_by(exposure_id=ex.id, status="passed").order_by(Validation.id.desc()).first()
    _safe("OMXVuln", omxvuln.push_status, tenant, ex, "remediated")
    _safe("OMXGRC", omxgrc.push_evidence, tenant, ex, v)
    _safe("SIEM/SOAR", outbound.emit, tenant, "exposure_closed",
          {"cve": ex.cve_id, "asset": ex.asset.name, "software": ex.software_name, "risk_before": ex.risk_score,
           "checks": v.check_data if v else {}})
    _safe("CMDB", push_cmdb, tenant, [ex.asset])


def on_run_completed(tenant: Tenant, run: AutonomousRun, report: dict) -> None:
    outbound.emit(tenant, "autonomous_run_completed", {"cve": run.cve_id, **{k: report[k] for k in ("assets", "closed", "still_open", "hours")}})
    omxgrc.push_metrics(tenant)


def notify_critical(tenant: Tenant, ex: Exposure) -> None:
    """Exposição crítica/emergência com veredicto multi-vendor: SIEM/SOAR + ticket no ITSM."""
    v = ex.verdict_data
    outbound.emit(tenant, "critical_exposure", {"cve": ex.cve_id, "asset": ex.asset.name, "risk": ex.risk_score,
                                                "category": ex.risk_category, "summary": v.get("summary", "")})
    if ex.risk_category in ("critical", "emergency"):
        outbound.open_ticket(tenant, f"[{ex.risk_category.upper()}] {ex.cve_id} em {ex.asset.name}",
                             f"{v.get('summary', '')}\nRisco {ex.risk_score}/100. Patch {'disponível' if ex.patch_available else 'indisponível'}.",
                             "high")


def push_cmdb(tenant: Tenant, assets: list[Asset]) -> int:
    """Atualiza a CMDB externa (ServiceNow) com o estado do ativo; sem ServiceNow só regista a data de sincronização."""
    c = for_tenant(tenant.id, "servicenow")
    n = 0
    for a in assets:
        if a is None:
            continue
        open_ = Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.asset_id == a.id,
                                      Exposure.status.in_(("open", "mitigated", "patching", "remediated"))).count()
        if c is not None:
            table = c.opts.get("cmdb_table") or "cmdb_ci_computer"
            body = {"name": a.name, "ip_address": a.ip, "os": a.os_name, "os_version": a.os_version,
                    "u_omxpatch_open_vulnerabilities": open_, "u_omxpatch_last_sync": utcnow().isoformat()}
            try:
                if a.cmdb_ref:
                    r = request(c, "PATCH", f"/api/now/table/{table}/{a.cmdb_ref}", json_body=body)
                else:
                    r = request(c, "POST", f"/api/now/table/{table}", json_body=body)
                    if r.status_code < 300:
                        a.cmdb_ref = r.json().get("result", {}).get("sys_id", "")
                if r.status_code >= 300:
                    continue
            except (requests.RequestException, ConnectorError, ValueError) as exc:
                log.warning("CMDB %s: %s", a.name, exc)
                continue
        a.cmdb_synced_at = utcnow()
        n += 1
    return n
