"""Módulo 10 — Closed Loop Validation.

Após a remediação valida, por ativo e exposição:
patch instalado · serviço reiniciado · CVE desapareceu · exposição eliminada · compliance atingido.

O agente (ou o Ansible) devolve a evidência (versão instalada, KB, serviços, portas, software); o servidor
volta a correlacionar o ativo para confirmar que o CVE já não é detetado e só então fecha a exposição,
atualiza a CMDB e propaga o estado ao OMXVuln. Falhas repetem a validação (3 tentativas) e escalam.
"""
from __future__ import annotations

import calendar
import json
import logging
from datetime import timedelta

from ..extensions import db
from ..models import Asset, CveIntel, Exposure, Task, Tenant, Validation, utcnow
from . import correlate, inventory

log = logging.getLogger("omxpatch.validation")
CHECKS = {"patch_installed": "Patch instalado", "service_restarted": "Serviço reiniciado",
          "cve_gone": "CVE desapareceu", "exposure_eliminated": "Exposição eliminada",
          "compliance": "Compliance atingido (dentro do SLA)"}
MAX_ATTEMPTS = 3


def schedule(ex: Exposure, tenant: Tenant, source_task: Task | None = None, delay_minutes: int = 0) -> Validation:
    v = Validation.query.filter_by(exposure_id=ex.id, status="pending").first()
    if v is None:
        v = Validation(tenant_id=ex.tenant_id, exposure_id=ex.id, asset_id=ex.asset_id, cve_id=ex.cve_id, status="pending")
        db.session.add(v)
        db.session.flush()
    asset = ex.asset
    patch = ex.patch
    payload = {"validation_id": v.id, "exposure_id": ex.id, "cve": ex.cve_id, "software": ex.software_name,
               "fixed_version": ex.fixed_version, "port": ex.port,
               "patch": {"uid": patch.patch_uid, "package": patch.package_name, "version_fixed": patch.version_fixed,
                         "installer": patch.installer} if patch else {},
               "patched_at": (ex.patched_at or utcnow()).isoformat(),
               "patched_at_epoch": calendar.timegm((ex.patched_at or utcnow()).timetuple()),
               "collect_software": True}
    mode = "ansible" if (asset.connection == "ansible" and asset.agent is None) else "agent"
    t = Task(tenant_id=ex.tenant_id, type="validate", asset_id=asset.id, exposure_id=ex.id, mode=mode,
             status="queued" if not delay_minutes else "pending",
             not_before=utcnow() + timedelta(minutes=delay_minutes) if delay_minutes else None,
             payload=json.dumps(payload), ring=asset.ring)
    db.session.add(t)
    db.session.flush()
    v.task_id = t.id
    return v


def still_vulnerable(asset: Asset, ex: Exposure) -> bool:
    cve = CveIntel.query.filter_by(cve_id=ex.cve_id).first()
    if cve is None:
        return True
    if ex.fixed_version.upper().startswith("KB"):
        return ex.fixed_version.upper() not in {str(k).upper() for k in asset.hw.get("hotfixes", [])}
    idx = correlate._index([cve])
    for sw, c, _entry in correlate.candidates(asset, idx):
        if sw.name[:255] == ex.software_name or not ex.software_name:
            return True
    return False


def evaluate(v: Validation, report: dict) -> Validation:
    """Aplica a evidência recolhida e decide: passed / partial / failed (+ fecho da exposição)."""
    ex = db.session.get(Exposure, v.exposure_id) if v.exposure_id else None
    asset = db.session.get(Asset, v.asset_id)
    tenant = db.session.get(Tenant, v.tenant_id)
    checks: dict[str, bool | None] = {}
    if report.get("software") is not None:
        inventory.set_software(asset, report["software"], source="validation", replace=bool(report.get("full_inventory")))
    if report.get("hotfixes") is not None:
        hw = asset.hw
        hw["hotfixes"] = sorted({str(k).upper() for k in list(hw.get("hotfixes", [])) + list(report["hotfixes"])})
        asset.hardware = json.dumps(hw)
    checks["patch_installed"] = report.get("patch_installed")
    checks["service_restarted"] = report.get("service_restarted")
    if ex is not None:
        checks["cve_gone"] = not still_vulnerable(asset, ex)
        port_open = bool(ex.port and ex.port in {int(p) for p in report.get("ports_open", []) if str(p).isdigit()})
        checks["exposure_eliminated"] = bool(checks["cve_gone"] and not (port_open and not checks["cve_gone"]))
        closed_at = utcnow()
        checks["compliance"] = bool(ex.due_date is None or closed_at <= ex.due_date)
    v.checks = json.dumps(checks)
    v.attempts = (v.attempts or 0) + 1
    hard = [checks.get(k) for k in ("patch_installed", "service_restarted", "cve_gone", "exposure_eliminated")
            if checks.get(k) is not None]
    if hard and all(hard):
        v.status = "passed"
        if ex is not None:
            ex.status, ex.closed_at = "closed", utcnow()
            ex.patched_at = ex.patched_at or utcnow()
            correlate.refresh(ex, tenant)
            ex.risk_score, ex.risk_category = 0, "low"
            ex.residual_score = 0
            _after_closed(ex, tenant, v)
    elif any(h is False for h in hard) and v.attempts < MAX_ATTEMPTS:
        v.status = "pending"
        if ex is not None:
            schedule(ex, tenant, delay_minutes=30)
    else:
        v.status = "failed" if any(h is False for h in hard) else "partial"
        if ex is not None and v.status == "failed" and ex.status == "remediated":
            ex.status = "open"
    return v


def on_report(task: Task, report: dict) -> None:
    pl = task.payload_data
    v = db.session.get(Validation, pl.get("validation_id")) if pl.get("validation_id") else None
    if v is None:
        return
    if report.get("status") == "failed" and not report.get("software") and not report.get("checks"):
        v.attempts = (v.attempts or 0) + 1
        v.status = "failed" if v.attempts >= MAX_ATTEMPTS else "pending"
        return
    merged = dict(report)
    for k, val in (report.get("checks") or {}).items():
        merged.setdefault(k, val)
    evaluate(v, merged)


def _after_closed(ex: Exposure, tenant: Tenant, v: Validation) -> None:
    """Fecho: CMDB, OMXVuln, GRC, SIEM e remoção de controlos temporários."""
    from . import controls
    from ..connectors import sync
    from ..models import CmdbChange
    db.session.add(CmdbChange(tenant_id=tenant.id, asset_id=ex.asset_id, field="exposure_closed",
                              old=ex.cve_id, new="closed", source="validation"))
    asset = ex.asset
    asset.cmdb_synced_at = utcnow()
    controls.retire_for(ex)
    try:
        sync.on_exposure_closed(tenant, ex)
    except Exception as exc:  # noqa: BLE001 - as integrações nunca podem impedir o fecho
        log.warning("Pós-fecho %s: %s", ex.cve_id, exc)


def stats(tenant_id: int) -> dict:
    q = Validation.query.filter_by(tenant_id=tenant_id)
    return {s: q.filter_by(status=s).count() for s in ("pending", "passed", "partial", "failed")}
