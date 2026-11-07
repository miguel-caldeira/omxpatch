"""Integração com o OMXGRC (ferramenta irmã): evidências e indicadores de conformidade.

Dois sentidos:

* **push** — o OMXPatch envia ao OMXGRC os resultados dos painéis do Módulo 12 (NIS2, ISO 27001, DORA, PCI-DSS,
  CIS) como *métricas* e cada remediação validada como *evidência* (``POST <evidence_path>`` / ``<metrics_path>``,
  caminhos configuráveis);
* **pull** — o OMXGRC pode consultar o OMXPatch por ``/api/v1/grc/controls`` e ``/api/v1/grc/evidence``
  (autenticação por token Bearer, ver ``web/api.py``).
"""
from __future__ import annotations

import logging

import requests

from ..engine import compliance, executive
from ..models import Exposure, Tenant, Validation, utcnow
from .http import request
from .store import ConnectorError, effective

log = logging.getLogger("omxpatch.omxgrc")


def metrics_payload(tenant: Tenant) -> dict:
    comp = compliance.build(tenant)
    k = executive.kpis(tenant)
    return {"source": "omxpatch", "tenant": tenant.slug, "generated_at": utcnow().isoformat(),
            "kpis": {x: k[x] for x in ("total_assets", "managed_assets", "shadow_it", "total_cves", "open_exposures",
                                       "exposed_assets", "mttp_days", "mttr_days", "patch_compliance", "kev_exposures",
                                       "sla_breaches", "closed_period")},
            "frameworks": {key: {"name": fw["name"], "score": fw["score"], "gaps": fw["gaps"],
                                 "requirements": fw["requirements"]} for key, fw in comp["frameworks"].items()}}


def evidence_item(ex: Exposure, v: Validation | None = None) -> dict:
    return {"type": "patch_validation", "source": "omxpatch", "cve": ex.cve_id, "asset": ex.asset.name,
            "asset_criticality": ex.asset.criticality, "software": ex.software_name, "from_version": ex.installed_version,
            "fixed_version": ex.fixed_version, "detected_at": ex.detected_at.isoformat(),
            "patched_at": ex.patched_at.isoformat() if ex.patched_at else None,
            "closed_at": ex.closed_at.isoformat() if ex.closed_at else None, "risk_before": ex.risk_score,
            "checks": v.check_data if v else {}, "controls": ["NIS2 21.2.e", "ISO 27001 A.8.8", "DORA Art. 9", "PCI-DSS 6.3.3", "CIS 7.7"]}


def evidence_list(tenant: Tenant, limit: int = 500) -> list[dict]:
    out = []
    for ex in Exposure.query.filter_by(tenant_id=tenant.id, status="closed").order_by(Exposure.closed_at.desc()).limit(limit):
        v = Validation.query.filter_by(exposure_id=ex.id, status="passed").order_by(Validation.id.desc()).first()
        out.append(evidence_item(ex, v))
    return out


def push_metrics(tenant: Tenant) -> bool:
    c = effective(tenant.id, "omxgrc")
    if c is None:
        return False
    path = c.opts.get("metrics_path") or "/api/v1/metrics"
    try:
        r = request(c, "POST", path, json_body=metrics_payload(tenant), timeout=60)
        ok = r.status_code < 300
        if c.id:
            c.last_sync_at, c.last_ok, c.last_detail = utcnow(), ok, f"métricas: HTTP {r.status_code}"
        return ok
    except (requests.RequestException, ConnectorError) as exc:
        if c.id:
            c.last_ok, c.last_detail = False, str(exc)[:300]
        log.warning("OMXGRC métricas: %s", exc)
        return False


def push_evidence(tenant: Tenant, ex: Exposure, v: Validation | None = None) -> bool:
    c = effective(tenant.id, "omxgrc")
    if c is None:
        return False
    try:
        r = request(c, "POST", c.opts.get("evidence_path") or "/api/v1/evidence", json_body=evidence_item(ex, v))
        return r.status_code < 300
    except (requests.RequestException, ConnectorError) as exc:
        log.warning("OMXGRC evidência: %s", exc)
        return False


def test(c) -> tuple[bool, str]:
    try:
        r = request(c, "GET", "/healthz")
        return r.status_code < 400, f"HTTP {r.status_code}"
    except (requests.RequestException, ConnectorError) as exc:
        return False, str(exc)[:300]
