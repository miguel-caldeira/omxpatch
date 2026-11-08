"""Módulo 13 — Executive Dashboard (vista CISO) e métricas partilhadas com a conformidade (Módulo 12)."""
from __future__ import annotations

from datetime import timedelta

from ..models import (RISK_CATEGORIES, Asset, AutonomousRun, Campaign, ControlAction, CveIntel,
                      Exposure, Patch, Simulation, Tenant, Validation, utcnow)
from . import risk


def _mean_days(pairs) -> float | None:
    vals = [(b - a).total_seconds() / 86400 for a, b in pairs if a and b and b >= a]
    return round(sum(vals) / len(vals), 1) if vals else None


def kpis(tenant: Tenant, now=None) -> dict:
    now = now or utcnow()
    tid = tenant.id
    assets = Asset.query.filter_by(tenant_id=tid).all()
    exps = Exposure.query.filter_by(tenant_id=tid).all()
    unresolved = [e for e in exps if e.status in ("open", "mitigated", "patching")]
    by_asset: dict[int, list[Exposure]] = {}
    for e in unresolved:
        by_asset.setdefault(e.asset_id, []).append(e)
    asset_by_id = {a.id: a for a in assets}
    cve_map = {c.cve_id: c for c in CveIntel.query.filter(CveIntel.cve_id.in_({e.cve_id for e in exps} or {"-"}))}
    kev_open = [e for e in unresolved if cve_map.get(e.cve_id) and cve_map[e.cve_id].kev]
    patchable = [e for e in exps if e.patch_available and e.status != "accepted"]
    done = [e for e in patchable if e.status in ("closed", "remediated")]
    on_time_open = [e for e in patchable if e.status in ("open", "mitigated", "patching") and (not e.due_date or e.due_date >= now)]
    compliance = round(100 * (len(done) + len(on_time_open)) / len(patchable), 1) if patchable else 100.0
    breaches = [e for e in unresolved if e.due_date and e.due_date < now]
    top = sorted(((risk.asset_risk([e.risk_score for e in exs]), aid, exs) for aid, exs in by_asset.items()),
                 key=lambda x: (-x[0], x[1]))[:10]
    def available_at(e: Exposure):
        pt = e.patch
        return ((pt.released_at or pt.created_at) if pt else None) or e.detected_at

    mttp = _mean_days((available_at(e), e.patched_at) for e in exps if e.patched_at)
    mttr = _mean_days((e.detected_at, e.closed_at) for e in exps if e.closed_at)
    trend = []
    for w in range(11, -1, -1):
        end = now - timedelta(weeks=w)
        start = end - timedelta(weeks=1)
        trend.append({"week": start.strftime("%d/%m"), "opened": sum(1 for e in exps if start <= e.detected_at < end),
                      "closed": sum(1 for e in exps if e.closed_at and start <= e.closed_at < end)})
    cats = {c: sum(1 for e in unresolved if e.risk_category == c) for c in RISK_CATEGORIES}
    return {
        "total_assets": len(assets), "managed_assets": sum(1 for a in assets if a.managed),
        "shadow_it": sum(1 for a in assets if a.shadow_it), "total_cves": len({e.cve_id for e in unresolved}),
        "open_exposures": len(unresolved), "exposed_assets": len(by_asset),
        "internet_exposed_assets": sum(1 for aid in by_asset if risk.internet_exposed(asset_by_id[aid])),
        "mttp_days": mttp, "mttr_days": mttr, "patch_compliance": compliance,
        "kev_exposures": len(kev_open), "kev_assets": len({e.asset_id for e in kev_open}),
        "sla_breaches": len(breaches), "by_category": cats, "trend": trend,
        "patchable_open": sum(1 for e in unresolved if e.patch_available),
        "no_patch_open": sum(1 for e in unresolved if not e.patch_available),
        "mitigated": sum(1 for e in exps if e.status == "mitigated"),
        "closed_period": sum(1 for e in exps if e.closed_at and e.closed_at >= now - timedelta(days=30)),
        "top_assets": [{"id": aid, "name": asset_by_id[aid].name, "risk": score, "category": risk.category_for(score),
                        "exposures": len(exs), "kev": sum(1 for e in exs if cve_map.get(e.cve_id) and cve_map[e.cve_id].kev),
                        "internet": risk.internet_exposed(asset_by_id[aid]), "criticality": asset_by_id[aid].criticality,
                        "owner": asset_by_id[aid].owner}
                       for score, aid, exs in top],
        "campaigns_active": Campaign.query.filter(Campaign.tenant_id == tid, Campaign.status.in_(("running", "scheduled", "paused"))).count(),
        "controls_active": ControlAction.query.filter(ControlAction.tenant_id == tid, ControlAction.status.in_(("applied", "verified"))).count(),
        "validation_failed": Validation.query.filter_by(tenant_id=tid, status="failed").count(),
        "autonomous_runs": AutonomousRun.query.filter_by(tenant_id=tid).count(),
        "autonomous_completed": AutonomousRun.query.filter_by(tenant_id=tid, status="completed").count(),
        "simulations_blocked": Simulation.query.filter_by(tenant_id=tid, outcome="blocked").count(),
        "patches_repo": Patch.query.filter_by(tenant_id=tid).count(),
        "generated_at": now.isoformat(),
    }
