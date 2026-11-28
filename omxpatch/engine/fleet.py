"""I1 — fiabilidade de patches entre organizações (anónima, opt-in) e avisos de problemas conhecidos.

Privacidade: só participam organizações que ativaram «Partilhar telemetria de patches» e só vêem o agregado quem também participa (reciprocidade).
Nunca se expõem nomes, ativos nem valores por organização: apenas {organizações, aplicações, taxas}. Com menos de ``MIN_TENANTS`` organizações ou
``MIN_REPORTS`` aplicações o agregado é omitido (k-anonimato), para que ninguém consiga deduzir o resultado de uma organização concreta."""
from __future__ import annotations

from ..models import Patch, PatchAdvisory, PatchTelemetry, Tenant

MIN_TENANTS = 3
MIN_REPORTS = 10
SEVERITIES = ("low", "medium", "high", "critical")


def fleet_stats(patch: Patch) -> dict | None:
    from ..extensions import db
    me = db.session.get(Tenant, patch.tenant_id)
    if me is None or not me.share_telemetry:
        return None
    rows = (PatchTelemetry.query.join(Patch, Patch.id == PatchTelemetry.patch_id).join(Tenant, Tenant.id == PatchTelemetry.tenant_id)
            .filter(Patch.patch_uid == patch.patch_uid, Patch.os_family == patch.os_family, Tenant.share_telemetry.is_(True), Tenant.active.is_(True))
            .with_entities(PatchTelemetry.tenant_id, PatchTelemetry.result, PatchTelemetry.crashed).all())
    tenants = {r[0] for r in rows}
    n = len(rows)
    if len(tenants) < MIN_TENANTS or n < MIN_REPORTS:
        return None
    ok = sum(1 for r in rows if r[1] == "success")
    return {"tenants": len(tenants), "n": n, "success_rate": round(ok * 100 / n, 1),
            "rollback_rate": round(sum(1 for r in rows if r[1] == "rolled_back") * 100 / n, 1),
            "crash_rate": round(sum(1 for r in rows if r[2]) * 100 / n, 1)}


def advisories_for(patch: Patch) -> list[dict]:
    uid = (patch.patch_uid or "").lower()
    q = PatchAdvisory.query.filter(PatchAdvisory.active.is_(True), PatchAdvisory.tenant_id.in_([patch.tenant_id]) | PatchAdvisory.tenant_id.is_(None))
    return [{"title": a.title, "severity": a.severity, "url": a.url, "source": a.source, "scope": "global" if a.tenant_id is None else "organização"}
            for a in q.all() if a.patch_uid.lower() == uid]
