"""Módulo 7 — Smart Test Rings (Ring 0 Laboratório → Ring 4 Produção global).

A promoção entre anéis é automática e baseada em critérios medidos na campanha: taxa de sucesso, *crash rate*,
experiência do utilizador (UX) e telemetria, com um período de observação (*soak*). Se um critério falha, a
campanha fica em pausa com os motivos e nada avança para a produção.
"""
from __future__ import annotations

from datetime import timedelta

from flask import current_app

from ..extensions import db
from ..models import RINGS, Asset, Campaign, PatchTelemetry, RingPolicy, Task, Tenant, utcnow


def ensure_policies(tenant: Tenant) -> list[RingPolicy]:
    cfg = current_app.config
    existing = {p.ring: p for p in RingPolicy.query.filter_by(tenant_id=tenant.id)}
    for ring in RINGS:
        if ring not in existing:
            soak = 0 if ring == 0 else int(cfg["RING_SOAK_HOURS"]) * (1 if ring < 3 else 2)
            existing[ring] = RingPolicy(tenant_id=tenant.id, ring=ring, min_success=float(cfg["RING_MIN_SUCCESS"]),
                                        max_crash=float(cfg["RING_MAX_CRASH"]), min_ux=float(cfg["RING_MIN_UX"]),
                                        min_devices=int(cfg["RING_MIN_DEVICES"]) if ring < 4 else 1, soak_hours=soak,
                                        auto_promote=True)
            db.session.add(existing[ring])
    db.session.flush()
    return [existing[r] for r in sorted(existing)]


def policy(tenant: Tenant, ring: int) -> RingPolicy:
    return next(p for p in ensure_policies(tenant) if p.ring == ring)


def suggest_ring(asset: Asset) -> int:
    tags = {t.lower() for t in asset.tag_list}
    dept = (asset.department or "").lower()
    if tags & {"lab", "laboratorio", "laboratório", "test", "teste", "ring0"}:
        return 0
    if tags & {"ti", "it", "ring1"} or dept in ("ti", "it"):
        return 1
    if tags & {"poweruser", "power-user", "powerusers", "ring2"}:
        return 2
    if tags & {"ring3", "business"} or (asset.kind == "workstation" and asset.criticality in ("medium", "low")):
        return 3
    return 4


def assign_rings(tenant: Tenant, only_default: bool = True) -> int:
    n = 0
    for a in Asset.query.filter_by(tenant_id=tenant.id):
        if only_default and a.ring != 4:
            continue
        r = suggest_ring(a)
        if r != a.ring:
            a.ring = r
            n += 1
    return n


def metrics(campaign: Campaign, ring: int) -> dict:
    tasks = Task.query.filter_by(campaign_id=campaign.id, type="patch", ring=ring).all()
    final = [t for t in tasks if t.status in ("succeeded", "failed", "rolled_back")]
    ok = [t for t in final if t.status == "succeeded"]
    ids = [t.id for t in tasks]
    tel = PatchTelemetry.query.filter(PatchTelemetry.task_id.in_(ids)).all() if ids else []
    ux = [r.ux_score for r in tel if r.ux_score is not None]
    crashes = sum(1 for r in tel if r.crashed)
    pending = [t for t in tasks if t.status not in ("succeeded", "failed", "rolled_back", "skipped", "cancelled")]
    skipped = sum(1 for t in tasks if t.status in ("skipped", "cancelled"))
    last = max((t.finished_at for t in final if t.finished_at), default=None)
    return {"devices": len(tasks), "pending": len(pending), "done": len(final), "succeeded": len(ok),
            "failed": sum(1 for t in final if t.status == "failed"),
            "rolled_back": sum(1 for t in final if t.status == "rolled_back"), "skipped": skipped,
            "success_rate": round(len(ok) * 100 / len(final), 1) if final else None,
            "crash_rate": round(crashes * 100 / len(final), 1) if final else None,
            "ux": round(sum(ux) / len(ux), 1) if ux else None, "last_finished": last}


def evaluate(campaign: Campaign, tenant: Tenant, ring: int, now=None, final: bool = False) -> dict:
    """Decisão para um anel: wait | promote | hold (com motivos)."""
    now = now or utcnow()
    pol = policy(tenant, ring)
    m = metrics(campaign, ring)
    if m["devices"] == 0:
        return {"decision": "promote", "reasons": ["Anel sem dispositivos em âmbito."], "metrics": m, "policy": pol}
    if m["pending"]:
        return {"decision": "wait", "reasons": [f"{m['pending']} tarefa(s) por concluir."], "metrics": m, "policy": pol}
    reasons = []
    if m["done"] < pol.min_devices and m["done"] < m["devices"]:
        reasons.append(f"Amostra insuficiente ({m['done']} < {pol.min_devices} dispositivos).")
    if m["success_rate"] is not None and m["success_rate"] < pol.min_success:
        reasons.append(f"Taxa de sucesso {m['success_rate']} % < {pol.min_success} %.")
    if m["crash_rate"] is not None and m["crash_rate"] > pol.max_crash:
        reasons.append(f"Crash rate {m['crash_rate']} % > {pol.max_crash} %.")
    if m["ux"] is not None and m["ux"] < pol.min_ux:
        reasons.append(f"Experiência do utilizador {m['ux']} < {pol.min_ux}.")
    if m["done"] == 0:
        reasons.append("Nenhuma tarefa concluída (todas ignoradas ou canceladas).")
    if reasons:
        return {"decision": "hold", "reasons": reasons, "metrics": m, "policy": pol}
    soak = 0 if (campaign.emergency or final) else pol.soak_hours      # o último anel não tem para onde promover
    if soak and m["last_finished"] and now < m["last_finished"] + timedelta(hours=soak):
        left = (m["last_finished"] + timedelta(hours=soak) - now)
        return {"decision": "wait", "reasons": [f"Período de observação: faltam {int(left.total_seconds() // 3600)} h."],
                "metrics": m, "policy": pol}
    if not pol.auto_promote or not campaign.auto_promote:
        return {"decision": "hold", "reasons": ["Critérios cumpridos; promoção manual configurada."], "metrics": m,
                "policy": pol, "manual_ok": True}
    return {"decision": "promote", "reasons": ["Critérios de promoção cumpridos."], "metrics": m, "policy": pol}
