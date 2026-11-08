"""API REST v1 (token Bearer do perfil do utilizador); super-administradores indicam a organização em ``X-Tenant-ID``."""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import timedelta

from flask import Blueprint, abort, g, jsonify, request

from ..connectors import omxgrc, omxvuln, signals as signals_mod, sync
from ..connectors.store import ConnectorError
from ..engine import advisor, autonomous, compliance, controls, correlate, deploy, executive, intel, inventory, patches, plans as plans_mod, practices as practices_mod, preflight, sources
from ..extensions import db
from ..models import (OperationPlan, Preflight, Asset, AutonomousRun, Campaign, ControlAction, CveIntel, EnrollmentToken, Exposure, Patch, Tenant,
                      Validation, utcnow)
from ..security import audit, get_scoped_or_404, require_tenant, roles_required, scoped

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.before_request
def _require_token():
    if g.get("api_user") is None:
        return jsonify({"error": "Token de API inválido ou em falta"}), 401
    return None


def _asset(a: Asset) -> dict:
    return {"id": a.id, "uid": a.uid, "name": a.name, "fqdn": a.fqdn, "ip": a.ip, "kind": a.kind, "source": a.source,
            "managed": a.managed, "shadow_it": a.shadow_it, "os": {"family": a.os_family, "name": a.os_name, "version": a.os_version},
            "user": a.primary_user, "owner": a.owner, "criticality": a.criticality, "business_value": a.business_value,
            "geo": {"country": a.country, "city": a.city, "lat": a.latitude, "lon": a.longitude}, "ring": a.ring,
            "tags": a.tag_list, "ports": a.ports, "cloud": {"provider": a.cloud_provider, "id": a.cloud_id},
            "hardware": a.hw if "hotfixes" not in a.hw else {k: v for k, v in a.hw.items() if k not in ("hotfixes", "services", "capabilities")},
            "last_seen": a.last_seen.isoformat(), "cmdb_ref": a.cmdb_ref}


def _exposure(e: Exposure) -> dict:
    return {"id": e.id, "cve": e.cve_id, "asset_id": e.asset_id, "asset": e.asset.name, "software": e.software_name,
            "installed_version": e.installed_version, "fixed_version": e.fixed_version, "status": e.status,
            "risk": {"score": e.risk_score, "category": e.risk_category, "residual": e.residual_score, "factors": e.factor_list},
            "verdict": e.verdict_data, "patch": {"id": e.patch_id, "uid": e.patch.patch_uid} if e.patch else None,
            "patch_available": e.patch_available, "detected_at": e.detected_at.isoformat(),
            "due_date": e.due_date.isoformat() if e.due_date else None, "omxvuln_finding_id": e.omxvuln_finding_id}


def _patch(p: Patch, with_intel: bool = False) -> dict:
    d = {"id": p.id, "uid": p.patch_uid, "title": p.title, "vendor": p.vendor, "product": p.product, "os_family": p.os_family,
         "installer": p.installer, "version_fixed": p.version_fixed, "cves": p.cve_list, "severity": p.severity, "status": p.status,
         "sha256": p.sha256, "has_file": bool(p.local_file), "reboot_required": p.reboot_required, "source": p.source}
    if with_intel:
        i = patches.intelligence(p)
        d["intelligence"] = {k: i[k] for k in ("level", "score", "reasons", "combined_success_rate", "reported_problems", "impact")}
    return d


@bp.get("/me")
def me():
    u = g.api_user
    t = require_tenant() if not u.is_superadmin or request.headers.get("X-Tenant-ID") else None
    return {"email": u.email, "role": u.role, "superadmin": u.is_superadmin,
            "tenant": {"id": t.id, "slug": t.slug, "name": t.name} if t else None}


# --------------------------------------------------------------------------- ativos


@bp.get("/assets")
def assets():
    limit = min(request.args.get("limit", 500, type=int), 5000)
    return jsonify([_asset(a) for a in scoped(Asset).order_by(Asset.id).offset(request.args.get("offset", 0, type=int)).limit(limit)])


@bp.post("/assets")
@roles_required("admin", "user")
def assets_upsert():
    data = request.get_json(silent=True) or {}
    items = data if isinstance(data, list) else [data]
    tenant = require_tenant()
    out = []
    for it in items[:1000]:
        try:
            a, created = inventory.upsert_asset(tenant, it, source=it.get("source") if it.get("source") in ("import", "manual") else "import")
        except ValueError as exc:
            abort(400, description=str(exc))
        if it.get("software"):
            inventory.set_software(a, it["software"], source="api")
        out.append({"id": a.id, "created": created})
    audit("assets_upserted", f"API {len(out)}", user=g.api_user)
    db.session.commit()
    return jsonify(out), 201


@bp.get("/assets/<int:asset_id>")
def asset_get(asset_id: int):
    a = get_scoped_or_404(Asset, asset_id)
    d = _asset(a)
    d["software"] = [{"name": s.name, "version": s.version, "vendor": s.vendor} for s in a.software]
    return jsonify(d)


@bp.post("/discover")
@roles_required("admin")
def discover():
    data = request.get_json(silent=True) or {}
    try:
        res = inventory.sweep(require_tenant(), data.get("targets", ""), probe_ot=bool(data.get("probe_ot")))
    except ValueError as exc:
        abort(400, description=str(exc))
    audit("asset_discovery", json.dumps(res), user=g.api_user)
    db.session.commit()
    return jsonify(res)


# --------------------------------------------------------------------------- exposições, inteligência, patches


@bp.get("/exposures")
def exposures():
    q = scoped(Exposure)
    a = request.args
    if a.get("status"):
        q = q.filter(Exposure.status == a["status"])
    else:
        q = q.filter(Exposure.status.in_(("open", "mitigated", "patching", "remediated")))
    if a.get("category"):
        q = q.filter(Exposure.risk_category.in_(a.getlist("category")))
    if a.get("cve"):
        q = q.filter(Exposure.cve_id == a["cve"].upper())
    limit = min(a.get("limit", 500, type=int), 5000)
    return jsonify([_exposure(e) for e in q.order_by(Exposure.risk_score.desc()).offset(a.get("offset", 0, type=int)).limit(limit)])


@bp.get("/exposures/<int:exposure_id>")
def exposure_get(exposure_id: int):
    return jsonify(_exposure(get_scoped_or_404(Exposure, exposure_id)))


@bp.post("/correlate")
@roles_required("admin", "user")
def correlate_now():
    res = correlate.correlate_tenant(require_tenant())
    res.pop("new_ids", None)
    return jsonify(res)


@bp.get("/intel/<cve_id>")
def intel_get(cve_id: str):
    c = CveIntel.query.filter_by(cve_id=cve_id.upper()).first_or_404()
    return jsonify({"cve": c.cve_id, "cvss": c.cvss, "epss": c.epss, "kev": c.kev, "ransomware": c.ransomware,
                    "exploit_maturity": c.exploit_maturity, "malware": c.malware_list, "cwe": c.cwe, "sources": c.sources.split(","),
                    "advisories": c.advisory_list, "description": c.description})


@bp.post("/intel/import")
@roles_required("admin")
def intel_import():
    try:
        res = intel.import_file((request.get_data(as_text=True) or ""))
    except (ValueError, KeyError) as exc:
        abort(400, description=f"JSON inválido: {exc}")
    return jsonify(res), 201


@bp.get("/patches")
def patches_list():
    q = scoped(Patch)
    if request.args.get("status"):
        q = q.filter(Patch.status == request.args["status"])
    return jsonify([_patch(p, with_intel=bool(request.args.get("intel"))) for p in q.order_by(Patch.id.desc()).limit(1000)])


@bp.post("/patches")
@roles_required("admin", "user")
def patch_create():
    data = request.get_json(silent=True) or {}
    tenant = require_tenant()
    uid = str(data.get("uid", "")).strip()
    if not uid:
        abort(400, description="Campo obrigatório: uid")
    if Patch.query.filter_by(tenant_id=tenant.id, patch_uid=uid).first():
        abort(409, description="Patch já existe")
    p = Patch(tenant_id=tenant.id, patch_uid=uid[:190], title=str(data.get("title", ""))[:500], vendor=str(data.get("vendor", ""))[:200],
              product=str(data.get("product", ""))[:255], os_family=data.get("os_family", ""), installer=data.get("installer", "wua"),
              package_name=str(data.get("package_name", ""))[:255], version_fixed=str(data.get("version_fixed", ""))[:120],
              download_url=str(data.get("download_url", ""))[:1000], sha256=str(data.get("sha256", "")).lower()[:64],
              cves=json.dumps(sorted({str(c).upper() for c in data.get("cves", [])})), severity=data.get("severity", "medium"),
              reboot_required=bool(data.get("reboot_required")), source="manual")
    db.session.add(p)
    audit("patch_created", f"API {uid}", user=g.api_user)
    db.session.commit()
    return jsonify(_patch(p)), 201


@bp.post("/patches/<int:patch_id>/approve")
@roles_required("admin")
def patch_approve(patch_id: int):
    p = get_scoped_or_404(Patch, patch_id)
    p.status = "approved"
    audit("patch_status", f"API {p.patch_uid} → approved", user=g.api_user)
    db.session.commit()
    return jsonify(_patch(p, True))


@bp.post("/patches/community")
@roles_required("admin")
def patches_community():
    items = request.get_json(silent=True) or []
    return jsonify({"updated": patches.import_community(require_tenant().id, items)})


@bp.post("/patches/<int:patch_id>/simulate")
@roles_required("admin", "user")
def patch_simulate(patch_id: int):
    """Simulação prévia (sem instalar) nos ativos do âmbito: ``{"scope": {"cve_id"|"asset_ids"|"tags"}}``."""
    p = get_scoped_or_404(Patch, patch_id)
    data = request.get_json(silent=True) or {}
    scope = data.get("scope") or ({"cve_id": p.cve_list[0]} if p.cve_list else {})
    rows = preflight.simulate_scope(require_tenant(), p, scope, g.api_user)
    audit("preflight_started", f"API {p.patch_uid}: {len(rows)}", user=g.api_user)
    db.session.commit()
    return jsonify([{"id": r.id, "asset_id": r.asset_id, "outcome": r.outcome} for r in rows]), 202


@bp.get("/preflights")
def preflights_list():
    q = scoped(Preflight)
    if request.args.get("patch_id", type=int):
        q = q.filter(Preflight.patch_id == request.args.get("patch_id", type=int))
    return jsonify([{"id": r.id, "patch": r.patch.patch_uid, "asset_id": r.asset_id, "asset": r.asset.name, "outcome": r.outcome,
                     "checks": r.check_list, "predicted": r.predicted_data, "finished_at": r.finished_at.isoformat() if r.finished_at else None}
                    for r in q.order_by(Preflight.id.desc()).limit(500)])


@bp.get("/sources")
def update_sources():
    wins = scoped(Asset).filter(Asset.os_family == "windows").all()
    return jsonify({"windows": sources.matrix(wins), "catalog": sources.APP_CATALOG})


@bp.post("/campaigns")
@roles_required("admin", "user")
def campaign_create():
    data = request.get_json(silent=True) or {}
    tenant = require_tenant()
    p = get_scoped_or_404(Patch, int(data.get("patch_id") or 0))
    try:
        c = deploy.create_campaign(tenant, p, data.get("name") or p.patch_uid, data.get("scope") or {}, g.api_user,
                                   use_rings=data.get("use_rings", True), use_wol=bool(data.get("wol")),
                                   bandwidth_kbps=int(data.get("bandwidth_kbps") or 0), emergency=bool(data.get("emergency")),
                                   reboot_policy=data.get("reboot_policy", "if_needed"), force=bool(data.get("force")),
                                   require_preflight=bool(data.get("require_preflight")))
    except deploy.PatchBlocked as exc:
        abort(409, description=str(exc))
    audit("campaign_created", f"API #{c.id}", user=g.api_user)
    db.session.commit()
    return jsonify({"id": c.id, "status": c.status}), 201


@bp.get("/campaigns")
def campaigns():
    return jsonify([{"id": c.id, "name": c.name, "status": c.status, "patch": c.patch.patch_uid, "current_ring": c.current_ring,
                     **deploy.campaign_summary(c)} for c in scoped(Campaign).order_by(Campaign.id.desc()).limit(200)])


# --------------------------------------------------------------------------- sinais multi-vendor


@bp.post("/signals")
@roles_required("admin", "user")
def signals_post():
    vendor = (request.args.get("vendor") or "generic").lower()[:32]
    tenant = require_tenant()
    try:
        res = signals_mod.ingest(tenant, vendor, request.get_data(as_text=True), request.content_type or "application/json")
    except (ValueError, KeyError) as exc:
        abort(400, description=f"Corpo inválido: {exc}")
    res["exposures_created"] = sync.apply_signals(tenant)
    return jsonify(res), 201


# --------------------------------------------------------------------------- controlos, IA, autonomia, validações


@bp.get("/controls")
def controls_list():
    return jsonify([{"id": c.id, "cve": c.cve_id, "category": c.category, "action": c.action, "status": c.status,
                     "asset": c.asset.name if c.asset else None, "risk_reduction": c.risk_reduction, "via": c.via,
                     "artifact": c.artifact} for c in scoped(ControlAction).order_by(ControlAction.id.desc()).limit(500)])


@bp.post("/advisor")
@roles_required("admin", "user")
def advisor_post():
    data = request.get_json(silent=True) or {}
    tenant = require_tenant()
    asset = get_scoped_or_404(Asset, int(data["asset_id"])) if data.get("asset_id") else None
    row = advisor.ask(tenant, data.get("question") or "Como reduzir o risco para menos de 20 pontos?", asset, g.api_user,
                      target=data.get("target"))
    db.session.commit()
    return jsonify({"id": row.id, "before": row.before_score, "after": row.after_score, "target": row.target_score,
                    "steps": row.steps, "narrative": row.narrative}), 201


@bp.get("/autonomous")
def autonomous_list():
    return jsonify([{"id": r.id, "cve": r.cve_id, "stage": r.stage, "status": r.status, "mode": r.mode,
                     "report": r.report_data} for r in scoped(AutonomousRun).order_by(AutonomousRun.id.desc()).limit(200)])


@bp.post("/autonomous")
@roles_required("admin")
def autonomous_trigger():
    cve = str((request.get_json(silent=True) or {}).get("cve", "")).upper()
    if not cve.startswith("CVE-"):
        abort(400, description="Campo obrigatório: cve")
    run = autonomous.trigger(require_tenant(), cve, force=True)
    db.session.commit()
    return jsonify({"id": run.id if run else None, "started": bool(run)}), 201 if run else 200


@bp.get("/validations")
def validations():
    return jsonify([{"id": v.id, "cve": v.cve_id, "asset_id": v.asset_id, "status": v.status, "checks": v.check_data, "attempts": v.attempts}
                    for v in scoped(Validation).order_by(Validation.id.desc()).limit(500)])


@bp.get("/compliance")
def compliance_get():
    return jsonify(compliance.build(require_tenant()))


@bp.get("/executive")
def executive_get():
    return jsonify(executive.kpis(require_tenant()))


# --------------------------------------------------------------------------- OMXVuln / OMXGRC


@bp.post("/sync/omxvuln")
@roles_required("admin")
def sync_omxvuln():
    try:
        return jsonify(omxvuln.pull_findings(require_tenant()))
    except ConnectorError as exc:
        abort(409, description=str(exc))


@bp.post("/sync/omxgrc")
@roles_required("admin")
def sync_omxgrc():
    return jsonify({"pushed": omxgrc.push_metrics(require_tenant())})


@bp.get("/grc/controls")
def grc_controls():
    """Para o OMXGRC: estado de cada requisito (NIS2, ISO 27001, DORA, PCI-DSS, CIS) com métrica e estado."""
    return jsonify(omxgrc.metrics_payload(require_tenant()))


@bp.get("/grc/evidence")
def grc_evidence():
    """Para o OMXGRC: evidências de remediação validadas (ciclo fechado)."""
    return jsonify(omxgrc.evidence_list(require_tenant(), min(request.args.get("limit", 500, type=int), 5000)))


# --------------------------------------------------------------------------- tokens de registo de agentes


def new_enrollment_token(tenant: Tenant, name: str, ring: int = 4, days: int = 30, max_uses: int = 0) -> tuple[str, EnrollmentToken]:
    raw = "omxe_" + secrets.token_urlsafe(24)
    tok = EnrollmentToken(tenant_id=tenant.id, name=name[:120], token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                          prefix=raw[:10], ring=ring, max_uses=max_uses, expires_at=utcnow() + timedelta(days=days))
    db.session.add(tok)
    return raw, tok


@bp.post("/enrollment-tokens")
@roles_required("admin")
def enrollment_token():
    data = request.get_json(silent=True) or {}
    raw, tok = new_enrollment_token(require_tenant(), data.get("name") or "ansible", int(data.get("ring", 4)),
                                    min(int(data.get("days", 30)), 365), int(data.get("max_uses", 0)))
    audit("enrollment_token_created", tok.name, user=g.api_user)
    db.session.commit()
    return jsonify({"token": raw, "expires_at": tok.expires_at.isoformat()}), 201


# --------------------------------------------------------------------------- operações e boas práticas


def _item(it) -> dict:
    return {"id": it.id, "asset_id": it.asset_id, "asset": it.asset.name, "kind": it.kind, "label": it.label, "status": it.status,
            "simulation": it.sim_outcome, "checks": it.check_list, "actions": it.action_list, "predicted": it.predicted_data,
            "approved_at": it.approved_at.isoformat() if it.approved_at else None, "output": it.output}


def _plan(p: OperationPlan, items: bool = True) -> dict:
    d = {"id": p.id, "name": p.name, "mode": p.mode, "status": p.status, "summary": plans_mod.summary(p)}
    if items:
        d["items"] = [_item(i) for i in p.items]
    return d


@bp.get("/practices")
def practices_catalog():
    return jsonify([{"id": k, "label": v["label"], "category": v["category"], "risk": v["risk"], "servers": v["servers"],
                     "params": {pk: {"label": pv[0], "choices": pv[1], "default": pv[2]} for pk, pv in v["params"].items()}}
                    for k, v in practices_mod.PRACTICES.items()])


@bp.get("/plans")
def plans_list():
    return jsonify([_plan(p, False) for p in scoped(OperationPlan).order_by(OperationPlan.id.desc()).limit(200)])


@bp.get("/plans/<int:plan_id>")
def plan_get(plan_id: int):
    return jsonify(_plan(get_scoped_or_404(OperationPlan, plan_id)))


@bp.post("/plans")
@roles_required("admin", "user")
def plan_create():
    """``{"name", "mode": by_patch|by_asset, "asset_ids": [], "patch_ids": [], "practices": [{"id", "params"}]}``."""
    d = request.get_json(silent=True) or {}
    try:
        p = plans_mod.create(require_tenant(), str(d.get("name") or "Plano API"), d.get("mode") or "by_patch",
                             [int(x) for x in d.get("asset_ids") or []], [int(x) for x in d.get("patch_ids") or []],
                             list(d.get("practices") or []), g.api_user, reboot_policy=d.get("reboot_policy") or "if_needed",
                             respect_windows=bool(d.get("respect_windows", True)))
    except (plans_mod.PlanError, ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    audit("plan_created", f"API #{p.id}", user=g.api_user)
    db.session.commit()
    return jsonify(_plan(p)), 201


@bp.post("/plans/<int:plan_id>/simulate")
@roles_required("admin", "user")
def plan_simulate(plan_id: int):
    p = get_scoped_or_404(OperationPlan, plan_id)
    n = plans_mod.simulate(p, require_tenant(), g.api_user)
    audit("plan_simulate", f"API #{p.id}: {n}", user=g.api_user)
    db.session.commit()
    return jsonify({"simulating": n}), 202


@bp.post("/plans/<int:plan_id>/approve")
@roles_required("admin", "user")
def plan_approve(plan_id: int):
    """OK explícito: exige ``"ok": true``; ``item_ids`` ou ``all_ok``; ``accept_warnings`` para itens com avisos."""
    p = get_scoped_or_404(OperationPlan, plan_id)
    d = request.get_json(silent=True) or {}
    if d.get("ok") is not True:
        return jsonify({"error": "OK explícito em falta (\"ok\": true)"}), 400
    res = plans_mod.approve(p, [int(x) for x in d.get("item_ids") or []] or None, g.api_user,
                            accept_warnings=bool(d.get("accept_warnings")), all_ok=bool(d.get("all_ok")))
    audit("plan_approved", f"API #{p.id}: {res['approved']}", user=g.api_user)
    db.session.commit()
    return jsonify({"approved": res["approved"], "refused": [{"item_id": i.id, "reason": w} for i, w in res["refused"]]})


@bp.post("/plans/<int:plan_id>/execute")
@roles_required("admin", "user")
def plan_execute(plan_id: int):
    p = get_scoped_or_404(OperationPlan, plan_id)
    res = plans_mod.execute(p, require_tenant(), g.api_user)
    audit("plan_executed", f"API #{p.id}: {res['queued']}", user=g.api_user)
    db.session.commit()
    return jsonify({"queued": res["queued"], "skipped": [{"item_id": i.id, "reason": w} for i, w in res["skipped"]]})
