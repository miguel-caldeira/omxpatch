"""Painel executivo (Módulo 13), ativos (Módulo 1), exposições/risco (Módulos 3–4), inteligência (Módulo 2) e sinais."""
from __future__ import annotations

import csv
import io
import json

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..connectors import signals as signals_mod
from ..connectors import sync
from ..engine import advisor, controls, correlate, executive, intel, inventory, patches, risk, simulation, validation
from ..extensions import db
from ..models import (ASSET_KINDS, CRITICALITIES, OPEN_EXPOSURE, Asset, AssetSoftware, CmdbChange, ControlAction, CveIntel,
                      Exposure, Patch, Signal, Simulation, Task, Validation, utcnow)
from ..security import audit, get_scoped_or_404, require_tenant, roles_required, scoped, write_required
from .common import tenant_or_select

bp = Blueprint("main", __name__)


@bp.route("/")
@login_required
def dashboard():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    from flask import current_app
    from ..engine import command_center
    return render_template("command_center.html", tenant=tenant, o=command_center.overview(current_app, tenant, current_user))


@bp.route("/executive")
@login_required
def executive_page():
    """Painel executivo (CISO) — indicadores de gestão."""
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    k = executive.kpis(tenant)
    return render_template("dashboard.html", k=k, tenant=tenant, max_cat=max(k["by_category"].values() or [1]) or 1)


@bp.route("/command/quick", methods=["POST"])
@login_required
@roles_required("admin", "user")
def command_quick():
    """Ações rápidas do Centro de comando. **Nunca aplicam nada**: criam um plano de operações e pedem a simulação;
    a aplicação continua a exigir o OK explícito na página do plano."""
    from ..engine import plans as plans_mod
    tenant = require_tenant()
    kind, oid = request.form.get("kind", ""), request.form.get("id", type=int)
    open_states = ("open", "mitigated", "patching")
    patch_ids, practice, asset_ids, label, mode = [], [], [], "", "by_patch"
    if kind == "patch":
        p = get_scoped_or_404(Patch, oid or 0)
        asset_ids = sorted({e.asset_id for e in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.patch_id == p.id, Exposure.status.in_(open_states))})
        patch_ids, label = [p.id], p.patch_uid
    elif kind == "asset":
        a = get_scoped_or_404(Asset, oid or 0)
        patch_ids = sorted({e.patch_id for e in Exposure.query.filter(Exposure.tenant_id == tenant.id, Exposure.asset_id == a.id, Exposure.status.in_(open_states),
                                                                      Exposure.patch_id.isnot(None))})
        asset_ids, label, mode = [a.id], a.name, "by_asset"
    elif kind == "tls":
        from ..models import PlanItem
        done = {i.asset_id for i in PlanItem.query.filter_by(tenant_id=tenant.id, kind="practice", practice="tls_protocols", status="succeeded")}
        asset_ids = [a.id for a in scoped(Asset).all() if a.hw.get("webservers") and a.id not in done]
        practice, label, mode = [{"id": "tls_protocols", "params": {}}], "TLS 1.2/1.3", "by_asset"
    else:
        abort(400)
    if not asset_ids or not (patch_ids or practice):
        flash("Nada a simular: não há ativos/patches aplicáveis.", "warning")
        return redirect(url_for("main.dashboard"))
    from ..models import OperationPlan
    name = f"Rápido: {label}"
    plan = OperationPlan.query.filter(OperationPlan.tenant_id == tenant.id, OperationPlan.name == name,
                                      OperationPlan.status.in_(("draft", "simulating", "simulated"))).order_by(OperationPlan.id.desc()).first()
    if plan is None:
        try:
            plan = plans_mod.create(tenant, name, mode, asset_ids, patch_ids, practice, current_user)
        except plans_mod.PlanError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("main.dashboard"))
        n = plans_mod.simulate(plan, tenant, current_user)
        audit("command_quick", f"{kind} {label}: plano #{plan.id}, {n} simulação(ões)")
        flash(f"Plano #{plan.id} criado e simulação pedida a {n} item(ns). Nada será aplicado sem o seu OK.", "info")
    else:
        flash(f"Já existe o plano #{plan.id} para «{label}» — a abrir.", "info")
    db.session.commit()
    return redirect(url_for("plans.plan_detail", plan_id=plan.id) if request.form.get("next") == "plan" else url_for("main.dashboard"))


# --------------------------------------------------------------------------- ativos


def _assets_query():
    q = scoped(Asset)
    a = request.args
    if a.get("q"):
        like = f"%{a['q'].strip()}%"
        q = q.filter(db.or_(Asset.name.ilike(like), Asset.ip.ilike(like), Asset.fqdn.ilike(like), Asset.owner.ilike(like),
                            Asset.primary_user.ilike(like), Asset.tags.ilike(like)))
    for field in ("os_family", "kind", "criticality", "source"):
        if a.get(field):
            q = q.filter(getattr(Asset, field) == a[field])
    if a.get("ring", type=int) is not None:
        q = q.filter(Asset.ring == a.get("ring", type=int))
    if a.get("shadow"):
        q = q.filter(Asset.shadow_it.is_(True))
    if a.get("unmanaged"):
        q = q.filter(Asset.managed.is_(False))
    return q.order_by(Asset.name)


@bp.route("/assets")
@login_required
def assets():
    if (r := tenant_or_select()) is not None:
        return r
    pag = _assets_query().paginate(page=request.args.get("page", 1, type=int), per_page=50, error_out=False)
    open_by_asset = dict(db.session.query(Exposure.asset_id, db.func.count(Exposure.id))
                         .filter(Exposure.tenant_id == require_tenant().id, Exposure.status.in_(("open", "mitigated", "patching")))
                         .group_by(Exposure.asset_id).all())
    return render_template("assets/list.html", pag=pag, open_by_asset=open_by_asset, stats=inventory.stats(require_tenant().id))


@bp.route("/assets/new", methods=["GET", "POST"])
@login_required
@roles_required("admin", "user")
def asset_new():
    tenant = require_tenant()
    if request.method == "POST":
        try:
            asset, _ = inventory.upsert_asset(tenant, _asset_form(), source="manual")
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("assets/form.html", asset=None, form=request.form), 400
        audit("asset_created", asset.name)
        db.session.commit()
        return redirect(url_for("main.asset_detail", asset_id=asset.id))
    return render_template("assets/form.html", asset=None, form={})


def _asset_form() -> dict:
    f = request.form
    data = {k: f.get(k, "").strip() for k in ("uid", "name", "fqdn", "ip", "mac", "kind", "os_family", "os_name", "os_version",
                                               "primary_user", "owner", "department", "criticality", "internet_exposed",
                                               "country", "city", "tags", "open_ports", "connection", "ansible_user",
                                               "maintenance_group", "cmdb_ref", "business_value", "ring", "ansible_port",
                                               "latitude", "longitude")}
    data["managed"] = bool(f.get("managed")) or data.get("connection") == "ansible"
    return {k: v for k, v in data.items() if v != ""} | {"managed": data["managed"]}


@bp.route("/assets/<int:asset_id>")
@login_required
def asset_detail(asset_id: int):
    asset = get_scoped_or_404(Asset, asset_id)
    exps = (Exposure.query.filter_by(tenant_id=asset.tenant_id, asset_id=asset.id)
            .order_by(Exposure.risk_score.desc()).limit(200).all())
    open_exps = [e for e in exps if e.status in ("open", "mitigated", "patching")]
    from ..models import AvailableUpdate
    update_count = asset.updates.filter(AvailableUpdate.status.notin_(("installed", "superseded"))).count()
    from ..engine import exposure_sim
    posture = {"misconfigurations": exposure_sim.misconfigurations(asset), "lateral": exposure_sim.lateral_paths(asset), "context": asset.hw.get("context") or {}}
    return render_template("assets/detail.html", posture=posture, update_count=update_count, asset=asset, exps=exps, risk_total=risk.asset_risk([e.risk_score for e in open_exps]),
                           software=asset.software.order_by(AssetSoftware.name).all(),
                           tasks=Task.query.filter_by(asset_id=asset.id).order_by(Task.id.desc()).limit(20).all(),
                           history=CmdbChange.query.filter_by(asset_id=asset.id).order_by(CmdbChange.id.desc()).limit(30).all(),
                           sims=Simulation.query.filter_by(asset_id=asset.id).order_by(Simulation.id.desc()).limit(10).all())


@bp.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required("admin", "user")
def asset_edit(asset_id: int):
    asset = get_scoped_or_404(Asset, asset_id)
    if request.method == "POST":
        data = _asset_form()
        data["uid"] = asset.uid
        inventory.upsert_asset(require_tenant(), data, source=asset.source)
        asset.managed = bool(request.form.get("managed")) or asset.managed
        asset.shadow_it = bool(request.form.get("shadow_it"))
        audit("asset_updated", asset.name)
        db.session.commit()
        flash("Ativo atualizado.", "success")
        return redirect(url_for("main.asset_detail", asset_id=asset.id))
    return render_template("assets/form.html", asset=asset, form={})


@bp.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def asset_delete(asset_id: int):
    asset = get_scoped_or_404(Asset, asset_id)
    for model in (Exposure, Task, Validation, Simulation, CmdbChange, ControlAction, Signal):
        model.query.filter_by(asset_id=asset.id).delete()
    if asset.agent is not None:
        asset.agent.asset_id = None
    audit("asset_deleted", asset.name)
    db.session.delete(asset)
    db.session.commit()
    flash("Ativo eliminado.", "info")
    return redirect(url_for("main.assets"))


@bp.route("/assets/<int:asset_id>/inventory", methods=["POST"])
@login_required
@roles_required("admin", "user")
def asset_inventory(asset_id: int):
    asset = get_scoped_or_404(Asset, asset_id)
    mode = "ansible" if (asset.connection == "ansible" and asset.agent is None) else "agent"
    db.session.add(Task(tenant_id=asset.tenant_id, type="inventory", asset_id=asset.id, mode=mode, status="queued",
                        payload="{}"))
    db.session.commit()
    flash("Inventário pedido.", "info")
    return redirect(url_for("main.asset_detail", asset_id=asset.id))


@bp.route("/assets/discover", methods=["POST"])
@login_required
@roles_required("admin")
def assets_discover():
    tenant = require_tenant()
    try:
        res = inventory.sweep(tenant, request.form.get("targets", ""), probe_ot=bool(request.form.get("probe_ot")))
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("main.assets"))
    audit("asset_discovery", json.dumps(res))
    db.session.commit()
    flash(f"Descoberta: {res['found']} ativos ({res['new']} novos, {res['shadow_it']} Shadow IT) em {res['scanned']} endereços.", "success")
    return redirect(url_for("main.assets", shadow=1 if res["shadow_it"] else None))


@bp.route("/assets/import", methods=["POST"])
@login_required
@roles_required("admin")
def assets_import():
    tenant = require_tenant()
    f = request.files.get("file")
    if not f:
        abort(400, description="Envie um ficheiro CSV")
    reader = csv.DictReader(io.StringIO(f.read().decode("utf-8-sig", errors="replace")))
    n = 0
    for row in reader:
        try:
            inventory.upsert_asset(tenant, {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}, source="import")
            n += 1
        except ValueError:
            continue
    audit("asset_import", f"{n} linhas")
    db.session.commit()
    flash(f"{n} ativos importados/atualizados.", "success")
    return redirect(url_for("main.assets"))


# --------------------------------------------------------------------------- exposições


def _exposures_query():
    q = scoped(Exposure).join(Asset, Asset.id == Exposure.asset_id)
    a = request.args
    st = a.get("status", "active")
    if st == "active":
        q = q.filter(Exposure.status.in_(("open", "mitigated", "patching", "remediated")))
    elif st != "all":
        q = q.filter(Exposure.status == st)
    if a.get("category"):
        q = q.filter(Exposure.risk_category.in_(a.getlist("category")))
    if a.get("asset_id", type=int):
        q = q.filter(Exposure.asset_id == a.get("asset_id", type=int))
    if a.get("cve"):
        q = q.filter(Exposure.cve_id.ilike(f"%{a['cve'].strip()}%"))
    if a.get("nopatch"):
        q = q.filter(Exposure.patch_available.is_(False))
    if a.get("kev"):
        q = q.join(CveIntel, CveIntel.cve_id == Exposure.cve_id).filter(CveIntel.kev.is_(True))
    if a.get("overdue"):
        q = q.filter(Exposure.due_date < utcnow(), Exposure.status.in_(("open", "mitigated", "patching")))
    if a.get("exploitability"):
        q = q.filter(Exposure.exploitability == a["exploitability"])
    if a.get("sort") == "loss":
        return q.order_by(Exposure.expected_loss.desc(), Exposure.risk_score.desc(), Exposure.id)
    return q.order_by(Exposure.risk_score.desc(), Exposure.id)


@bp.route("/exposures")
@login_required
def exposures():
    if (r := tenant_or_select()) is not None:
        return r
    pag = _exposures_query().paginate(page=request.args.get("page", 1, type=int), per_page=50, error_out=False)
    cves = {c.cve_id: c for c in CveIntel.query.filter(CveIntel.cve_id.in_({e.cve_id for e in pag.items} or {"-"}))}
    return render_template("exposures/list.html", pag=pag, cves=cves)


@bp.route("/exposures/<int:exposure_id>")
@login_required
def exposure_detail(exposure_id: int):
    ex = get_scoped_or_404(Exposure, exposure_id)
    cve = CveIntel.query.filter_by(cve_id=ex.cve_id).first()
    intelligence = patches.intelligence(ex.patch) if ex.patch else None
    from ..engine import priority
    loss = priority.score(ex, cve, ex.asset, [c for c in ControlAction.query.filter_by(tenant_id=ex.tenant_id, cve_id=ex.cve_id, asset_id=ex.asset_id)])
    return render_template("exposures/detail.html", ex=ex, cve=cve, intelligence=intelligence, loss=loss, loss_text=priority.money(ex.expected_loss),
                           ctrls=ControlAction.query.filter_by(tenant_id=ex.tenant_id, cve_id=ex.cve_id, asset_id=ex.asset_id).all(),
                           vals=Validation.query.filter_by(exposure_id=ex.id).order_by(Validation.id.desc()).all(),
                           sims=Simulation.query.filter_by(exposure_id=ex.id).order_by(Simulation.id.desc()).all(),
                           signals=Signal.query.filter(Signal.tenant_id == ex.tenant_id, db.or_(Signal.cve_id == ex.cve_id,
                                                       db.and_(Signal.cve_id == "", Signal.asset_id == ex.asset_id)))
                           .order_by(Signal.observed_at.desc()).limit(30).all())


@bp.route("/exposures/correlate", methods=["POST"])
@login_required
@roles_required("admin", "user")
def exposures_correlate():
    tenant = require_tenant()
    res = correlate.correlate_tenant(tenant)
    audit("correlation_run", f"{res['assets']} ativos, {res['new']} novas exposições")
    db.session.commit()
    flash(f"Correlação concluída: {res['assets']} ativos, {res['new']} novas exposições, {res['remediated']} remediadas.", "success")
    return redirect(request.referrer or url_for("main.exposures"))


@bp.route("/exposures/<int:exposure_id>/accept", methods=["POST"])
@login_required
@roles_required("admin")
def exposure_accept(exposure_id: int):
    ex = get_scoped_or_404(Exposure, exposure_id)
    reason = request.form.get("reason", "").strip()
    if len(reason) < 10:
        flash("Indique a justificação da aceitação do risco (mín. 10 caracteres).", "danger")
    else:
        ex.status = "accepted"
        audit("risk_accepted", f"{ex.cve_id} em {ex.asset.name}: {reason[:300]}")
        db.session.commit()
        flash("Risco aceite.", "info")
    return redirect(url_for("main.exposure_detail", exposure_id=ex.id))


@bp.route("/exposures/<int:exposure_id>/reopen", methods=["POST"])
@login_required
@roles_required("admin")
def exposure_reopen(exposure_id: int):
    ex = get_scoped_or_404(Exposure, exposure_id)
    ex.status, ex.closed_at = "open", None
    correlate.refresh(ex)
    audit("exposure_reopened", f"{ex.cve_id} em {ex.asset.name}")
    db.session.commit()
    return redirect(url_for("main.exposure_detail", exposure_id=ex.id))


@bp.route("/exposures/<int:exposure_id>/validate", methods=["POST"])
@login_required
@roles_required("admin", "user")
def exposure_validate(exposure_id: int):
    ex = get_scoped_or_404(Exposure, exposure_id)
    validation.schedule(ex, require_tenant())
    audit("validation_requested", f"{ex.cve_id} em {ex.asset.name}")
    db.session.commit()
    flash("Validação pedida ao ativo.", "info")
    return redirect(url_for("main.exposure_detail", exposure_id=ex.id))


@bp.route("/exposures/<int:exposure_id>/notify", methods=["POST"])
@login_required
@roles_required("admin", "user")
def exposure_notify(exposure_id: int):
    ex = get_scoped_or_404(Exposure, exposure_id)
    sync.notify_critical(require_tenant(), ex)
    db.session.commit()
    flash("Evento enviado ao SIEM/SOAR e pedido aberto no ITSM (se configurados).", "info")
    return redirect(url_for("main.exposure_detail", exposure_id=ex.id))


# --------------------------------------------------------------------------- inteligência


@bp.route("/intel")
@login_required
def intel_page():
    q = CveIntel.query
    a = request.args
    if a.get("q"):
        q = q.filter(CveIntel.cve_id.ilike(f"%{a['q'].strip()}%"))
    if a.get("kev"):
        q = q.filter(CveIntel.kev.is_(True))
    if a.get("ransomware"):
        q = q.filter(CveIntel.ransomware.is_(True))
    pag = q.order_by(CveIntel.kev.desc(), CveIntel.epss.desc().nullslast(), CveIntel.cvss.desc().nullslast()).paginate(
        page=a.get("page", 1, type=int), per_page=50, error_out=False)
    return render_template("intel/list.html", pag=pag, stats=intel.stats())


@bp.route("/intel/<cve_id>")
@login_required
def intel_detail(cve_id: str):
    cve = CveIntel.query.filter_by(cve_id=cve_id.upper()).first_or_404()
    tid = require_tenant().id if not (current_user.is_superadmin and not request.args.get("t")) else None
    exps = Exposure.query.filter_by(tenant_id=tid, cve_id=cve.cve_id).all() if tid else []
    return render_template("intel/detail.html", cve=cve, exps=exps)


@bp.route("/intel/sync", methods=["POST"])
@login_required
@roles_required("admin")
def intel_sync():
    res = intel.sync_all()
    audit("intel_sync", json.dumps(res, default=str)[:500])
    db.session.commit()
    flash("Sincronização de inteligência: " + ", ".join(f"{k}: {v}" for k, v in res.items()), "info")
    return redirect(url_for("main.intel_page"))


@bp.route("/intel/import", methods=["POST"])
@login_required
@roles_required("admin")
def intel_import():
    f = request.files.get("file")
    if not f:
        abort(400, description="Envie o ficheiro JSON")
    try:
        res = intel.import_file(f.read().decode("utf-8-sig"))
    except (ValueError, KeyError) as exc:
        flash(f"Ficheiro inválido: {exc}", "danger")
        return redirect(url_for("main.intel_page"))
    audit("intel_import", json.dumps(res))
    flash(f"Importados {res['count']} registos ({res['kind']}).", "success")
    return redirect(url_for("main.intel_page"))


@bp.route("/intel/<cve_id>/enrich", methods=["POST"])
@login_required
@roles_required("admin", "user")
def intel_enrich(cve_id: str):
    intel.enrich([cve_id.upper()])
    db.session.commit()
    return redirect(url_for("main.intel_detail", cve_id=cve_id))


# --------------------------------------------------------------------------- sinais multi-vendor


@bp.route("/signals")
@login_required
def signals_page():
    if (r := tenant_or_select()) is not None:
        return r
    q = scoped(Signal)
    if request.args.get("kind"):
        q = q.filter(Signal.kind == request.args["kind"])
    if request.args.get("source"):
        q = q.filter(Signal.source == request.args["source"])
    pag = q.order_by(Signal.observed_at.desc()).paginate(page=request.args.get("page", 1, type=int), per_page=50, error_out=False)
    sources = [s for (s,) in scoped(Signal).with_entities(Signal.source).distinct()]
    return render_template("signals/list.html", pag=pag, sources=sources)


@bp.route("/signals/import", methods=["POST"])
@login_required
@roles_required("admin", "user")
def signals_import():
    tenant = require_tenant()
    f = request.files.get("file")
    vendor = request.form.get("vendor", "generic").strip().lower()[:32] or "generic"
    if not f:
        abort(400, description="Envie o ficheiro (JSON ou CSV)")
    try:
        res = signals_mod.ingest(tenant, vendor, f.read().decode("utf-8-sig"), f.mimetype or "")
        sync.apply_signals(tenant)
    except (ValueError, KeyError) as exc:
        flash(f"Ficheiro inválido: {exc}", "danger")
        return redirect(url_for("main.signals_page"))
    audit("signals_import", json.dumps(res))
    db.session.commit()
    flash(f"{res['new']} novos sinais ({res['received']} recebidos; {res['unknown_assets']} com ativo desconhecido).", "success")
    return redirect(url_for("main.signals_page"))


__all__ = ["advisor", "controls", "simulation", "ASSET_KINDS", "CRITICALITIES", "OPEN_EXPOSURE", "Patch", "write_required"]


@bp.route("/assets/<int:asset_id>/isolate", methods=["POST"])
@login_required
@roles_required("admin", "user")
def asset_isolate(asset_id: int):
    """Propõe o isolamento preventivo do ativo (fica «proposto»: aprovar e aplicar no controlo; exige agente)."""
    asset = get_scoped_or_404(Asset, asset_id)
    if asset.agent is None:
        flash("O isolamento exige um agente instalado no ativo.", "danger")
        return redirect(url_for("main.asset_detail", asset_id=asset.id))
    keep = [x.strip() for x in request.form.get("keep_ssh_from", "").replace(";", ",").split(",") if x.strip()]
    try:
        c = controls.propose_isolation(require_tenant(), asset, request.form.get("ttl", type=int) or 120, keep, user=current_user)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("main.asset_detail", asset_id=asset.id))
    audit("asset_isolation_proposed", f"{asset.name}: controlo #{c.id}")
    db.session.commit()
    flash("Isolamento proposto: reveja, aprove e aplique no controlo. O agente mantém só a ligação à consola e liberta-se sozinho no prazo.", "info")
    return redirect(url_for("secops.control_detail", control_id=c.id))
