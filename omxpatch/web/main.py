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
    k = executive.kpis(tenant)
    return render_template("dashboard.html", k=k, tenant=tenant, max_cat=max(k["by_category"].values() or [1]) or 1)


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
    return render_template("assets/detail.html", asset=asset, exps=exps, risk_total=risk.asset_risk([e.risk_score for e in open_exps]),
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
    return render_template("exposures/detail.html", ex=ex, cve=cve, intelligence=intelligence,
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
