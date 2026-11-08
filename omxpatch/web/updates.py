"""Atualizações descobertas nos ativos: lista, descoberta a pedido, descarga para o servidor, simulação e remediação."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..engine import plans as plans_mod, updates as updates_mod
from ..extensions import db
from ..models import UPDATE_STATUSES, Asset, AvailableUpdate, UpdateScan
from ..security import audit, get_scoped_or_404, require_tenant, roles_required, scoped
from .common import tenant_or_select

bp = Blueprint("updates", __name__)
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _query():
    q = scoped(AvailableUpdate).filter(AvailableUpdate.status.notin_(("installed", "superseded")))
    a = request.args
    if a.get("asset_id", type=int):
        q = q.filter(AvailableUpdate.asset_id == a.get("asset_id", type=int))
    for k in ("source", "status", "severity", "category"):
        if a.get(k):
            q = q.filter(getattr(AvailableUpdate, k) == a[k])
    if a.get("q"):
        like = f"%{a['q'][:60]}%"
        q = q.filter(db.or_(AvailableUpdate.name.ilike(like), AvailableUpdate.title.ilike(like), AvailableUpdate.kb.ilike(like)))
    return q


@bp.route("/updates")
@login_required
def updates_list():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    page = max(1, request.args.get("page", 1, type=int))
    rows = _query().order_by(AvailableUpdate.severity.desc(), AvailableUpdate.id.desc()).offset((page - 1) * 100).limit(100).all()
    rows.sort(key=lambda u: (SEV_ORDER.get(u.severity, 9), u.asset.name if u.asset else ""))
    scans = scoped(UpdateScan).order_by(UpdateScan.id.desc()).limit(8).all()
    return render_template("updates/list.html", rows=rows, summary=updates_mod.summary(tenant), scans=scans, statuses=UPDATE_STATUSES, page=page,
                           assets=scoped(Asset).order_by(Asset.name).limit(500).all(), sources=sorted({s for (s,) in db.session.query(AvailableUpdate.source).filter(
                               AvailableUpdate.tenant_id == tenant.id).distinct()}))


@bp.route("/updates/scans")
@login_required
def scans_list():
    return render_template("updates/scans.html", scans=scoped(UpdateScan).order_by(UpdateScan.id.desc()).limit(200).all())


@bp.route("/updates/scan", methods=["POST"])
@login_required
@roles_required("admin", "user")
def scan_now():
    """«Descobrir agora»: pede a todos os agentes (ou a um ativo) que descubram e enviem as atualizações."""
    tenant = require_tenant()
    ids = [request.form.get("asset_id", type=int)] if request.form.get("asset_id", type=int) else None
    n = updates_mod.request_scan(tenant, ids)
    audit("updates_scan_requested", f"{n} agente(s)")
    db.session.commit()
    flash(f"Descoberta pedida a {n} agente(s): o resultado chega no próximo contacto e fica registado em «Histórico de descobertas».", "info" if n else "warning")
    return redirect(request.referrer or url_for("updates.updates_list"))


@bp.route("/updates/download", methods=["POST"])
@login_required
@roles_required("admin", "user")
def download_now():
    """«Descarregar agora»: não espera pelo worker; descarrega já alguns patches pendentes para o repositório do servidor."""
    tenant = require_tenant()
    res = updates_mod.download_pending(tenant, limit=5)
    audit("updates_download", f"{res}")
    db.session.commit()
    flash(f"Transferência: {res['downloaded']} descarregado(s), {res['failed']} falhado(s), {res['skipped']} sem transferência possível.", "success" if res["downloaded"] else "info")
    return redirect(url_for("updates.updates_list"))


@bp.route("/updates/approve", methods=["POST"])
@login_required
@roles_required("admin", "user")
def approve_patches():
    """Aprova no repositório os patches das atualizações selecionadas (só os que têm ficheiro no servidor ou usam o gestor do SO)."""
    require_tenant()
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    done = 0
    for au in scoped(AvailableUpdate).filter(AvailableUpdate.id.in_(ids or [0])):
        p = au.patch
        if p is None or p.status in ("approved", "rejected"):
            continue
        if p.installer in ("msi", "exe", "pkg") and not p.local_file:
            continue
        p.status = "approved"
        done += 1
    audit("updates_patches_approved", f"{done} patch(es) por {current_user.email}")
    db.session.commit()
    flash(f"{done} patch(es) aprovado(s) no repositório.", "success" if done else "warning")
    return redirect(request.referrer or url_for("updates.updates_list"))


@bp.route("/updates/plan", methods=["POST"])
@login_required
@roles_required("admin", "user")
def make_plan():
    """Cria um plano de operações com as atualizações selecionadas (ativo × patch exatos) e pede a simulação. Nada é aplicado sem OK."""
    tenant = require_tenant()
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    rows = scoped(AvailableUpdate).filter(AvailableUpdate.id.in_(ids or [0]), AvailableUpdate.patch_id.isnot(None),
                                         AvailableUpdate.status.notin_(("installed", "superseded"))).all()
    pairs = sorted({(u.asset_id, u.patch_id) for u in rows})
    if not pairs:
        flash("Selecione atualizações pendentes.", "warning")
        return redirect(url_for("updates.updates_list"))
    try:
        plan = plans_mod.create(tenant, f"Atualizações ({len(pairs)})", "by_asset", [], [], [], current_user, pairs=pairs)
    except plans_mod.PlanError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("updates.updates_list"))
    n = plans_mod.simulate(plan, tenant, current_user)
    audit("updates_plan", f"plano #{plan.id}: {len(pairs)} par(es) ativo×patch, {n} simulação(ões)")
    db.session.commit()
    flash(f"Plano #{plan.id} criado e simulação pedida a {n} item(ns). Nada será aplicado sem o seu OK.", "info")
    return redirect(url_for("plans.plan_detail", plan_id=plan.id))


@bp.route("/updates/<int:update_id>")
@login_required
def update_detail(update_id: int):
    au = get_scoped_or_404(AvailableUpdate, update_id)
    same = scoped(AvailableUpdate).filter(AvailableUpdate.patch_id == au.patch_id, AvailableUpdate.status.notin_(("installed", "superseded"))).all() if au.patch_id else [au]
    return render_template("updates/detail.html", u=au, same=same, statuses=UPDATE_STATUSES)
