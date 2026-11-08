"""Operações em massa (por atualização ou por ativo) e boas práticas: simular → ver ações e resultados → OK → executar."""
from __future__ import annotations


from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..engine import deploy, plans as plans_mod, practices as pr
from ..extensions import db
from ..models import (Asset, Exposure, OperationPlan, Patch, PlanItem)
from ..security import audit, get_scoped_or_404, require_tenant, roles_required, scoped
from .common import parse_date, tenant_or_select

bp = Blueprint("plans", __name__)


def _ints(values) -> list[int]:
    return [int(v) for v in values if str(v).isdigit()]


@bp.route("/practices")
@login_required
def practices_page():
    if (r := tenant_or_select()) is not None:
        return r
    assets = scoped(Asset).order_by(Asset.name).all()
    rows = [(a, a.hw.get("webservers")) for a in assets if a.hw.get("webservers") is not None or a.agent is not None]
    return render_template("plans/practices.html", catalog=pr.PRACTICES, rows=rows)


@bp.route("/plans")
@login_required
def plans_list():
    if (r := tenant_or_select()) is not None:
        return r
    rows = scoped(OperationPlan).order_by(OperationPlan.id.desc()).limit(200).all()
    return render_template("plans/list.html", rows=rows, summaries={p.id: plans_mod.summary(p) for p in rows})


@bp.route("/plans/new", methods=["GET", "POST"])
@login_required
@roles_required("admin", "user")
def plan_new():
    tenant = require_tenant()
    if request.method == "POST":
        f = request.form
        asset_ids = _ints(f.getlist("asset_ids")) + _ints(f.get("asset_ids_text", "").replace(" ", "").split(","))
        specs = [{"id": pid, "params": {k: f.get(f"pp_{pid}_{k}", "") for k in pr.PRACTICES[pid]["params"]} | ({"server": f.get("server")} if f.get("server") else {})}
                 for pid in pr.PRACTICES if f.get(f"practice_{pid}")]
        try:
            plan = plans_mod.create(tenant, f.get("name", "").strip() or "Plano de operações", f.get("mode", "by_patch"), sorted(set(asset_ids)),
                                    _ints(f.getlist("patch_ids")), specs, current_user, f.get("reboot_policy", "if_needed"),
                                    bool(f.get("respect_windows")), parse_date(f.get("start_at", "")))
        except plans_mod.PlanError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("plans.plan_new", **{k: v for k, v in request.args.items()}))
        audit("plan_created", f"#{plan.id} {plan.name}: {plan.items.count()} item(ns)")
        db.session.commit()
        if f.get("simulate_now"):
            plans_mod.simulate(plan, tenant, current_user)
            audit("plan_simulate", f"#{plan.id}")
            db.session.commit()
        return redirect(url_for("plans.plan_detail", plan_id=plan.id))
    mode, pre_assets, pre_patches = "by_patch", set(), set()
    a = request.args
    if a.get("patch_id", type=int):
        p = get_scoped_or_404(Patch, a.get("patch_id", type=int))
        pre_patches = {p.id}
        pre_assets = {x.id for x in deploy.resolve_scope(tenant, {"cve_id": p.cve_list[0]} if p.cve_list else {}, p)} if p.cve_list else set()
    elif a.get("asset_id", type=int):
        asset = get_scoped_or_404(Asset, a.get("asset_id", type=int))
        mode, pre_assets = "by_asset", {asset.id}
        pre_patches = {e.patch_id for e in Exposure.query.filter_by(tenant_id=tenant.id, asset_id=asset.id).filter(
            Exposure.status.in_(("open", "mitigated"))) if e.patch_id}
    assets = scoped(Asset).order_by(Asset.name).limit(500).all()
    patches_ = scoped(Patch).filter(Patch.status.in_(("approved", "downloaded", "identified"))).order_by(Patch.id.desc()).limit(300).all()
    return render_template("plans/form.html", mode=mode, assets=assets, patches=patches_, pre_assets=pre_assets, pre_patches=pre_patches,
                           catalog=pr.PRACTICES, pre_practice=a.get("practice", ""), detected=pr.detected_servers)


@bp.route("/plans/<int:plan_id>")
@login_required
def plan_detail(plan_id: int):
    plan = get_scoped_or_404(OperationPlan, plan_id)
    by = request.args.get("by") or ("asset" if plan.mode == "by_asset" else "operation")
    items = plan.items.order_by(PlanItem.id).all()
    groups: dict = {}
    for it in items:
        key = (it.asset.name, it.asset_id) if by == "asset" else ((it.kind, it.patch_id or it.practice), it.label)
        groups.setdefault(key, []).append(it)
    ordered = [{"title": (k[0] if by == "asset" else k[1]), "items": v} for k, v in sorted(groups.items(), key=lambda kv: str(kv[0]))]
    eligible = {it.id: plans_mod.eligible(it) for it in items}
    return render_template("plans/detail.html", plan=plan, groups=ordered, by=by, summary=plans_mod.summary(plan), eligible=eligible,
                           catalog=pr.PRACTICES, n_items=len(items), itsm_on=__import__("omxpatch.engine.itsm", fromlist=["x"]).enabled(require_tenant()))


@bp.route("/plans/<int:plan_id>/<action>", methods=["POST"])
@login_required
@roles_required("admin", "user")
def plan_action(plan_id: int, action: str):
    plan = get_scoped_or_404(OperationPlan, plan_id)
    tenant = require_tenant()
    ids = _ints(request.form.getlist("item_ids"))
    back = redirect(url_for("plans.plan_detail", plan_id=plan.id, by=request.form.get("by") or None))
    if plan.status == "cancelled" and action != "noop":
        flash("O plano está cancelado.", "warning")
        return back
    if action == "simulate":
        n = plans_mod.simulate(plan, tenant, current_user, only=ids or None)
        audit("plan_simulate", f"#{plan.id}: {n} item(ns)")
        flash(f"Simulação pedida para {n} item(ns): os agentes respondem no próximo contacto; o resultado mostra ações e resultados previstos.", "info")
    elif action == "approve":
        if not request.form.get("confirm_ok"):
            flash("Confirme a caixa «OK» para aprovar a execução.", "danger")
            return back
        res = plans_mod.approve(plan, ids or None, current_user, accept_warnings=bool(request.form.get("accept_warnings")),
                                all_ok=bool(request.form.get("all_ok")))
        audit("plan_approved", f"#{plan.id}: {res['approved']} item(ns) por {current_user.email}")
        flash(f"OK registado em {res['approved']} item(ns).", "success" if res["approved"] else "warning")
        for it, why in res["refused"][:8]:
            flash(f"Não aprovado — {it.asset.name} / {it.label}: {why}.", "warning")
    elif action == "revoke":
        n = plans_mod.revoke(plan, ids)
        audit("plan_revoked", f"#{plan.id}: {n}")
    elif action == "execute":
        res = plans_mod.execute(plan, tenant, current_user)
        audit("plan_executed", f"#{plan.id}: {res['queued']} item(ns)")
        if res.get("blocked_by_itsm"):
            flash("Execução bloqueada pela governação ITSM: " + res["blocked_by_itsm"], "warning")
        else:
            flash(f"{res['queued']} item(ns) aprovados enviados para execução." if res["queued"] else "Nenhum item aprovado para executar.",
                  "success" if res["queued"] else "warning")
        for it, why in res["skipped"][:8]:
            flash(f"{it.asset.name} / {it.label}: {why}", "warning")
    elif action == "request_change":
        from ..engine import itsm
        try:
            res = itsm.request_change_for_plan(plan, tenant, current_user)
            audit("plan_change_requested", f"#{plan.id}: {res['ref']}")
            flash(f"Change {res['ref']} pedida no ITSM. A execução fica bloqueada até ser aprovada.", "success")
        except itsm.ChangeError as exc:
            flash(str(exc), "danger")
    elif action == "refresh_change":
        from ..engine import itsm
        state = itsm.refresh_plan(plan, tenant)
        flash(f"Change {plan.change_ref}: {plan.change_detail or state}", "info")
    elif action == "cancel":
        n = plans_mod.cancel(plan)
        audit("plan_cancelled", f"#{plan.id}: {n}")
    else:
        abort(400)
    db.session.commit()
    return back


@bp.route("/plans/items/<int:item_id>")
@login_required
def item_detail(item_id: int):
    it = get_scoped_or_404(PlanItem, item_id)
    return render_template("plans/item.html", it=it, catalog=pr.PRACTICES, ok=plans_mod.eligible(it))


@bp.route("/plans/items/<int:item_id>/revert", methods=["POST"])
@login_required
@roles_required("admin")
def item_revert(item_id: int):
    it = get_scoped_or_404(PlanItem, item_id)
    try:
        plans_mod.revert(it, require_tenant())
    except plans_mod.PlanError as exc:
        flash(str(exc), "danger")
    else:
        audit("practice_revert", f"item #{it.id} {it.label} em {it.asset.name}")
        db.session.commit()
        flash("Reversão pedida ao agente.", "info")
    return redirect(url_for("plans.item_detail", item_id=it.id))
