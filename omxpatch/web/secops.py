"""Controlos compensatórios (M8), IA (M9), validação (M10), simulação (M14), remediação autónoma (M15), conformidade (M12)."""
from __future__ import annotations

import csv
import io
import json

from flask import Blueprint, Response, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..engine import advisor, autonomous, compliance, controls, executive, simulation
from ..extensions import db
from ..models import (CONTROL_ACTIONS, AiPlan, Asset, AutonomousRun, ControlAction, Exposure, Simulation,
                      Validation)
from ..security import audit, get_scoped_or_404, require_tenant, roles_required, scoped
from .common import tenant_or_select

bp = Blueprint("secops", __name__)


# --------------------------------------------------------------------------- Módulo 8


@bp.route("/controls")
@login_required
def controls_list():
    if (r := tenant_or_select()) is not None:
        return r
    q = scoped(ControlAction)
    if request.args.get("status"):
        q = q.filter(ControlAction.status == request.args["status"])
    if request.args.get("category"):
        q = q.filter(ControlAction.category == request.args["category"])
    pag = q.order_by(ControlAction.id.desc()).paginate(page=request.args.get("page", 1, type=int), per_page=50, error_out=False)
    return render_template("controls/list.html", pag=pag, summary=controls.summary(require_tenant().id))


@bp.route("/controls/<int:control_id>")
@login_required
def control_detail(control_id: int):
    return render_template("controls/detail.html", c=get_scoped_or_404(ControlAction, control_id))


@bp.route("/exposures/<int:exposure_id>/controls/propose", methods=["POST"])
@login_required
@roles_required("admin", "user")
def controls_propose(exposure_id: int):
    ex = get_scoped_or_404(Exposure, exposure_id)
    created = controls.propose_for(require_tenant(), ex)
    audit("controls_proposed", f"{ex.cve_id}: {len(created)}")
    db.session.commit()
    flash(f"{len(created)} controlo(s) compensatório(s) proposto(s)." if created else "Sem novas propostas para esta exposição.", "info")
    return redirect(url_for("main.exposure_detail", exposure_id=ex.id))


@bp.route("/exposures/<int:exposure_id>/controls/new", methods=["POST"])
@login_required
@roles_required("admin", "user")
def control_new(exposure_id: int):
    ex = get_scoped_or_404(Exposure, exposure_id)
    action = request.form.get("action", "")
    if action not in CONTROL_ACTIONS:
        abort(400)
    params = {k: request.form[k].strip() for k in ("port", "proto", "ioc", "country", "account", "process", "scope") if request.form.get(k, "").strip()}
    if "port" in params:
        try:
            params["port"] = int(params["port"])
        except ValueError:
            flash("Porta inválida.", "danger")
            return redirect(url_for("main.exposure_detail", exposure_id=ex.id))
    if action == "block_port" and "port" not in params:
        flash("Indique a porta a bloquear.", "danger")
        return redirect(url_for("main.exposure_detail", exposure_id=ex.id))
    c = controls.make(require_tenant(), ex, action, params, user=current_user)
    audit("control_created", f"{ex.cve_id} {action}")
    db.session.commit()
    return redirect(url_for("secops.control_detail", control_id=c.id))


@bp.route("/controls/<int:control_id>/<action>", methods=["POST"])
@login_required
@roles_required("admin")
def control_action(control_id: int, action: str):
    c = get_scoped_or_404(ControlAction, control_id)
    tenant = require_tenant()
    try:
        if action == "approve":
            controls.approve(c, current_user)
        elif action == "reject":
            controls.reject(c)
        elif action == "apply":
            controls.apply(c, tenant)
        elif action == "mark_applied":
            controls.mark_applied(c, verified=bool(request.form.get("verified")))
        elif action == "revert":
            c.status = "reverted"
        else:
            abort(400)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("secops.control_detail", control_id=c.id))
    audit(f"control_{action}", f"#{c.id} {c.cve_id} {c.action}")
    if c.exposure_id:
        from ..engine import correlate
        ex = db.session.get(Exposure, c.exposure_id)
        if ex:
            correlate.refresh(ex, tenant)
    db.session.commit()
    return redirect(url_for("secops.control_detail", control_id=c.id))


# --------------------------------------------------------------------------- Módulo 9


@bp.route("/advisor", methods=["GET", "POST"])
@login_required
def advisor_page():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    if request.method == "POST":
        if not current_user.can_write:
            abort(403)
        q = request.form.get("question", "").strip() or "Como reduzir o risco para menos de 20 pontos?"
        asset = get_scoped_or_404(Asset, int(request.form["asset_id"])) if request.form.get("asset_id") else None
        row = advisor.ask(tenant, q, asset, current_user, target=request.form.get("target", type=int))
        audit("ai_plan", f"#{row.id} {q[:200]}")
        db.session.commit()
        return redirect(url_for("secops.advisor_plan", plan_id=row.id))
    plans = scoped(AiPlan).order_by(AiPlan.id.desc()).limit(30).all()
    assets = scoped(Asset).order_by(Asset.name).limit(500).all()
    return render_template("advisor/index.html", plans=plans, assets=assets)


@bp.route("/advisor/<int:plan_id>")
@login_required
def advisor_plan(plan_id: int):
    return render_template("advisor/plan.html", p=get_scoped_or_404(AiPlan, plan_id))


@bp.route("/advisor/<int:plan_id>/apply", methods=["POST"])
@login_required
@roles_required("admin")
def advisor_apply(plan_id: int):
    row = get_scoped_or_404(AiPlan, plan_id)
    res = advisor.apply_plan(require_tenant(), row, current_user)
    audit("ai_plan_applied", f"#{row.id}: {json.dumps(res)[:300]}")
    db.session.commit()
    msg = f"Plano aplicado: {res['controls']} controlo(s) aprovado(s), {res['campaigns']} campanha(s)."
    if res["patches_to_approve"]:
        msg += " A aprovar no repositório: " + ", ".join(res["patches_to_approve"])
    flash(msg, "success")
    return redirect(url_for("secops.advisor_plan", plan_id=row.id))


# --------------------------------------------------------------------------- Módulo 10


@bp.route("/validations")
@login_required
def validations():
    if (r := tenant_or_select()) is not None:
        return r
    q = scoped(Validation)
    if request.args.get("status"):
        q = q.filter(Validation.status == request.args["status"])
    pag = q.order_by(Validation.id.desc()).paginate(page=request.args.get("page", 1, type=int), per_page=50, error_out=False)
    return render_template("validations/list.html", pag=pag)


# --------------------------------------------------------------------------- Módulo 14


@bp.route("/simulations")
@login_required
def simulations():
    if (r := tenant_or_select()) is not None:
        return r
    pag = scoped(Simulation).order_by(Simulation.id.desc()).paginate(page=request.args.get("page", 1, type=int), per_page=50, error_out=False)
    comps = {s.id: simulation.compare(s) for s in pag.items if s.baseline_id}
    assets = scoped(Asset).filter(Asset.managed.is_(True)).order_by(Asset.name).limit(500).all()
    return render_template("simulations/list.html", pag=pag, comps=comps, assets=assets, scenarios=simulation.SCENARIOS)


@bp.route("/simulations/new", methods=["POST"])
@login_required
@roles_required("admin", "user")
def simulation_new():
    tenant = require_tenant()
    asset = get_scoped_or_404(Asset, request.form.get("asset_id", type=int) or 0)
    ex = get_scoped_or_404(Exposure, request.form.get("exposure_id", type=int)) if request.form.get("exposure_id") else None
    scenario = request.form.get("scenario", "")
    phase = "after_fix" if request.form.get("after_fix") else "baseline"
    try:
        base = None
        if phase == "after_fix" and ex is not None:
            sim = simulation.validate_after_fix(tenant, ex, scenario)
        else:
            sim = simulation.start(tenant, asset, scenario, ex, phase=phase, baseline=base)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("secops.simulations"))
    audit("simulation_started", f"#{sim.id} {scenario} em {asset.name}")
    db.session.commit()
    flash("Simulação em fila: o agente executa-a no próximo contacto." if sim.status == "queued" else "A simulação exige agente instalado.", "info")
    return redirect(url_for("secops.simulations"))


# --------------------------------------------------------------------------- Módulo 15


@bp.route("/autonomous", methods=["GET", "POST"])
@login_required
def autonomous_page():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    if request.method == "POST":
        if not current_user.can_manage:
            abort(403)
        mode = request.form.get("mode", "off")
        if mode in ("off", "advise", "auto"):
            tenant.autonomous_mode = mode
        tenant.autonomous_min_score = max(0, min(100, request.form.get("min_score", type=int) or 50))
        tenant.autonomous_kev_only = bool(request.form.get("kev_only"))
        audit("autonomous_settings", f"modo={tenant.autonomous_mode} min={tenant.autonomous_min_score}")
        db.session.commit()
        flash("Definições do modo autónomo guardadas.", "success")
        return redirect(url_for("secops.autonomous_page"))
    runs = scoped(AutonomousRun).order_by(AutonomousRun.id.desc()).limit(100).all()
    return render_template("autonomous/index.html", runs=runs, tenant=tenant)


@bp.route("/autonomous/trigger", methods=["POST"])
@login_required
@roles_required("admin")
def autonomous_trigger():
    cve = request.form.get("cve", "").strip().upper()
    if not cve.startswith("CVE-"):
        flash("Indique um CVE válido.", "danger")
        return redirect(url_for("secops.autonomous_page"))
    run = autonomous.trigger(require_tenant(), cve, force=True)
    audit("autonomous_trigger", cve)
    db.session.commit()
    flash("Fluxo iniciado." if run else "Já existe um fluxo ativo para este CVE.", "info")
    return redirect(url_for("secops.autonomous_run", run_id=run.id) if run else url_for("secops.autonomous_page"))


@bp.route("/autonomous/<int:run_id>")
@login_required
def autonomous_run(run_id: int):
    run = get_scoped_or_404(AutonomousRun, run_id)
    return render_template("autonomous/run.html", run=run, stage_idx=autonomous.stage_index(run))


@bp.route("/autonomous/<int:run_id>/<action>", methods=["POST"])
@login_required
@roles_required("admin")
def autonomous_action(run_id: int, action: str):
    run = get_scoped_or_404(AutonomousRun, run_id)
    if action == "approve":
        autonomous.approve(run, current_user)
    elif action == "stop":
        autonomous.stop(run)
    elif action == "advance":
        autonomous.advance(run)
    else:
        abort(400)
    audit(f"autonomous_{action}", f"#{run.id} {run.cve_id}")
    db.session.commit()
    return redirect(url_for("secops.autonomous_run", run_id=run.id))


# --------------------------------------------------------------------------- Módulo 12 / 13


@bp.route("/compliance")
@login_required
def compliance_page():
    if (r := tenant_or_select()) is not None:
        return r
    return render_template("compliance/index.html", data=compliance.build(require_tenant()),
                           active=request.args.get("fw", ""))


@bp.route("/compliance/export.<fmt>")
@login_required
def compliance_export(fmt: str):
    data = compliance.build(require_tenant())
    if fmt == "json":
        return jsonify(data)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["referencial", "requisito", "descrição", "estado", "métrica", "detalhe"])
        for key, fw in data["frameworks"].items():
            for r in fw["requirements"]:
                w.writerow([fw["name"], r["id"], r["title"], r["status"], r["metric"], r["detail"]])
        return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=compliance.csv"})
    abort(404)


@bp.route("/executive.json")
@login_required
def executive_json():
    return jsonify(executive.kpis(require_tenant()))
