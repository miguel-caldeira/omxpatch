"""Repositório de patches (Módulos 5–6), campanhas e anéis (Módulo 7), janelas de manutenção."""
from __future__ import annotations

import json

from flask import Blueprint, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from ..engine import deploy, patches, rings
from ..extensions import db
from ..models import (RINGS, Asset, Campaign, CveIntel, Exposure, MaintenanceWindow, Patch, RingPolicy, Task, utcnow)
from ..security import audit, get_scoped_or_404, require_tenant, roles_required, scoped
from .common import parse_date, tenant_or_select

bp = Blueprint("patching", __name__)


@bp.route("/patches")
@login_required
def patches_list():
    if (r := tenant_or_select()) is not None:
        return r
    q = scoped(Patch)
    a = request.args
    if a.get("status"):
        q = q.filter(Patch.status == a["status"])
    if a.get("os_family"):
        q = q.filter(Patch.os_family == a["os_family"])
    if a.get("q"):
        like = f"%{a['q'].strip()}%"
        q = q.filter(db.or_(Patch.patch_uid.ilike(like), Patch.title.ilike(like), Patch.product.ilike(like), Patch.cves.ilike(like)))
    pag = q.order_by(Patch.created_at.desc()).paginate(page=a.get("page", 1, type=int), per_page=50, error_out=False)
    levels = {p.id: patches.intelligence(p)["level"] for p in pag.items}
    return render_template("patches/list.html", pag=pag, levels=levels)


@bp.route("/patches/new", methods=["GET", "POST"])
@login_required
@roles_required("admin", "user")
def patch_new():
    tenant = require_tenant()
    if request.method == "POST":
        f = request.form
        uid = f.get("patch_uid", "").strip()
        if not uid:
            flash("Indique o identificador do patch (ex.: KB5031234).", "danger")
            return render_template("patches/form.html", form=f), 400
        if Patch.query.filter_by(tenant_id=tenant.id, patch_uid=uid[:190]).first():
            flash("Já existe um patch com esse identificador.", "danger")
            return render_template("patches/form.html", form=f), 409
        cves = sorted({c.strip().upper() for c in f.get("cves", "").replace(";", ",").split(",") if c.strip()})
        p = Patch(tenant_id=tenant.id, patch_uid=uid[:190], title=f.get("title", "")[:500], vendor=f.get("vendor", "")[:200],
                  product=f.get("product", "")[:255], os_family=f.get("os_family", ""), installer=f.get("installer", "wua"),
                  package_name=f.get("package_name", "")[:255], version_fixed=f.get("version_fixed", "")[:120],
                  silent_args=f.get("silent_args", "")[:500], download_url=f.get("download_url", "")[:1000],
                  sha256=f.get("sha256", "").strip().lower()[:64], cves=json.dumps(cves), severity=f.get("severity", "medium"),
                  reboot_required=bool(f.get("reboot_required")), source="manual", bulletin_url=f.get("bulletin_url", "")[:1000],
                  impact=f.get("impact", "low"), released_at=parse_date(f.get("released_at", "")))
        db.session.add(p)
        audit("patch_created", uid)
        db.session.commit()
        return redirect(url_for("patching.patch_detail", patch_id=p.id))
    return render_template("patches/form.html", form={})


@bp.route("/patches/<int:patch_id>")
@login_required
def patch_detail(patch_id: int):
    p = get_scoped_or_404(Patch, patch_id)
    affected = (Exposure.query.filter_by(tenant_id=p.tenant_id, patch_id=p.id)
                .filter(Exposure.status.in_(("open", "mitigated", "patching", "remediated"))).count())
    camps = Campaign.query.filter_by(tenant_id=p.tenant_id, patch_id=p.id).order_by(Campaign.id.desc()).all()
    return render_template("patches/detail.html", p=p, intel=patches.intelligence(p), affected=affected, camps=camps)


@bp.route("/patches/identify", methods=["POST"])
@login_required
@roles_required("admin", "user")
def patches_identify():
    tenant = require_tenant()
    n = 0
    cve_ids = {e.cve_id for e in Exposure.query.filter_by(tenant_id=tenant.id).filter(Exposure.status.in_(("open", "mitigated", "patching")))}
    for cve in CveIntel.query.filter(CveIntel.cve_id.in_(cve_ids or {"-"})):
        n += len(patches.identify_for_cve(tenant.id, cve))
    for e in Exposure.query.filter_by(tenant_id=tenant.id).filter(Exposure.status.in_(("open", "mitigated"))):
        patches.link_exposure(e, CveIntel.query.filter_by(cve_id=e.cve_id).first())
    audit("patches_identified", str(n))
    db.session.commit()
    flash(f"Identificação concluída: {n} patch(es) no repositório.", "success")
    return redirect(url_for("patching.patches_list"))


@bp.route("/patches/<int:patch_id>/status", methods=["POST"])
@login_required
@roles_required("admin")
def patch_status(patch_id: int):
    p = get_scoped_or_404(Patch, patch_id)
    new = request.form.get("status")
    if new == "approved" and p.installer in ("msi", "exe", "pkg") and not p.local_file:
        flash("Este tipo de instalador exige o ficheiro no repositório (carregue-o ou descarregue-o) antes da aprovação.", "danger")
    elif new in ("approved", "rejected", "identified", "superseded"):
        p.status = new
        audit("patch_status", f"{p.patch_uid} → {new}")
        db.session.commit()
    return redirect(url_for("patching.patch_detail", patch_id=p.id))


@bp.route("/patches/<int:patch_id>/upload", methods=["POST"])
@login_required
@roles_required("admin", "user")
def patch_upload(patch_id: int):
    p = get_scoped_or_404(Patch, patch_id)
    f = request.files.get("file")
    if not f:
        abort(400, description="Envie o ficheiro do instalador")
    try:
        patches.store_file(p, require_tenant(), f.read(), f.filename or p.patch_uid)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("patching.patch_detail", patch_id=p.id))
    audit("patch_uploaded", f"{p.patch_uid} sha256={p.sha256[:16]}")
    db.session.commit()
    flash("Ficheiro guardado no repositório.", "success")
    return redirect(url_for("patching.patch_detail", patch_id=p.id))


@bp.route("/patches/<int:patch_id>/download", methods=["POST"])
@login_required
@roles_required("admin", "user")
def patch_download(patch_id: int):
    p = get_scoped_or_404(Patch, patch_id)
    try:
        patches.download(p, require_tenant())
        audit("patch_downloaded", p.patch_uid)
        db.session.commit()
        flash("Instalador descarregado e verificado (SHA-256).", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"Transferência falhou: {exc}", "danger")
    return redirect(url_for("patching.patch_detail", patch_id=p.id))


@bp.route("/patches/<int:patch_id>/file")
@login_required
def patch_file(patch_id: int):
    p = get_scoped_or_404(Patch, patch_id)
    path = patches.local_path(p, require_tenant())
    if path is None:
        abort(404)
    return send_file(path, as_attachment=True, download_name=path.name)


@bp.route("/patches/<int:patch_id>/community", methods=["POST"])
@login_required
@roles_required("admin")
def patch_community(patch_id: int):
    p = get_scoped_or_404(Patch, patch_id)
    f = request.form
    try:
        p.community_success_rate = float(f["success_rate"]) if f.get("success_rate") else None
        p.community_reports = int(f.get("reports") or 0)
        p.reported_problems = int(f.get("problems") or 0)
    except ValueError:
        flash("Valores numéricos inválidos.", "danger")
        return redirect(url_for("patching.patch_detail", patch_id=p.id))
    p.impact = f.get("impact") if f.get("impact") in ("low", "medium", "high") else p.impact
    issues = [{"title": line.split("|")[0].strip(), "severity": (line.split("|") + ["medium"])[1].strip().lower()}
              for line in f.get("issues", "").splitlines() if line.strip()]
    p.vendor_known_issues = json.dumps(issues)
    audit("patch_intel_updated", p.patch_uid)
    db.session.commit()
    return redirect(url_for("patching.patch_detail", patch_id=p.id))


# --------------------------------------------------------------------------- campanhas


@bp.route("/campaigns")
@login_required
def campaigns():
    if (r := tenant_or_select()) is not None:
        return r
    rows = scoped(Campaign).order_by(Campaign.id.desc()).limit(200).all()
    return render_template("campaigns/list.html", rows=rows, summaries={c.id: deploy.campaign_summary(c) for c in rows})


@bp.route("/campaigns/new", methods=["GET", "POST"])
@login_required
@roles_required("admin", "user")
def campaign_new():
    tenant = require_tenant()
    patch = get_scoped_or_404(Patch, request.values.get("patch_id", type=int) or 0)
    if request.method == "POST":
        f = request.form
        scope: dict = {}
        if f.get("cve_id"):
            scope["cve_id"] = f["cve_id"].strip().upper()
        if f.get("tags"):
            scope["tags"] = [t.strip() for t in f["tags"].split(",") if t.strip()]
        if f.get("os_family"):
            scope["os_family"] = f["os_family"]
        if f.get("asset_ids"):
            scope["asset_ids"] = [int(i) for i in f["asset_ids"].replace(" ", "").split(",") if i.isdigit()]
        try:
            c = deploy.create_campaign(
                tenant, patch, f.get("name") or f"{patch.patch_uid}", scope, _user(),
                use_rings=bool(f.get("use_rings")), start_at=parse_date(f.get("start_at", "")), use_wol=bool(f.get("use_wol")),
                bandwidth_kbps=int(f.get("bandwidth_kbps") or 0), reboot_policy=f.get("reboot_policy", "if_needed"),
                emergency=bool(f.get("emergency")), force=bool(f.get("force")), auto_promote=bool(f.get("auto_promote")),
                respect_windows=bool(f.get("respect_windows")))
        except deploy.PatchBlocked as exc:
            flash(str(exc), "danger")
            return render_template("campaigns/form.html", patch=patch, form=f, intel=patches.intelligence(patch)), 400
        audit("campaign_created", f"#{c.id} {patch.patch_uid}")
        db.session.commit()
        return redirect(url_for("patching.campaign_detail", campaign_id=c.id))
    form = {"use_rings": "1", "auto_promote": "1", "respect_windows": "1", "reboot_policy": "if_needed",
            "cve_id": (patch.cve_list or [""])[0]}
    return render_template("campaigns/form.html", patch=patch, form=form, intel=patches.intelligence(patch))


def _user():
    from flask_login import current_user
    return current_user._get_current_object()


@bp.route("/campaigns/<int:campaign_id>")
@login_required
def campaign_detail(campaign_id: int):
    c = get_scoped_or_404(Campaign, campaign_id)
    tenant = require_tenant()
    tasks = Task.query.filter_by(campaign_id=c.id, type="patch").order_by(Task.ring, Task.id).all()
    ring_info = []
    for r in sorted({t.ring for t in tasks} | {int(k) for k in c.rings_state}):
        ring_info.append({"ring": r, "state": c.rings_state.get(str(r), {}), "metrics": rings.metrics(c, r), "policy": rings.policy(tenant, r)})
    return render_template("campaigns/detail.html", c=c, tasks=tasks, ring_info=ring_info, summary=deploy.campaign_summary(c),
                           intel=patches.intelligence(c.patch))


@bp.route("/campaigns/<int:campaign_id>/<action>", methods=["POST"])
@login_required
@roles_required("admin", "user")
def campaign_action(campaign_id: int, action: str):
    c = get_scoped_or_404(Campaign, campaign_id)
    tenant = require_tenant()
    if action == "start" and c.status in ("draft", "scheduled"):
        c.status, c.start_at = "scheduled", utcnow()
        deploy.advance(c, tenant)
    elif action == "pause" and c.status in ("running", "scheduled"):
        c.status = "paused"
    elif action == "resume" and c.status == "paused":
        deploy.resume(c, tenant)
    elif action == "promote" and c.status == "paused":
        if not request.form.get("confirm"):
            flash("Confirme a promoção manual (decisão registada).", "danger")
            return redirect(url_for("patching.campaign_detail", campaign_id=c.id))
        deploy.resume(c, tenant, override=True)
    elif action == "cancel" and c.status not in ("completed", "cancelled"):
        deploy.cancel(c)
    else:
        abort(400)
    audit(f"campaign_{action}", f"#{c.id} {c.name}")
    db.session.commit()
    return redirect(url_for("patching.campaign_detail", campaign_id=c.id))


@bp.route("/tasks/<int:task_id>")
@login_required
def task_detail(task_id: int):
    t = get_scoped_or_404(Task, task_id)
    return render_template("campaigns/task.html", t=t)


@bp.route("/tasks/<int:task_id>/retry", methods=["POST"])
@login_required
@roles_required("admin", "user")
def task_retry(task_id: int):
    t = get_scoped_or_404(Task, task_id)
    if t.status in ("failed", "cancelled", "rolled_back", "skipped"):
        t.status, t.attempts, t.finished_at = "pending", 0, None
        db.session.commit()
    return redirect(request.referrer or url_for("patching.campaign_detail", campaign_id=t.campaign_id or 0))


# --------------------------------------------------------------------------- janelas de manutenção e anéis


@bp.route("/windows", methods=["GET", "POST"])
@login_required
@roles_required("admin", "user", "auditor")
def windows():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    if request.method == "POST":
        if not _user().can_manage:
            abort(403)
        f = request.form
        days = ",".join(d for d in f.getlist("weekdays") if d.isdigit())
        w = MaintenanceWindow(tenant_id=tenant.id, name=f.get("name", "Janela")[:120], weekdays=days or "0,1,2,3,4,5,6",
                              start_time=f.get("start_time", "22:00")[:5], duration_minutes=int(f.get("duration") or 240),
                              timezone=f.get("timezone", "")[:64], rings=",".join(r for r in f.getlist("rings") if r.isdigit()),
                              group=f.get("group", "")[:120], allow_emergency=bool(f.get("allow_emergency")))
        db.session.add(w)
        audit("window_created", w.name)
        db.session.commit()
        return redirect(url_for("patching.windows"))
    return render_template("patching/windows.html", rows=scoped(MaintenanceWindow).order_by(MaintenanceWindow.name).all())


@bp.route("/windows/<int:window_id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def window_delete(window_id: int):
    w = get_scoped_or_404(MaintenanceWindow, window_id)
    db.session.delete(w)
    audit("window_deleted", w.name)
    db.session.commit()
    return redirect(url_for("patching.windows"))


@bp.route("/rings", methods=["GET", "POST"])
@login_required
def rings_page():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    pols = rings.ensure_policies(tenant)
    if request.method == "POST":
        if not _user().can_manage:
            abort(403)
        f = request.form
        for p in pols:
            try:
                p.min_success = float(f.get(f"min_success_{p.ring}", p.min_success))
                p.max_crash = float(f.get(f"max_crash_{p.ring}", p.max_crash))
                p.min_ux = float(f.get(f"min_ux_{p.ring}", p.min_ux))
                p.min_devices = int(f.get(f"min_devices_{p.ring}", p.min_devices))
                p.soak_hours = int(f.get(f"soak_hours_{p.ring}", p.soak_hours))
            except ValueError:
                flash("Valores inválidos.", "danger")
                return redirect(url_for("patching.rings_page"))
            p.auto_promote = bool(f.get(f"auto_{p.ring}"))
        audit("ring_policies_updated", "")
        db.session.commit()
        flash("Critérios de promoção guardados.", "success")
        return redirect(url_for("patching.rings_page"))
    counts = {r: scoped(Asset).filter(Asset.ring == r).count() for r in RINGS}
    return render_template("patching/rings.html", pols=pols, counts=counts)


@bp.route("/rings/assign", methods=["POST"])
@login_required
@roles_required("admin")
def rings_assign():
    n = rings.assign_rings(require_tenant(), only_default=not request.form.get("all"))
    audit("rings_assigned", str(n))
    db.session.commit()
    flash(f"{n} ativos atribuídos a anéis (por etiqueta, departamento e tipo).", "success")
    return redirect(url_for("patching.rings_page"))


@bp.route("/assets/<int:asset_id>/ring", methods=["POST"])
@login_required
@roles_required("admin", "user")
def asset_ring(asset_id: int):
    a = get_scoped_or_404(Asset, asset_id)
    ring = request.form.get("ring", type=int)
    if ring in RINGS:
        a.ring = ring
        audit("asset_ring", f"{a.name} → {ring}")
        db.session.commit()
    return redirect(url_for("main.asset_detail", asset_id=a.id))
