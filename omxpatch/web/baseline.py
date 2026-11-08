"""Linha de base (gold images): requisitos, desvio dos ativos e exportação para a pipeline de imagens."""
from __future__ import annotations

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..engine import baseline as bl
from ..extensions import db
from ..models import BaselineItem
from ..security import audit, get_scoped_or_404, require_tenant, roles_required
from .common import tenant_or_select

bp = Blueprint("baseline", __name__)


@bp.route("/baseline")
@login_required
def baseline_page():
    if (r := tenant_or_select()) is not None:
        return r
    tenant = require_tenant()
    scope = request.args.get("scope") or None
    its = bl.items(tenant, scope)
    return render_template("baseline/list.html", items=its, drift=bl.drift(tenant), scopes=sorted({b.scope for b in bl.items(tenant)}), scope=scope, formats=list(bl.EXPORTERS))


@bp.route("/baseline/export")
@login_required
def baseline_export():
    tenant = require_tenant()
    scope, fmt = request.args.get("scope", "linux"), request.args.get("format", "json")
    if fmt not in bl.EXPORTERS:
        abort(400)
    mime, ext, fn = bl.EXPORTERS[fmt]
    audit("baseline_export", f"{scope} {fmt}")
    db.session.commit()
    return Response(fn(tenant, scope), mimetype=mime + "; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="omxpatch-baseline-{scope.replace(":", "-")}.{ext}"'})


@bp.route("/baseline/add", methods=["POST"])
@login_required
@roles_required("admin", "user")
def baseline_add():
    tenant = require_tenant()
    f = request.form
    name, kind = f.get("name", "").strip()[:255], f.get("kind", "patch")
    scope = f.get("scope", "linux").strip()[:120]
    if not name or kind not in ("patch", "practice") or scope.split(":")[0] not in ("linux", "windows", "macos"):
        flash("Indique nome, tipo e âmbito (linux, windows ou macos[:etiqueta]).", "danger")
        return redirect(url_for("baseline.baseline_page"))
    row = BaselineItem.query.filter_by(tenant_id=tenant.id, scope=scope, kind=kind, name=name).first() or BaselineItem(tenant_id=tenant.id, scope=scope, kind=kind, name=name)
    row.min_version, row.installer, row.active, row.note = f.get("min_version", "").strip()[:120], f.get("installer", "").strip()[:16], True, "manual"
    db.session.add(row)
    audit("baseline_added", f"{scope}/{kind}/{name}")
    db.session.commit()
    return redirect(url_for("baseline.baseline_page"))


@bp.route("/baseline/<int:item_id>/remove", methods=["POST"])
@login_required
@roles_required("admin", "user")
def baseline_remove(item_id: int):
    row = get_scoped_or_404(BaselineItem, item_id)
    row.active = False
    audit("baseline_removed", f"{row.scope}/{row.kind}/{row.name}")
    db.session.commit()
    return redirect(url_for("baseline.baseline_page"))
