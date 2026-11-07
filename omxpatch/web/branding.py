"""Identidade visual da organização: tema (CSS), logótipo e configuração."""
from __future__ import annotations

from flask import Blueprint, Response, abort, current_app, flash, redirect, request, send_file, url_for
from flask_login import current_user, login_required

from .. import branding
from ..extensions import db
from ..models import Tenant
from ..security import admin_required, audit, current_tenant, require_tenant

bp = Blueprint("branding", __name__)


@bp.route("/branding/theme.css")
def theme():
    tenant = current_tenant() if current_user.is_authenticated else None
    resp = Response(branding.theme_css(tenant), mimetype="text/css")
    resp.headers["Cache-Control"] = "private, max-age=86400"   # o URL muda com brand_version
    return resp


@bp.route("/branding/logo/<int:tenant_id>")
@login_required
def logo(tenant_id: int):
    if not current_user.is_superadmin and current_user.tenant_id != tenant_id:
        abort(404)
    tenant = db.session.get(Tenant, tenant_id)
    path = branding.logo_path(current_app.config, tenant) if tenant else None
    if path is None:
        abort(404)
    resp = send_file(path, mimetype=branding.mimetype(path.name), max_age=86400)
    resp.headers["Cache-Control"] = "private, max-age=86400"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return resp


@bp.route("/branding/settings", methods=["POST"])
@login_required
@admin_required
def settings():
    tenant = require_tenant()
    f = request.form
    if f.get("action") == "reset":
        branding.remove_logo(current_app.config, tenant)
        tenant.brand_header = tenant.brand_primary = tenant.brand_accent = ""
        tenant.brand_version = (tenant.brand_version or 0) + 1
        audit("branding_reset", tenant.slug)
        db.session.commit()
        flash("Identidade visual reposta para o tema por omissão.", "success")
        return redirect(url_for("admin.tenant_settings") + "#identidade")
    for field in ("brand_header", "brand_primary", "brand_accent"):
        value = (f.get(field) or "").strip().lower()
        if value and not branding.valid_hex(value):
            flash("Cor inválida: use o formato #rrggbb.", "danger")
            return redirect(url_for("admin.tenant_settings") + "#identidade")
        setattr(tenant, field, "" if value == branding.DEFAULTS[field] else value)
    if f.get("remove_logo") == "1":
        branding.remove_logo(current_app.config, tenant)
    file = request.files.get("logo")
    if file and file.filename:
        try:
            branding.save_logo(current_app.config, tenant, file.read(branding.MAX_LOGO_BYTES + 1))
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("admin.tenant_settings") + "#identidade")
    tenant.brand_version = (tenant.brand_version or 0) + 1
    p = branding.palette(tenant)
    notes = []
    if p["adjusted"]["primary"]:
        notes.append(f"cor principal escurecida para {p['primary']} (contraste mínimo 4,5:1 no texto)")
    if p["adjusted"]["accent"]:
        notes.append(f"cor de destaque ajustada para {p['accent']} (contraste mínimo 3:1)")
    audit("branding_updated", f"{tenant.slug}: barra={tenant.brand_header or 'omissão'} principal="
          f"{tenant.brand_primary or 'omissão'} destaque={tenant.brand_accent or 'omissão'} logótipo="
          f"{'sim' if tenant.logo_file else 'não'}")
    db.session.commit()
    flash("Identidade visual guardada." + (" Ajustes automáticos de legibilidade: " + "; ".join(notes) + "."
                                           if notes else ""), "success")
    return redirect(url_for("admin.tenant_settings") + "#identidade")
