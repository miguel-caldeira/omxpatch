"""Fábrica da aplicação Flask (WSGI) do OMXPatch — mesma estrutura do OMXVuln."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_login import current_user
from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__, licensing
from .config import load_config
from .extensions import db, login_manager
from . import models as m
from .security import csrf_token, current_tenant, user_from_bearer, verify_csrf

log = logging.getLogger("omxpatch")


def resource_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) / "omxpatch" if base else Path(__file__).resolve().parent


class PrefixMiddleware:
    """Publica a app num subdiretório (ex.: https://site/omxpatch) atrás de NGINX/IIS."""

    def __init__(self, wsgi_app, prefix: str):
        self.wsgi_app, self.prefix = wsgi_app, prefix

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == self.prefix or path.startswith(self.prefix + "/"):
            environ["PATH_INFO"] = path[len(self.prefix):] or "/"
        if not environ.get("SCRIPT_NAME", "").endswith(self.prefix):
            environ["SCRIPT_NAME"] = environ.get("SCRIPT_NAME", "").rstrip("/") + self.prefix
        return self.wsgi_app(environ, start_response)


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    if type(dbapi_conn).__module__.startswith("sqlite3"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()


def _license_banner() -> dict | None:
    if not current_user.is_authenticated or current_user.is_superadmin or current_user.tenant is None:
        return None
    st = licensing.status(current_user.tenant)
    if st["state"] == "grace":
        return {"level": "danger", "text": licensing.grace_message(current_user.tenant)}
    if st["state"] == "expiring" and current_user.can_manage:
        n = st["days_left"]
        return {"level": "warning", "text": f"A licença desta organização expira {'hoje' if n == 0 else f'daqui a {n} dia(s)'} "
                                            f"({st['expires']:%d/%m/%Y})."}
    return None


def create_app(overrides: dict | None = None, start_worker: bool | None = None) -> Flask:
    res = resource_dir()
    app = Flask("omxpatch", template_folder=str(res / "templates"), static_folder=str(res / "static"))
    app.config.update(load_config(overrides))
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"check_same_thread": False, "timeout": 30}}
    logging.basicConfig(level=os.environ.get("OMXPATCH_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init_app(app)
    from . import siem
    siem.init_app(app)
    login_manager.init_app(app)

    n = int(app.config["TRUSTED_PROXIES"])
    if n > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n, x_port=n, x_prefix=n)
    if app.config["URL_PREFIX"]:
        app.wsgi_app = PrefixMiddleware(app.wsgi_app, app.config["URL_PREFIX"])

    from .web import admin, agent_api, api, auth, branding, main, patching, secops
    for bp in (auth.bp, main.bp, patching.bp, secops.bp, admin.bp, api.bp, agent_api.bp, branding.bp):
        app.register_blueprint(bp)

    @login_manager.user_loader
    def load_user(ident: str):
        try:
            uid, ver = ident.split(":")
            user = db.session.get(m.User, int(uid))
        except (ValueError, TypeError):
            return None
        if user is None or str(user.session_version) != ver:
            return None
        if not user.is_superadmin and user.enabled and licensing.is_suspended(user.tenant):
            g.license_suspended = licensing.suspended_message(user.tenant)
            return None
        return user

    @app.before_request
    def _before():
        g.api_user = None
        if request.blueprint == "agent":
            return None                      # autenticação própria (chave do agente), sem cookies nem CSRF
        if request.blueprint == "api":
            g.api_user = user_from_bearer()
            if g.api_user is not None:
                return None
        verify_csrf()
        if not current_user.is_authenticated and g.get("license_suspended") and request.endpoint not in ("static", "health"):
            session.clear()
            flash(g.license_suspended, "danger")
            if request.endpoint != "auth.login":
                return redirect(url_for("auth.login"))
        if not current_user.is_authenticated or request.endpoint in (None, "static", "health"):
            return None
        if request.blueprint == "auth":
            return None
        if session.get("mfa_pending"):
            return redirect(url_for("auth.mfa"))
        if current_user.must_change_password:
            return redirect(url_for("auth.change_password"))
        tenant = current_user.tenant
        if tenant is not None and tenant.require_mfa and not current_user.mfa_enabled:
            return redirect(url_for("auth.mfa_setup"))
        return None

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        fa = app.config["FRAME_ANCESTORS"].strip().lower()
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN" if fa in ("'self'", "self") else "DENY")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                f"frame-ancestors {app.config['FRAME_ANCESTORS']}; form-action 'self'; base-uri 'self'")
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if current_user.is_authenticated:
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.context_processor
    def _ctx():
        return {
            "csrf_token": csrf_token, "current_tenant": current_tenant() if current_user.is_authenticated else None,
            "ROLES": m.ROLES, "OS_FAMILIES": m.OS_FAMILIES, "ASSET_KINDS": m.ASSET_KINDS, "ASSET_SOURCES": m.ASSET_SOURCES,
            "CRITICALITIES": m.CRITICALITIES, "RISK_LABELS": m.RISK_LABELS, "RISK_CATEGORIES": m.RISK_CATEGORIES,
            "EXPOSURE_STATUSES": m.EXPOSURE_STATUSES, "PATCH_STATUSES": m.PATCH_STATUSES, "INSTALLER_TYPES": m.INSTALLER_TYPES,
            "CAMPAIGN_STATUSES": m.CAMPAIGN_STATUSES, "TASK_STATUSES": m.TASK_STATUSES, "TASK_TYPES": m.TASK_TYPES,
            "RINGS": m.RINGS, "CONTROL_ACTIONS": m.CONTROL_ACTIONS, "CONTROL_CATEGORIES": m.CONTROL_CATEGORIES,
            "CONTROL_STATUSES": m.CONTROL_STATUSES, "SIGNAL_KINDS": m.SIGNAL_KINDS, "SIMULATIONS": m.SIMULATIONS,
            "AUTONOMOUS_MODES": m.AUTONOMOUS_MODES, "AUTONOMOUS_STAGES": m.AUTONOMOUS_STAGES,
            "AUTONOMOUS_STAGE_LABELS": m.AUTONOMOUS_STAGE_LABELS, "EXPLOIT_MATURITY": m.EXPLOIT_MATURITY,
            "now": m.utcnow(), "version": __version__,
            "all_tenants": (m.Tenant.query.order_by(m.Tenant.name).all()
                            if current_user.is_authenticated and current_user.is_superadmin else []),
            "license_banner": _license_banner(),
        }

    @app.template_filter("dt")
    def _dt(value, fmt="%Y-%m-%d %H:%M"):
        return value.strftime(fmt) if value else "—"

    @app.template_filter("reject_page")
    def _reject_page(d):
        return {k: v for k, v in d.items() if k != "page"}

    @app.template_filter("tojson_pretty")
    def _pretty(v):
        import json
        return json.dumps(v, ensure_ascii=False, indent=2, default=str)

    @app.route("/healthz")
    def health():
        return {"status": "ok", "version": __version__}

    def _error(code, default):
        def handler(e):
            if request.blueprint in ("api", "agent") or request.accept_mimetypes.best == "application/json":
                return {"error": getattr(e, "description", default)}, code
            return render_template("error.html", code=code, message=getattr(e, "description", default)), code
        return handler

    for code, msg in ((400, "Pedido inválido"), (403, "Acesso negado"), (404, "Não encontrado"),
                      (409, "Conflito"), (413, "Ficheiro demasiado grande")):
        app.register_error_handler(code, _error(code, msg))

    with app.app_context():
        db.create_all()
        from .migrations import upgrade
        upgrade()

    if start_worker is None:
        start_worker = bool(app.config["EMBEDDED_WORKER"]) and not app.config.get("TESTING")
    if start_worker:
        from .worker import Worker
        app.extensions["omxpatch_worker"] = Worker(app)
        app.extensions["omxpatch_worker"].start()
    return app
