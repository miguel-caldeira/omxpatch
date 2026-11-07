from __future__ import annotations

from datetime import timedelta

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .. import licensing
from .. import mfa as mfa_mod
from ..extensions import db
from ..models import ApiToken, Tenant, User, utcnow
from ..security import audit, flash_errors, new_api_token, password_problems

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated and not session.get("mfa_pending"):
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter(db.func.lower(User.email) == email).first()
        now = utcnow()
        if user and user.locked_until and user.locked_until > now:
            flash("Conta temporariamente bloqueada por excesso de tentativas. Tente mais tarde.", "danger")
            return render_template("auth/login.html"), 429
        try:
            password_ok = user is not None and user.check_password(password)
        except RuntimeError as exc:
            flash(str(exc), "danger")
            return render_template("auth/login.html"), 500
        if password_ok and user.enabled and not user.is_superadmin and user.tenant is not None \
                and user.tenant.active and licensing.is_suspended(user.tenant):
            audit("login_license_suspended", email, tenant_id=user.tenant_id, user=user)
            db.session.commit()
            flash(licensing.suspended_message(user.tenant), "danger")
            return render_template("auth/login.html"), 403
        if user is None or not password_ok or not user.is_active:
            if user is not None:
                user.failed_logins += 1
                if user.failed_logins >= current_app.config["LOGIN_MAX_FAILURES"]:
                    user.locked_until = now + timedelta(minutes=current_app.config["LOGIN_LOCK_MINUTES"])
                    user.failed_logins = 0
                    audit("login_locked", email, tenant_id=user.tenant_id, user=user)
            audit("login_failed", email, tenant_id=user.tenant_id if user else None, user=user)
            db.session.commit()
            flash("Credenciais inválidas.", "danger")
            return render_template("auth/login.html"), 401
        user.failed_logins = 0
        user.locked_until = None
        session.clear()
        session.permanent = True
        login_user(user)
        if user.mfa_enabled:
            session["mfa_pending"] = True
            db.session.commit()
            return redirect(url_for("auth.mfa"))
        _complete_login(user)
        return redirect(url_for("main.dashboard"))
    return render_template("auth/login.html")


def _complete_login(user: User) -> None:
    session.pop("mfa_pending", None)
    user.last_login = utcnow()
    if user.is_superadmin and not session.get("tenant_id"):
        first = Tenant.query.filter_by(active=True).order_by(Tenant.name).first()
        session["tenant_id"] = first.id if first else None
    audit("login", user.email, tenant_id=user.tenant_id, user=user)
    _license_notice(user)
    db.session.commit()


def _license_notice(user: User) -> None:
    """Aviso (popup) no login durante o período de tolerância da licença; o super-administrador vê a lista
    das organizações em tolerância ou suspensas."""
    if user.is_superadmin:
        items = []
        for t in Tenant.query.filter_by(active=True).order_by(Tenant.name).all():
            st = licensing.status(t)
            if st["state"] == "grace":
                items.append(f"{t.name}: expirou a {st['expires']:%d/%m/%Y}, suspensa a partir de "
                             f"{st['grace_end'] + timedelta(days=1):%d/%m/%Y}")
            elif st["state"] == "suspended":
                items.append(f"{t.name}: suspensa desde {st['grace_end'] + timedelta(days=1):%d/%m/%Y}")
        if items:
            session["license_notice"] = {"title": "Licenças a renovar",
                                         "text": "Organizações com a licença expirada (renove em Organizações):",
                                         "items": items}
    elif user.tenant is not None and licensing.status(user.tenant)["state"] == "grace":
        session["license_notice"] = {"title": "Licença expirada — período de tolerância",
                                     "text": licensing.grace_message(user.tenant), "items": []}


@bp.route("/mfa", methods=["GET", "POST"])
@login_required
def mfa():
    if not session.get("mfa_pending"):
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        user = current_user._get_current_object()
        method = mfa_mod.verify_login(user, request.form.get("code", ""))
        if method:
            user.failed_logins = 0
            if method == "recovery":
                audit("mfa_recovery_used", f"{user.email} (restam {mfa_mod.recovery_left(user)})", tenant_id=user.tenant_id)
                flash(f"Entrou com um código de recuperação. Restam {mfa_mod.recovery_left(user)}.", "warning")
            _complete_login(user)
            return redirect(url_for("main.dashboard"))
        # o 2.º fator conta para o bloqueio da conta (proteção contra força bruta)
        user.failed_logins += 1
        audit("mfa_failed", user.email, tenant_id=user.tenant_id)
        if user.failed_logins >= current_app.config["LOGIN_MAX_FAILURES"]:
            user.locked_until = utcnow() + timedelta(minutes=current_app.config["LOGIN_LOCK_MINUTES"])
            user.failed_logins = 0
            audit("login_locked", user.email, tenant_id=user.tenant_id, user=user)
            db.session.commit()
            logout_user()
            session.clear()
            flash("Demasiados códigos inválidos: conta temporariamente bloqueada.", "danger")
            return redirect(url_for("auth.login"))
        db.session.commit()
        flash("Código inválido.", "danger")
    return render_template("auth/mfa.html")


@bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    if session.get("mfa_pending"):
        return redirect(url_for("auth.mfa"))
    p = mfa_mod.PROVIDERS["totp"]
    secret = session.get("mfa_setup_secret") or p.new_secret()
    session["mfa_setup_secret"] = secret
    if request.method == "POST":
        counter = p.match(secret, request.form.get("code", ""))
        if counter is not None:
            codes, hashed = mfa_mod.new_recovery_codes()
            current_user.mfa_secret = secret
            current_user.mfa_method = "totp"
            current_user.mfa_enabled = True
            current_user.mfa_last_counter = counter
            current_user.mfa_recovery_codes = hashed
            session.pop("mfa_setup_secret", None)
            session["recovery_codes"] = codes
            audit("mfa_enabled", current_user.email)
            db.session.commit()
            return redirect(url_for("auth.mfa_recovery"))
        flash("Código inválido — confirme a hora do dispositivo.", "danger")
    uri = p.uri(secret, current_user.email)
    return render_template("auth/mfa_setup.html", secret=secret, uri=uri, qr=mfa_mod.qr_image(uri), provider=p)


@bp.route("/mfa/recovery", methods=["GET", "POST"])
@login_required
def mfa_recovery():
    """Mostra uma única vez os códigos de recuperação; POST gera novos (exige código TOTP)."""
    if session.get("mfa_pending") or not current_user.mfa_enabled:
        return redirect(url_for("auth.profile"))
    if request.method == "POST":
        user = current_user._get_current_object()
        counter = mfa_mod.provider(user).match(user.mfa_secret, request.form.get("code", ""), user.mfa_last_counter)
        if counter is None:
            flash("Código inválido.", "danger")
            return redirect(url_for("auth.profile"))
        codes, hashed = mfa_mod.new_recovery_codes()
        user.mfa_last_counter, user.mfa_recovery_codes = counter, hashed
        session["recovery_codes"] = codes
        audit("mfa_recovery_regenerated", user.email)
        db.session.commit()
    codes = session.pop("recovery_codes", None)
    if not codes:
        return redirect(url_for("auth.profile"))
    return render_template("auth/mfa_recovery.html", codes=codes)


@bp.route("/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    if current_user.tenant and current_user.tenant.require_mfa:
        flash("A sua organização exige MFA.", "warning")
        return redirect(url_for("auth.profile"))
    if not current_user.check_password(request.form.get("password", "")):
        flash("Password incorreta.", "danger")
        return redirect(url_for("auth.profile"))
    current_user.mfa_enabled = False
    current_user.mfa_secret = ""
    current_user.mfa_recovery_codes = ""
    current_user.mfa_last_counter = None
    audit("mfa_disabled", current_user.email)
    db.session.commit()
    flash("MFA desativado.", "info")
    return redirect(url_for("auth.profile"))


@bp.route("/logout", methods=["POST"])
def logout():
    if current_user.is_authenticated:
        audit("logout", current_user.email)
        db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if session.get("mfa_pending"):
        return redirect(url_for("auth.mfa"))
    if request.method == "POST":
        if not current_user.check_password(request.form.get("current", "")):
            flash("Password atual incorreta.", "danger")
        elif request.form.get("new") != request.form.get("confirm"):
            flash("As passwords não coincidem.", "danger")
        elif problems := password_problems(request.form.get("new", "")):
            flash_errors(["Password fraca: " + "; ".join(problems)])
        else:
            current_user.set_password(request.form["new"])
            current_user.must_change_password = False
            current_user.session_version += 1
            audit("password_changed", current_user.email)
            db.session.commit()
            login_user(current_user._get_current_object())
            flash("Password alterada.", "success")
            return redirect(url_for("main.dashboard"))
    return render_template("auth/change_password.html")


@bp.route("/profile")
@login_required
def profile():
    if session.get("mfa_pending"):
        return redirect(url_for("auth.mfa"))
    tokens = ApiToken.query.filter_by(user_id=current_user.id).order_by(ApiToken.created_at.desc()).all()
    return render_template("auth/profile.html", tokens=tokens, new_token=session.pop("new_token", None),
                           recovery_left=mfa_mod.recovery_left(current_user))


@bp.route("/profile/tokens", methods=["POST"])
@login_required
def create_token():
    if session.get("mfa_pending") or current_user.role == "auditor" and not current_user.is_superadmin:
        abort(403)
    name = request.form.get("name", "").strip() or "token"
    days = request.form.get("days", type=int) or 90
    raw, digest, prefix = new_api_token()
    db.session.add(ApiToken(user_id=current_user.id, name=name[:120], token_hash=digest, prefix=prefix,
                            expires_at=utcnow() + timedelta(days=min(days, 365))))
    audit("api_token_created", name)
    db.session.commit()
    session["new_token"] = raw
    return redirect(url_for("auth.profile"))


@bp.route("/profile/tokens/<int:token_id>/delete", methods=["POST"])
@login_required
def delete_token(token_id: int):
    tok = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first_or_404()
    db.session.delete(tok)
    audit("api_token_revoked", tok.name)
    db.session.commit()
    return redirect(url_for("auth.profile"))


@bp.route("/tenant/select", methods=["POST"])
@login_required
def select_tenant():
    if not current_user.is_superadmin:
        abort(403)
    tid = request.form.get("tenant_id", type=int)
    if tid and db.session.get(Tenant, tid):
        session["tenant_id"] = tid
    return redirect(request.referrer if request.referrer and request.referrer.startswith(request.host_url) else url_for("main.dashboard"))
