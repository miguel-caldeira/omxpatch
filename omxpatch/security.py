"""Controlo de acessos, isolamento multitenant, CSRF, MFA (TOTP) e auditoria."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from functools import wraps
from urllib.parse import quote

from flask import abort, current_app, flash, g, redirect, request, session, url_for
from flask_login import current_user

from .extensions import db
from .models import ApiToken, AuditLog, Tenant, utcnow

# --------------------------------------------------------------------------- CSRF


def csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


# --------------------------------------------------------------------------- SSRF (ligações de saída)


class OutboundURLError(ValueError):
    pass


def check_outbound_url(url: str, *, require_https: bool = False) -> str:
    """Valida um URL configurado por um administrador (webhook, API de um motor) antes de o contactar.

    Impede SSRF para serviços locais e para o endpoint de metadados da cloud: resolve o nome e recusa se
    algum endereço for de loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16 — inclui 169.254.169.254
    da AWS/GCP/Azure — e fe80::/10) ou não especificado. As redes privadas (LAN) continuam permitidas, para
    o SIEM/SOAR interno; ``[security] allow_loopback_outbound = true`` permite também o loopback (coletor no
    mesmo servidor). Devolve o URL validado ou lança ``OutboundURLError``."""
    import ipaddress
    import socket
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    schemes = ("https",) if require_https else ("http", "https")
    if parts.scheme not in schemes or not parts.hostname:
        raise OutboundURLError(f"O endereço tem de ser um URL {' ou '.join(s + '://' for s in schemes)}")
    allow_loopback = bool(current_app.config.get("ALLOW_LOOPBACK_OUTBOUND")) if current_app else False

    def blocked(ip) -> bool:
        return (ip.is_link_local or ip.is_unspecified or ip.is_reserved or ip.is_multicast
                or (ip.is_loopback and not allow_loopback))

    # IP literal no URL: bloqueado sem depender de DNS (ex.: 127.0.0.1, 169.254.169.254, ::1)
    try:
        literal = ipaddress.ip_address(parts.hostname.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None and blocked(literal):
        raise OutboundURLError(f"O endereço {literal} é um destino interno não permitido (loopback, link-local "
                               "ou metadados da cloud). Use um endereço acessível na rede.")
    # Nome: se resolver para um destino interno, bloqueia; se a resolução falhar, não bloqueia a gravação
    # (o pedido real falharia na mesma e o nome pode resolver só a partir da rede do scanner).
    if literal is None:
        try:
            infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80),
                                       proto=socket.IPPROTO_TCP)
        except OSError:
            infos = []
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if blocked(ip):
                raise OutboundURLError(
                    f"O endereço {parts.hostname} resolve para {ip}, um destino interno não permitido "
                    "(loopback, link-local ou metadados da cloud). Use um endereço acessível na rede.")
    return url


def verify_csrf() -> None:
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if getattr(g, "api_user", None) is not None:
        return  # API com token Bearer não usa cookies
    sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="Token CSRF inválido ou expirado. Recarregue a página.")


# --------------------------------------------------------------------------- Tenancy


def current_tenant_id() -> int | None:
    user = getattr(g, "api_user", None) or current_user
    if not getattr(user, "is_authenticated", False):
        return None
    if user.is_superadmin:
        tid = session.get("tenant_id") if getattr(g, "api_user", None) is None else request.headers.get("X-Tenant-ID", type=int)
        return tid
    return user.tenant_id


def current_tenant() -> Tenant | None:
    tid = current_tenant_id()
    return db.session.get(Tenant, tid) if tid else None


def require_tenant() -> Tenant:
    t = current_tenant()
    if t is None:
        abort(409, description="Selecione uma organização (tenant) para continuar.")
    return t


def scoped(model):
    """Query filtrada pelo tenant ativo — usar SEMPRE em entidades de negócio."""
    tid = current_tenant_id()
    if tid is None:
        abort(409, description="Selecione uma organização (tenant) para continuar.")
    return model.query.filter(model.tenant_id == tid)


def get_scoped_or_404(model, obj_id: int):
    obj = scoped(model).filter(model.id == obj_id).first()
    if obj is None:
        abort(404)
    return obj


# --------------------------------------------------------------------------- Roles


def _actor():
    return getattr(g, "api_user", None) or current_user


def roles_required(*roles: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = _actor()
            if not getattr(user, "is_authenticated", False):
                return current_app.login_manager.unauthorized()
            if not user.has_role(*roles):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def superadmin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = _actor()
        if not getattr(user, "is_authenticated", False):
            return current_app.login_manager.unauthorized()
        if not user.is_superadmin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def write_required(fn):
    return roles_required("admin", "user")(fn)


def admin_required(fn):
    return roles_required("admin")(fn)


# --------------------------------------------------------------------------- Passwords


def report_limited_to(user) -> int | None:
    """Perfil Utilizador: os relatórios só incluem vulnerabilidades atribuídas a si (devolve o id).
    Administradores, auditores e super-administradores veem a organização inteira (None)."""
    if user.is_superadmin or user.role in ("admin", "auditor"):
        return None
    return user.id


def password_problems(password: str) -> list[str]:
    minimum = current_app.config.get("PASSWORD_MIN_LENGTH", 12)
    problems = []
    if len(password) < minimum:
        problems.append(f"mínimo de {minimum} caracteres")
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes < 3:
        problems.append("pelo menos 3 tipos: minúsculas, maiúsculas, dígitos, símbolos")
    return problems


# --------------------------------------------------------------------------- API tokens


def new_api_token() -> tuple[str, str, str]:
    raw = "omp_" + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest(), raw[:10]


def user_from_bearer():
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    raw = header[7:].strip()
    token = ApiToken.query.filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).first()
    if token is None or (token.expires_at and token.expires_at < utcnow()):
        return None
    user = token.user
    if not user.is_active:
        return None
    token.last_used = utcnow()
    db.session.commit()
    return user


# --------------------------------------------------------------------------- TOTP (RFC 6238)


def totp_new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_verify(secret: str, code: str, window: int = 1, now: float | None = None) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not secret or len(code) != 6 or not code.isdigit():
        return False
    counter = int((now or time.time()) // 30)
    return any(hmac.compare_digest(_totp_at(secret, counter + d), code) for d in range(-window, window + 1))


def totp_uri(secret: str, email: str) -> str:
    return f"otpauth://totp/OMXPatch:{quote(email)}?secret={secret}&issuer=OMXPatch&digits=6&period=30"


# --------------------------------------------------------------------------- Auditoria


def audit(action: str, detail: str = "", tenant_id: int | None = None, user=None) -> None:
    user = user or _actor()
    uid = user.id if getattr(user, "is_authenticated", False) else None
    try:
        ip = request.remote_addr or ""
    except RuntimeError:
        ip = ""
    db.session.add(AuditLog(
        tenant_id=tenant_id if tenant_id is not None else current_tenant_id_safe(),
        user_id=uid, action=action, detail=detail[:4000], ip=ip,
    ))


def current_tenant_id_safe() -> int | None:
    try:
        return current_tenant_id()
    except RuntimeError:
        return None


def flash_errors(errors: list[str]) -> None:
    for e in errors:
        flash(e, "danger")


def redirect_back(default: str):
    target = request.form.get("next") or request.args.get("next")
    if target and target.startswith("/") and not target.startswith("//"):
        return redirect(target)
    return redirect(url_for(default))
