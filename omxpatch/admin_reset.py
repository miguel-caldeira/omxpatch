"""Reposição da password do super-administrador (acesso perdido à plataforma).

Três formas, todas exigem acesso de administrador ao servidor:

* **no arranque** — crie o ficheiro ``reset-admin`` no diretório de dados e reinicie o serviço
  (Linux: ``sudo touch /var/lib/omxpatch/reset-admin && sudo systemctl restart omxpatch``;
  Windows: ``New-Item C:\\ProgramData\\OMXPatch\\reset-admin; Restart-Service OMXPatch``);
* **no arranque** — variável de ambiente ``OMXPATCH_RESET_ADMIN=1`` (ou o e-mail a repor);
* **de imediato** — ``omxpatch reset-admin [--email ...] [--reset-mfa]``.

O ficheiro pode estar vazio ou indicar, uma opção por linha, ``email=...`` e ``mfa=reset``. A nova password
(aleatória, a alterar no 1.º login) é mostrada no registo do serviço e gravada em
``<dados>/initial_admin.txt`` (permissões 600); o ficheiro ``reset-admin`` é apagado. A conta é
desbloqueada e reativada, as sessões abertas terminam e a ação fica no registo de auditoria.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from .models import PRIMARY_ADMIN_EMAIL as DEFAULT_EMAIL
FLAG_FILE = "reset-admin"


def flag_path(cfg) -> Path:
    return Path(cfg["DATA_DIR"]) / FLAG_FILE


def _read_flag(path: Path) -> dict:
    opts: dict[str, str] = {}
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            return {"_invalid": "1"}
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                opts[k.strip().lower()] = v.strip()
            elif "@" in line:
                opts["email"] = line
    except OSError:
        pass
    return opts


def pending(cfg) -> dict | None:
    """Pedido de reposição no arranque (ficheiro ou variável de ambiente), ou None."""
    env = (os.environ.get("OMXPATCH_RESET_ADMIN") or "").strip()
    path = flag_path(cfg)
    if path.exists() or path.is_symlink():
        opts = _read_flag(path)
        opts["_source"] = str(path)
        return opts
    if env and env.lower() not in ("0", "false", "no", "nao", "não"):
        return {"email": env if "@" in env else "", "_source": "OMXPATCH_RESET_ADMIN"}
    return None


def reset(app, email: str = "", reset_mfa: bool = False, source: str = "linha de comandos") -> tuple[str, str]:
    """Repõe (ou cria) o super-administrador ``email``; devolve (email, nova password)."""
    from .extensions import db
    from .models import User
    from .security import audit
    with app.app_context():
        email = (email or "").strip().lower()
        if email:
            user = User.query.filter(db.func.lower(User.email) == email).first()
            if user is not None and not user.is_superadmin:
                raise ValueError(f"{email} não é super-administrador: só é possível repor super-administradores")
        else:
            user = (User.query.filter(db.func.lower(User.email) == DEFAULT_EMAIL).first()
                    or User.query.filter_by(is_superadmin=True).order_by(User.id).first())
            email = user.email if user else DEFAULT_EMAIL
        password = secrets.token_urlsafe(14) + "!A1"
        if user is None:
            user = User(email=email, name="Super-administrador", role="admin", is_superadmin=True)
            db.session.add(user)
        user.set_password(password)
        user.enabled = True
        if email == DEFAULT_EMAIL and not User.query.filter(User.is_primary.is_(True), User.id != user.id).first():
            user.is_primary = True
        user.must_change_password = True
        user.failed_logins = 0
        user.locked_until = None
        user.session_version = (user.session_version or 1) + 1      # termina as sessões abertas
        if reset_mfa:
            user.mfa_enabled, user.mfa_secret, user.mfa_recovery_codes = False, "", ""
            user.mfa_last_counter = None
        db.session.flush()
        audit("admin_password_reset", f"{email} ({source}{', MFA reposto' if reset_mfa else ''})", tenant_id=None, user=user)
        db.session.commit()
        write_initial(app, email, password, "Password reposta.")
        return email, password


def write_initial(app, email: str, password: str, note: str) -> Path:
    path = Path(app.config["DATA_DIR"]) / "initial_admin.txt"
    path.write_text(f"utilizador: {email}\npassword: {password}\n"
                    f"{note} Altere-a no primeiro login e apague este ficheiro.\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def ensure_primary(app, log=print) -> str | None:
    """Garante o super-administrador inicial (admin@omxpatch.local), sem alterar dados existentes.

    * já existe um super-administrador inicial: nada a fazer;
    * existe ``admin@omxpatch.local`` como super-administrador (versões anteriores): passa a ser o inicial,
      com a password que já tem;
    * não existe: é criado (também numa base de dados já com organizações e utilizadores) com uma
      password aleatória, a alterar no 1.º login, mostrada no registo e em ``initial_admin.txt``.
    Devolve a password quando cria a conta."""
    from .extensions import db
    from .models import User
    from .security import audit
    with app.app_context():
        if User.query.filter_by(is_primary=True).first():
            return None
        user = User.query.filter(db.func.lower(User.email) == DEFAULT_EMAIL).first()
        if user is not None:
            if not user.is_superadmin:
                log(f"AVISO: {DEFAULT_EMAIL} existe mas não é super-administrador; super-administrador inicial "
                    "não definido (use 'omxpatch reset-admin' depois de mudar o e-mail dessa conta).")
                return None
            user.is_primary = True
            user.enabled = True
            audit("primary_admin_marked", DEFAULT_EMAIL, tenant_id=None, user=user)
            db.session.commit()
            return None
        password = secrets.token_urlsafe(14) + "!A1"
        user = User(email=DEFAULT_EMAIL, name="Super-administrador", role="admin", is_superadmin=True,
                    is_primary=True, must_change_password=True)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        audit("primary_admin_created", DEFAULT_EMAIL, tenant_id=None, user=user)
        db.session.commit()
        path = write_initial(app, DEFAULT_EMAIL, password, "Super-administrador inicial.")
    log("=" * 70)
    log(" Super-administrador inicial criado")
    log(f"   utilizador: {DEFAULT_EMAIL}")
    log(f"   password:   {password}")
    log(f"   (também guardado em {path}; altere-a no primeiro login)")
    log("=" * 70)
    return password


def initial_password(app) -> tuple[str, str | None, str]:
    """(e-mail, password inicial ainda válida ou None, mensagem) — para os instaladores."""
    from .extensions import db
    from .models import User
    with app.app_context():
        user = User.query.filter_by(is_primary=True).first() or \
            User.query.filter(db.func.lower(User.email) == DEFAULT_EMAIL).first()
        email = user.email if user else DEFAULT_EMAIL
        path = Path(app.config["DATA_DIR"]) / "initial_admin.txt"
        if user is None:
            return email, None, "O super-administrador inicial ainda não foi criado (é criado no arranque do serviço)."
        if user.must_change_password and path.is_file():
            text = path.read_text(encoding="utf-8")
            if f"utilizador: {email}" in text and "password: " in text:
                return email, text.split("password: ", 1)[1].split("\n", 1)[0].strip(), ""
        return email, None, ("A password inicial já foi alterada (dados existentes mantidos). Se a perdeu, "
                             "reponha-a com 'omxpatch reset-admin' ou com o ficheiro reset-admin no diretório de dados.")


def on_startup(app, log=print) -> bool:
    """Executa a reposição pedida por ficheiro/variável de ambiente; True se repôs."""
    req = pending(app.config)
    if req is None:
        return False
    path = flag_path(app.config)
    if req.get("_invalid"):
        log(f"Pedido de reposição ignorado: {path} tem de ser um ficheiro normal e pequeno.")
        return False
    try:
        email, password = reset(app, req.get("email", ""), reset_mfa=req.get("mfa", "").lower() in ("reset", "1", "sim", "yes"),
                                source=f"arranque, {req['_source']}")
    except ValueError as exc:
        log(f"Reposição da password de administrador recusada: {exc}")
        return False
    finally:
        try:
            if path.exists() or path.is_symlink():
                path.unlink()
        except OSError as exc:
            log(f"AVISO: não foi possível apagar {path} ({exc}): apague-o para não repor de novo no próximo arranque")
    log("=" * 70)
    log(" Password do super-administrador reposta no arranque")
    log(f"   utilizador: {email}")
    log(f"   password:   {password}")
    log(f"   (também guardada em {Path(app.config['DATA_DIR']) / 'initial_admin.txt'}; altere-a no 1.º login)")
    log("=" * 70)
    return True
