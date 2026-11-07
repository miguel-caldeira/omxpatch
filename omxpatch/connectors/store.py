"""Cifra dos segredos dos conectores (Fernet), com chave fora da base de dados (``<dados>/connectors.key``)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

from ..extensions import db
from ..models import Connector


class ConnectorError(RuntimeError):
    pass


def _fernet() -> Fernet:
    env = os.environ.get("OMXPATCH_CONNECTORS_KEY")
    if env:
        return Fernet(env.encode())
    path = Path(current_app.config["DATA_DIR"]) / "connectors.key"
    if path.is_file():
        return Fernet(path.read_bytes().strip())
    key = Fernet.generate_key()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return Fernet(key)


def get_secrets(c: Connector) -> dict:
    if not c.secret:
        return {}
    try:
        return json.loads(_fernet().decrypt(c.secret.encode()).decode())
    except (InvalidToken, ValueError) as exc:
        raise ConnectorError("Não foi possível decifrar as credenciais (chave connectors.key alterada?). "
                             "Introduza-as de novo.") from exc


def set_secrets(c: Connector, values: dict) -> None:
    cur = get_secrets(c) if c.secret else {}
    cur.update({k: v for k, v in values.items() if v})            # campo vazio = manter
    c.secret = _fernet().encrypt(json.dumps(cur).encode()).decode()


def for_tenant(tenant_id: int, kind: str, only_enabled: bool = True) -> Connector | None:
    q = Connector.query.filter_by(tenant_id=tenant_id, kind=kind)
    if only_enabled:
        q = q.filter_by(enabled=True)
    return q.first()


def of_group(tenant_id: int, group: str) -> list[Connector]:
    from .catalog import KINDS
    kinds = [k for k, v in KINDS.items() if v["group"] == group]
    return Connector.query.filter(Connector.tenant_id == tenant_id, Connector.kind.in_(kinds), Connector.enabled.is_(True)).all()


def save(tenant_id: int, kind: str, base_url: str, username: str, secrets: dict, options: dict, verify_tls: bool,
         enabled: bool = True) -> Connector:
    c = Connector.query.filter_by(tenant_id=tenant_id, kind=kind).first()
    if c is None:
        c = Connector(tenant_id=tenant_id, kind=kind)
        db.session.add(c)
    c.base_url, c.username, c.verify_tls, c.enabled = base_url.strip(), username.strip(), verify_tls, enabled
    c.options = json.dumps(options)
    set_secrets(c, secrets)
    return c


def effective(tenant_id: int, kind: str):
    """Conector da organização ou, na falta dele, o definido na configuração global (``[omxvuln]`` / ``[omxgrc]``)."""
    c = for_tenant(tenant_id, kind)
    if c is not None:
        return c
    cfg = current_app.config
    prefix = kind.upper()
    if kind in ("omxvuln", "omxgrc") and cfg.get(f"{prefix}_URL") and cfg.get(f"{prefix}_TOKEN"):
        tmp = Connector(tenant_id=tenant_id, kind=kind, base_url=cfg[f"{prefix}_URL"],
                        verify_tls=bool(cfg.get(f"{prefix}_VERIFY_TLS", True)), enabled=True, options="{}")
        if kind == "omxvuln" and cfg.get("OMXVULN_TENANT_ID"):
            tmp.options = json.dumps({"tenant_id": str(cfg["OMXVULN_TENANT_ID"])})
        set_secrets(tmp, {"token": cfg[f"{prefix}_TOKEN"]})
        return tmp
    return None
