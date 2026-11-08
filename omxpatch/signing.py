"""Assinatura Ed25519 das tarefas e do pacote do agente.

O servidor assina cada tarefa no momento em que a entrega (com ``iat``) e o pacote do agente (versão + SHA-256). O agente
verifica com a chave pública que fixou ao registar-se (e que só aceita trocar por uma lista que contenha a que já tem), por isso
uma tarefa alterada na base de dados, num proxy ou por quem não tenha a chave privada é recusada. A chave privada fica em
``<dados>/signing/task.key``; a rotação (``omxpatch signing rotate``) mantém a chave anterior publicada para os agentes migrarem."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(kind: str, data: dict) -> bytes:
    return b"OMXPatch-" + kind.encode() + b"\0" + json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _dir(cfg) -> Path:
    d = Path(cfg["DATA_DIR"]) / "signing"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def private_key(cfg) -> Ed25519PrivateKey:
    p = _dir(cfg) / "task.key"
    if p.is_file():
        return serialization.load_pem_private_key(p.read_bytes(), None)
    key = Ed25519PrivateKey.generate()
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def public_keys(cfg) -> list[str]:
    """Chave atual primeiro, depois a anterior (se tiver havido rotação)."""
    keys = [_pub_hex(private_key(cfg))]
    prev = _dir(cfg) / "task.prev.pub"
    if prev.is_file() and prev.read_text().strip() not in keys:
        keys.append(prev.read_text().strip())
    return keys


def sign(cfg, kind: str, data: dict) -> str:
    return private_key(cfg).sign(canonical(kind, data)).hex()


def rotate(cfg) -> dict:
    """Gera uma nova chave; a anterior fica publicada (task.prev.pub) para os agentes a substituírem sem perder a continuidade."""
    d = _dir(cfg)
    old = private_key(cfg)
    (d / "task.prev.pub").write_text(_pub_hex(old))
    os.replace(d / "task.key", d / f"task.key.{int(time.time())}.old")
    new = private_key(cfg)
    return {"current": _pub_hex(new), "previous": _pub_hex(old)}


def sign_task(cfg, agent_id: int, task: dict) -> dict:
    """Acrescenta ``iat`` e ``sig`` a uma tarefa entregue ao agente."""
    task["iat"] = int(time.time())
    task["sig"] = sign(cfg, "task", {"id": task["id"], "type": task["type"], "payload": task["payload"], "agent": agent_id, "iat": task["iat"]})
    return task
