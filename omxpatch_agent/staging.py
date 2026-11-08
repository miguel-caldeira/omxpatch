"""*Staging* local dos instaladores: a simulação prévia descarrega-os e verifica o SHA-256; a instalação real reutiliza-os
(sem voltar a descarregar) quando o hash continua a corresponder."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import config


def staging_dir() -> Path:
    d = config.config_dir() / "staging"
    d.mkdir(parents=True, exist_ok=True)
    return d


def path_for(p: dict, suffix: str) -> Path:
    return staging_dir() / f"{int(p['patch_id'])}-{(p.get('sha256') or 'nohash')[:16]}{suffix}"


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def valid_staged(p: dict, suffix: str) -> Path | None:
    f = path_for(p, suffix)
    if f.is_file() and p.get("sha256") and file_sha256(f) == p["sha256"].lower():
        return f
    return None


def stage(client, p: dict, suffix: str) -> str:
    """Devolve o caminho do instalador no staging, descarregando-o (com limite de banda) se ainda não existir."""
    if not p.get("has_file"):
        raise RuntimeError("O patch não tem ficheiro no repositório do servidor")
    ok = valid_staged(p, suffix)
    if ok:
        return str(ok)
    f = path_for(p, suffix)
    client.download(p["patch_id"], str(f), p.get("sha256", ""), int(p.get("bandwidth_kbps") or 0))
    return str(f)


def cleanup(max_age_days: int = 14) -> int:
    import time
    n = 0
    for f in staging_dir().iterdir():
        if f.is_file() and time.time() - f.stat().st_mtime > max_age_days * 86400:
            f.unlink(missing_ok=True)
            n += 1
    return n


__all__ = ["os"]
