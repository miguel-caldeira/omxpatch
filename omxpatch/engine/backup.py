"""Cópia de segurança e retenção.

* **Cópia:** base de dados (SQLite: API de *backup* online, consistente com o serviço a correr; PostgreSQL: ``pg_dump`` se existir) +
  ficheiros que não se recriam (chave de sessão, certificados e chaves TLS, chave de assinatura, alterações de configuração),
  num ``.tar.gz`` em ``<dados>/backups``. **Contém segredos** (chaves privadas): permissões 600 — guarde-o cifrado e fora do servidor.
* **Retenção:** apaga auditoria e tarefas concluídas antigas (``AUDIT_RETENTION_DAYS`` / ``TASK_RETENTION_DAYS``; 0 = guardar sempre)
  e cópias antigas (``BACKUP_KEEP``)."""
from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess  # nosec B404 - pg_dump com argumentos fixos
import tarfile
import tempfile
import time
from datetime import timedelta
from pathlib import Path

from ..extensions import db
from ..models import AuditLog, Task, utcnow

FILES = ("secret.key", "omxpatch.overrides.toml")
DIRS = ("tls", "signing")


def backup_dir(cfg) -> Path:
    d = Path(cfg.get("BACKUP_DIR") or Path(cfg["DATA_DIR"]) / "backups")
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def sqlite_copy(src: str, dest_dir, label: str) -> Path:
    """Cópia consistente de uma base SQLite (funciona com a base em uso)."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / f"{label}-{time.strftime('%Y%m%d-%H%M%S')}.db"
    src_c, dst_c = sqlite3.connect(src), sqlite3.connect(str(out))
    try:
        src_c.backup(dst_c)
    finally:
        dst_c.close()
        src_c.close()
    os.chmod(out, 0o600)
    return out


def create(app, label: str = "omxpatch") -> dict:
    cfg = app.config
    data = Path(cfg["DATA_DIR"])
    out_dir = backup_dir(cfg)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = out_dir / f"{label}-{stamp}.tar.gz"
    with tempfile.TemporaryDirectory() as tmp:
        tmpd = Path(tmp)
        engine = db.engine.dialect.name
        if engine == "sqlite":
            dump = sqlite_copy(db.engine.url.database, tmpd, "database")
            dump.rename(tmpd / "database.sqlite")
        elif engine == "postgresql" and shutil.which("pg_dump"):
            r = subprocess.run(["pg_dump", "--format=custom", "--file", str(tmpd / "database.pgdump"), str(db.engine.url.render_as_string(hide_password=False))],  # nosec B603
                               capture_output=True, text=True, timeout=3600, env={**os.environ})
            if r.returncode:
                raise RuntimeError("pg_dump falhou: " + r.stderr[-300:])
        else:
            raise RuntimeError(f"Sem suporte para copiar a base {engine}: use a ferramenta nativa (pg_dump/mysqldump)")
        with tarfile.open(target, "w:gz") as tar:
            for f in tmpd.iterdir():
                tar.add(f, arcname=f.name)
            for name in FILES:
                if (data / name).is_file():
                    tar.add(data / name, arcname=f"files/{name}")
            for d in DIRS:
                if (data / d).is_dir():
                    tar.add(data / d, arcname=f"files/{d}")
    os.chmod(target, 0o600)
    kept = prune(cfg)
    return {"file": str(target), "size": target.stat().st_size, "engine": engine, "pruned": kept}


def prune(cfg) -> int:
    keep = int(cfg.get("BACKUP_KEEP") or 0)
    if keep <= 0:
        return 0
    files = sorted(backup_dir(cfg).glob("omxpatch-*.tar.gz"))
    old = files[:-keep]
    for f in old:
        f.unlink()
    return len(old)


def listing(cfg) -> list[dict]:
    return [{"name": f.name, "size": f.stat().st_size, "at": time.strftime("%Y-%m-%d %H:%M", time.localtime(f.stat().st_mtime))}
            for f in sorted(backup_dir(cfg).glob("omxpatch-*.tar.gz"), reverse=True)[:20]]


def restore(file: str, data_dir: str, force: bool = False) -> dict:
    """Repõe uma cópia **com o serviço parado**. Recusa se já existir uma base de dados e não houver ``force``;
    a base atual é guardada como ``*.before-restore``. Só aceita nomes esperados (sem caminhos fora do diretório de dados)."""
    data = Path(data_dir)
    with tarfile.open(file, "r:gz") as tar:
        names = tar.getnames()
        for n in names:
            if n.startswith("/") or ".." in Path(n).parts:
                raise ValueError("cópia inválida: " + n)
        if "database.sqlite" not in names:
            raise ValueError("A cópia não contém uma base SQLite (restaure PostgreSQL com pg_restore)")
        db_file = data / "omxpatch.db"
        if db_file.exists() and not force:
            raise FileExistsError(f"{db_file} já existe: pare o serviço e use --force (a atual fica guardada)")
        data.mkdir(parents=True, exist_ok=True)
        if db_file.exists():
            shutil.copy2(db_file, str(db_file) + f".before-restore-{int(time.time())}")
        for n in names:
            if n == "database.sqlite":
                with tar.extractfile(n) as src, open(db_file, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            elif n.startswith("files/") and n != "files":
                rel = Path(n[6:])
                if rel.parts[0] not in FILES and rel.parts[0] not in DIRS:
                    continue
                m = tar.getmember(n)
                if m.isdir():
                    (data / rel).mkdir(parents=True, exist_ok=True)
                elif m.isfile():
                    (data / rel).parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(m) as src, open(data / rel, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    os.chmod(data / rel, 0o600)
    return {"restored": str(db_file)}


# --------------------------------------------------------------------------- retenção


def retention(app) -> dict:
    """Apaga auditoria e tarefas concluídas antigas, conforme a configuração (0 = nunca)."""
    cfg, now, out = app.config, utcnow(), {"audit": 0, "tasks": 0, "agent_logs": 0}
    days = int(cfg.get("AUDIT_RETENTION_DAYS") or 0)
    if days > 0:
        out["audit"] = AuditLog.query.filter(AuditLog.created_at < now - timedelta(days=days)).delete(synchronize_session=False)
    days = int(cfg.get("TASK_RETENTION_DAYS") or 0)
    if days > 0:
        out["tasks"] = Task.query.filter(Task.status.in_(("succeeded", "failed", "rolled_back", "cancelled")),
                                         Task.created_at < now - timedelta(days=days)).delete(synchronize_session=False)
    days = int(cfg.get("AGENT_LOG_RETENTION_DAYS") or 0)
    if days > 0:
        from ..models import AgentLog
        out["agent_logs"] = AgentLog.query.filter(AgentLog.ts < now - timedelta(days=days)).delete(synchronize_session=False)
    db.session.commit()
    return out
