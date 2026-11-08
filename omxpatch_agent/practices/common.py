"""Base das boas práticas de configuração: edições de ficheiros com *diff*, cópia de segurança, aplicação atómica com teste
da configuração, reversão automática e verificação TLS real por protocolo."""
from __future__ import annotations
from ..config import unlink_quiet as _unlink_quiet

import difflib
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .. import config

#: Mozilla «intermediate» (TLS 1.2: só AEAD com ECDHE/DHE; TLS 1.3 usa sempre suites seguras)
INTERMEDIATE_CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                        "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384")
MARK = "OMXPatch"
HSTS_DEFAULT_MAX_AGE = 31536000


@dataclass
class Edit:
    path: str
    old: str | None            # None = ficheiro novo
    new: str
    note: str = ""

    @property
    def changed(self) -> bool:
        return self.old != self.new

    def action(self) -> dict:
        return {"target": self.path, "kind": "criar ficheiro" if self.old is None else "editar ficheiro", "summary": self.note,
                "diff": diff_text(self.old or "", self.new, self.path), "reversible": True}


def diff_text(old: str, new: str, name: str, limit: int = 80) -> str:
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), f"{name} (atual)", f"{name} (proposto)", lineterm="", n=2))
    if len(lines) > limit:
        lines = lines[:limit] + [f"… (+{len(lines) - limit} linhas)"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- edição de diretivas


def replace_directives(text: str, pattern: str, new_line: str) -> tuple[str, int]:
    """Substitui, mantendo a indentação, todas as linhas (não comentadas) que casam ``pattern`` por ``new_line``
    quando são diferentes. Devolve (texto, n.º de linhas alteradas)."""
    rx = re.compile(pattern, re.I)
    out, n = [], 0
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("#") or not rx.match(stripped):
            out.append(line)
            continue
        indent = line[:len(line) - len(stripped)]
        eol = "\n" if line.endswith("\n") else ""
        if stripped.rstrip() == new_line.rstrip():
            out.append(line)
        else:
            out.append(f"{indent}{new_line}{eol}")
            n += 1
    return "".join(out), n


def has_line(text: str, pattern: str) -> bool:
    rx = re.compile(pattern, re.I)
    return any(rx.match(l.lstrip()) for l in text.splitlines() if not l.lstrip().startswith("#"))


# --------------------------------------------------------------------------- cópia de segurança e aplicação


def backup_root() -> Path:
    d = config.config_dir() / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_backup(item: str, edits: list[Edit], extra: dict | None = None) -> Path:
    d = backup_root() / re.sub(r"[^A-Za-z0-9_.-]", "_", str(item))
    d.mkdir(parents=True, exist_ok=True)
    manifest = {"files": [], **(extra or {})}
    for i, e in enumerate(edits):
        if e.old is None:
            manifest["files"].append({"path": e.path, "created": True})
        else:
            (d / f"{i}.bak").write_text(e.old, encoding="utf-8")
            manifest["files"].append({"path": e.path, "backup": f"{i}.bak"})
    (d / "manifest.json").write_text(json.dumps(manifest))
    return d


def restore_backup(item: str) -> list[str]:
    d = backup_root() / re.sub(r"[^A-Za-z0-9_.-]", "_", str(item))
    m = json.loads((d / "manifest.json").read_text())
    done = []
    for f in m["files"]:
        p = Path(f["path"])
        if f.get("created"):
            _unlink_quiet(p)
        else:
            write_atomic(str(p), (d / f["backup"]).read_text(encoding="utf-8"))
        done.append(str(p))
    return done


def write_atomic(path: str, text: str) -> None:
    p = Path(path)
    mode = p.stat().st_mode & 0o7777 if p.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".omxpatch-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        _unlink_quiet(Path(tmp))
        raise


# --------------------------------------------------------------------------- verificação TLS real


def tls_speaks(host: str, port: int, timeout: float = 3.0) -> bool:
    """A porta fala TLS? (handshake com qualquer versão ≥ 1.2, sem validar o certificado)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host):
            return True
    except (OSError, ssl.SSLError):
        return False


def tls_probe(host: str, port: int, version: str, timeout: float = 3.0) -> str:
    """``accepted`` | ``rejected`` | ``untestable`` (o cliente OpenSSL não consegue oferecer esse protocolo)."""
    tv = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1, "TLSv1.2": ssl.TLSVersion.TLSv1_2,
          "TLSv1.3": ssl.TLSVersion.TLSv1_3}[version]
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        ctx.minimum_version = ctx.maximum_version = tv
    except (ValueError, ssl.SSLError):
        return "untestable"
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host):
            return "accepted"
    except ssl.SSLError as exc:
        msg = str(exc).upper()
        if "NO_PROTOCOLS_AVAILABLE" in msg or "NO PROTOCOLS AVAILABLE" in msg or "UNSUPPORTED_PROTOCOL" in msg and "ALERT" not in msg:
            return "untestable"
        return "rejected"
    except OSError:
        return "rejected"


def tls_matrix(host: str, port: int) -> dict:
    return {v: tls_probe(host, port, v) for v in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")}


def judge_matrix(m: dict, want_tls13: bool) -> tuple[bool, list[str]]:
    """Cumpre a boa prática? TLS 1.2 aceite, 1.0/1.1 não aceites e (se esperado) 1.3 aceite."""
    bad = []
    if m.get("TLSv1.2") != "accepted":
        bad.append("TLS 1.2 não é aceite")
    if want_tls13 and m.get("TLSv1.3") != "accepted":
        bad.append("TLS 1.3 não é aceite")
    for v in ("TLSv1", "TLSv1.1"):
        if m.get(v) == "accepted":
            bad.append(f"{v} ainda é aceite")
    return not bad, bad


def which(name: str) -> str | None:
    return shutil.which(name)
