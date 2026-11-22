"""Diagnóstico do motor Ansible: porque é que não está disponível e o comando exato que o resolve."""
from __future__ import annotations

import json
import os
import re
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

from flask import current_app

from . import ansible_runner

REQUIRED = ("ansible.posix", "community.general", "ansible.windows", "community.windows", "ansible.netcommon")   # cisco/juniper/arista só para essas plataformas
_cache: dict = {}


def _venv_pip() -> str:
    return str(Path(sys.executable).parent / "pip")


def _version(exe: str, cfg=None) -> tuple[str, str]:
    """(versão, erro): o erro é a 1.ª linha da saída de erro quando o ansible-playbook não executa."""
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60, env=ansible_runner.ansible_env(cfg))  # nosec B603
    except (OSError, subprocess.SubprocessError) as exc:
        return "", str(exc)[:200]
    first = (p.stdout.splitlines() or [""])[0].strip()
    if p.returncode != 0 or not first:
        return "", ((p.stderr or p.stdout).strip().splitlines() or ["erro desconhecido"])[0][:250]
    return first, ""


def _collections(exe: str, path: str, cfg=None) -> list[str] | None:
    gal = str(Path(exe).with_name("ansible-galaxy"))
    if not Path(gal).is_file():
        return None
    try:
        out = subprocess.run([gal, "collection", "list", "--format", "json"], capture_output=True, text=True, timeout=60,  # nosec B603
                             env=ansible_runner.ansible_env(cfg, path)).stdout
        data = json.loads(out[out.index("{"):])           # sem JSON = o ansible-galaxy não executou: desconhecido (não «em falta»)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return sorted({name for paths in data.values() for name in paths})


def _has_app() -> bool:
    try:
        current_app._get_current_object()  # noqa: SLF001
        return True
    except RuntimeError:
        return False


def collections_path() -> str:
    """Pasta de coleções usada pelo serviço (a do ambiente virtual, onde o instalador as põe) + a definida no ambiente."""
    venv = str(Path(sys.prefix) / "share" / "omxpatch" / "ansible" / "collections")
    return os.pathsep.join(p for p in (os.environ.get("ANSIBLE_COLLECTIONS_PATH", ""), venv) if p)


def diagnose(fresh: bool = False, cfg: dict | None = None) -> dict:
    """{ok, reason, enabled, configured, found, python, platform, version, missing_collections, fix}  (em cache 60 s)."""
    if cfg is None and not fresh and _cache.get("t", 0) > time.time() - 60 and _cache.get("data"):
        return _cache["data"]
    cfg = cfg if cfg is not None else current_app.config
    venv = str(Path(sys.executable).parent)
    base = Path(sys.prefix)
    cpath = collections_path()
    found = ansible_runner.binary(cfg["ANSIBLE_PLAYBOOK"])
    d = {"enabled": bool(cfg["ANSIBLE_ENABLED"]), "configured": str(cfg["ANSIBLE_PLAYBOOK"]), "found": found or "", "python": sys.version.split()[0], "executable": sys.executable,
         "platform": sys.platform, "version": "", "missing_collections": [], "config_file": cfg.get("CONFIG_FILE") or "", "collections_path": cpath}
    py_ok = sys.version_info >= (3, 9)
    if sys.platform.startswith("win"):
        d.update(ok=False, reason="windows", fix="O Ansible não corre nativamente no Windows: use um controlador Linux (o modo sem agente e o motor Ansible precisam dele). Neste servidor Windows use agentes.")
    elif not d["enabled"]:
        d.update(ok=False, reason="disabled", fix=f"O Ansible está desativado na configuração. Em {d['config_file'] or '/etc/omxpatch/omxpatch.toml'} defina [ansible] enabled = true e reinicie "
                                                  f"(sudo systemctl restart omxpatch omxpatch-worker), ou execute: sudo {venv}/omxpatch ansible-doctor --fix")
    elif not found:
        d.update(ok=False, reason="missing_binary",
                 fix=f"ansible-playbook não está instalado neste servidor (Python {d['python']}). Execute: sudo {venv}/omxpatch ansible-doctor --fix   "
                     f"(instala ansible-core e as coleções; precisa de acesso ao PyPI/Galaxy, ou use --wheels <pasta com os wheels do pacote>).")
    else:
        d["version"], d["version_error"] = _version(found, cfg)
        if d["version_error"]:
            d.update(ok=False, reason="broken", fix=f"O ansible-playbook existe mas não executa: {d['version_error']}  —  Reinstale: sudo {venv}/omxpatch ansible-doctor --fix")
            _cache.update(t=time.time(), data=d) if (cfg is current_app.config if _has_app() else False) else None
            d["python_ok"] = py_ok
            return d
        cols = _collections(found, cpath, cfg)
        if cols is not None:
            d["missing_collections"] = [c for c in REQUIRED if c not in cols]
        d["ok"] = True
        d["reason"] = "missing_collections" if d["missing_collections"] else "ok"
        d["fix"] = ("" if not d["missing_collections"] else
                    f"Faltam coleções Ansible ({', '.join(d['missing_collections'])}): sudo {Path(found).with_name('ansible-galaxy')} collection install -r {cfg['ANSIBLE_DIR']}/requirements.yml -p {base}/share/omxpatch/ansible/collections")
    d["python_ok"] = py_ok
    if cfg is current_app.config if _has_app() else False:
        _cache.update(t=time.time(), data=d)
    return d


def enable_in_config(path: str, playbook: str) -> bool:
    """Põe «[ansible] enabled = true» e o caminho do ansible-playbook no ficheiro de configuração (mantém o resto)."""
    p = Path(path)
    t = p.read_text(encoding="utf-8") if p.is_file() else ""
    m = re.search(r"(?ms)^\[ansible\]\s*\n(.*?)(?=^\[|\Z)", t)
    body = m.group(1) if m else ""
    body2 = re.sub(r"(?m)^enabled\s*=.*$", "enabled = true", body) if re.search(r"(?m)^enabled\s*=", body) else "enabled = true\n" + body
    if not re.search(r"(?m)^playbook\s*=", body2):
        body2 = body2.rstrip("\n") + f'\nplaybook = "{playbook}"\n'
    else:
        body2 = re.sub(r"(?m)^playbook\s*=.*$", f'playbook = "{playbook}"', body2)
    new = (t[:m.start(1)] + body2 + t[m.end(1):]) if m else (t.rstrip("\n") + ("\n\n" if t else "") + "[ansible]\n" + body2)
    if new == t:
        return False
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(new, encoding="utf-8")
    return True
