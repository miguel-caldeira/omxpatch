"""Atualização automática do agente: só com pacote **assinado** pela consola, validado por autoteste e com reversão.

Fluxo: a consola anuncia versão + SHA-256 + assinatura Ed25519 (no contacto) → o agente descarrega o pacote com a sua chave,
confere o SHA-256 e a assinatura → extrai para uma pasta temporária e corre ``selftest`` com o código novo → troca a pasta
(a anterior fica em ``omxpatch_agent.prev``) → reinicia-se. Nunca atualiza se estiver instalado como pacote do sistema
(site-packages), se a pasta não for gravável ou se o pacote não tiver assinatura válida."""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import subprocess  # nosec B404 - autoteste do pacote novo
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import omxpatch_agent as pkg

from . import __version__, config, trust
from .versioning import compare

log = logging.getLogger("omxpatch.agent.update")


def install_root() -> Path:
    return Path(pkg.__file__).resolve().parent.parent


def can_update() -> tuple[bool, str]:
    root = install_root()
    if "site-packages" in root.parts or "dist-packages" in root.parts:
        return False, "instalado como pacote do sistema"
    if not os.access(str(root), os.W_OK):
        return False, "pasta de instalação sem permissão de escrita"
    return True, ""


def _safe_extract(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for n in z.namelist():
            if n.startswith(("/", "\\")) or ".." in n.split("/") or not n.startswith("omxpatch_agent/"):
                raise ValueError("pacote inválido: " + n)
        z.extractall(dest)


def check(cfg: dict, trust_info: dict, manual: bool = False) -> dict | None:
    """Devolve a oferta de atualização se houver uma mais recente e **assinada**; senão None."""
    v, sha, sig = trust_info.get("agent_version"), trust_info.get("bundle_sha256"), trust_info.get("bundle_sig")
    if not (v and sha and sig) or (not manual and not cfg.get("auto_update", True)):
        return None
    if compare(str(v), __version__) <= 0:
        return None
    if not trust.verify_with(cfg.get("task_keys") or [], "bundle", {"version": v, "sha256": sha}, sig):
        log.warning("Atualização %s anunciada sem assinatura válida: ignorada", v)
        return None
    ok, why = can_update()
    if not ok:
        log.info("Atualização %s disponível mas não aplicável: %s", v, why)
        return None
    return {"version": v, "sha256": sha}


def apply(client, offer: dict) -> str:
    """Aplica a atualização; devolve a nova versão ou levanta ``RuntimeError`` (nada fica alterado se falhar)."""
    import hashlib
    data, header_sha = client.bundle()
    digest = hashlib.sha256(data).hexdigest()
    if digest != offer["sha256"] or (header_sha and header_sha != digest):
        raise RuntimeError("SHA-256 do pacote não corresponde ao anunciado")
    root = install_root()
    tmp = Path(tempfile.mkdtemp(prefix="omxpatch-update-"))
    try:
        _safe_extract(data, tmp)
        env = dict(os.environ, PYTHONPATH=str(tmp))
        r = subprocess.run([sys.executable, "-m", "omxpatch_agent", "selftest", "--json"], env=env, cwd=str(tmp), capture_output=True, text=True, timeout=300)  # nosec B603
        if r.returncode != 0:
            raise RuntimeError("autoteste do pacote novo falhou: " + (r.stdout or r.stderr)[-300:])
        new_version = json.loads(r.stdout).get("version", "")
        if new_version != offer["version"]:
            raise RuntimeError(f"versão do pacote ({new_version}) diferente da anunciada ({offer['version']})")
        cur, prev = root / "omxpatch_agent", root / "omxpatch_agent.prev"
        shutil.rmtree(prev, ignore_errors=True)
        os.replace(cur, prev)
        try:
            shutil.copytree(tmp / "omxpatch_agent", cur)
        except OSError:
            shutil.rmtree(cur, ignore_errors=True)
            os.replace(prev, cur)
            raise
        (config.config_dir() / "update.json").write_text(json.dumps({"from": __version__, "to": new_version, "at": time.time()}))
        return new_version
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def rollback() -> bool:
    """Repõe a versão anterior (``omxpatch_agent.prev``)."""
    root = install_root()
    cur, prev = root / "omxpatch_agent", root / "omxpatch_agent.prev"
    if not prev.is_dir():
        return False
    bad = root / "omxpatch_agent.bad"
    shutil.rmtree(bad, ignore_errors=True)
    os.replace(cur, bad)
    os.replace(prev, cur)
    shutil.rmtree(bad, ignore_errors=True)
    return True


def restart_self() -> None:
    """Relança o agente com o código novo (POSIX: exec no mesmo processo; Windows: novo processo e termina este)."""
    if os.name != "nt":
        os.execv(sys.executable, [sys.executable] + sys.argv)  # nosec B606
    subprocess.Popen([sys.executable] + sys.argv, creationflags=0x00000208, close_fds=True)  # nosec B603 - DETACHED|NEW_GROUP
    os._exit(0)
