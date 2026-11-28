"""Instalação do agente OMXPatch SEM agente prévio: SSH (Linux/macOS) ou WMI/DCOM + SMB (Windows).

Gera o script de auto-instalação da consola com um token de registo de **uso único** (válido 1 dia), copia-o para o equipamento, executa-o
(`sudo -n` se o utilizador não for root), apaga-o e confirma que o agente se registou (o token foi usado). A partir daí o ativo passa a poder
usar o agente (execução local, deteção, patching com janelas e reversão)."""
from __future__ import annotations

import re
import time
import uuid
from urllib.parse import urlsplit

from flask import current_app

from .. import installers
from ..models import Asset, EnrollmentToken, Task, Tenant
from ..transports import TransportError, make_transport


class DeployError(RuntimeError):
    pass


def _conn(asset: Asset) -> tuple[str, dict]:
    from . import ansible_engine as eng
    inv = eng.build_inventory([asset], {asset.id: asset.ansible_transport} if asset.ansible_transport == "agent" else None)
    v = inv["all"]["hosts"][f"asset{asset.id}"]
    kind = {"omx_wmi": "wmi", "ssh": "ssh"}.get(v.get("ansible_connection") or "ssh")
    if kind is None:
        raise DeployError("A instalação do agente só é possível por SSH (Linux/macOS) ou WMI (Windows); este ativo usa " + str(v.get("ansible_connection")))
    return kind, v


def _transport(kind: str, v: dict):
    from . import ansible_runner
    host = v.get("ansible_host")
    if kind == "wmi":
        return make_transport("wmi", host=host, user=v.get("ansible_user", ""), password=v.get("ansible_password", ""), domain=v.get("omx_domain", ""), timeout=30)
    return make_transport("ssh", host=host, user=v.get("ansible_user", ""), password=v.get("ansible_password", ""), key_pem=v.get("__ssh_key__", ""),
                          passphrase=v.get("ansible_ssh_private_key_passphrase", ""), port=int(v.get("ansible_port") or 22),
                          known_hosts=str(ansible_runner.ansible_home() / "known_hosts"), accept_new="accept-new" in str(v.get("ansible_ssh_common_args", "")), timeout=20)


def _os_kind(asset: Asset) -> str:
    return {"windows": "windows", "macos": "macos"}.get(asset.os_family or "", "linux")


def make_script(tenant: Tenant, asset: Asset, token_name: str) -> tuple[str, str, EnrollmentToken]:
    from ..web.admin import agent_pin
    from ..web.api import new_enrollment_token
    cfg = current_app.config
    raw, tok = new_enrollment_token(tenant, token_name[:120], asset.ring if asset.ring in (0, 1, 2, 3, 4) else 4, 1, 1)
    host = urlsplit(cfg["AGENT_BASE_URL"]).hostname or ""
    name, body = installers.render(_os_kind(asset), url=cfg["AGENT_BASE_URL"], pin=agent_pin(), token=raw, tenant_name=tenant.name, host=host,
                                   server_ip=cfg["AGENT_SERVER_IP"], when=time.strftime("%Y-%m-%d %H:%M"))
    return name, body, tok


def install(tenant: Tenant, asset: Asset, wait: int = 90) -> dict:
    """Devolve {"status", "output", ...}. Nunca regista o token nos logs."""
    from ..extensions import db
    kind, v = _conn(asset)
    name, body, tok = make_script(tenant, asset, f"agentless-{asset.name}")
    db.session.flush()
    data = (b"\xef\xbb\xbf" if name.endswith(".ps1") else b"") + body.encode("utf-8")
    ident = uuid.uuid4().hex[:10]
    win = kind == "wmi"
    remote = rf"C:\Windows\Temp\omx-{ident}.ps1" if win else f"/tmp/.omx-{ident}.sh"
    log: list[str] = []
    t = _transport(kind, v)
    try:
        with t:
            tmp = current_app.instance_path
            import os
            import tempfile
            fd, local = tempfile.mkstemp(prefix="omx-inst-", dir=tmp if os.path.isdir(tmp) else None)
            try:
                os.write(fd, data)
                os.close(fd)
                os.chmod(local, 0o600)
                t.put(local, remote)
            finally:
                try:
                    os.unlink(local)
                except OSError:
                    pass
            log.append(f"Script copiado para {remote} ({kind.upper()})")
            if win:
                cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{remote}"'
            else:
                uid = t.run("id -u", timeout=30).out.strip()
                if uid == "0":
                    cmd = f"sh {remote}"
                else:
                    if t.run("sudo -n true", timeout=30).rc != 0:
                        raise DeployError("O utilizador não é root e o sudo pede palavra-passe: configure NOPASSWD ou use uma conta root/administrador.")
                    cmd = f"sudo -n sh {remote}"
            r = t.run(cmd, timeout=900)
            log.append(f"Instalador terminou com código {r.rc}")
            tail = (r.out + r.err)[-4000:]
            tail = re.sub(r"omxe_[A-Za-z0-9_\-]+", "omxe_…", tail).strip()
            try:
                t.run(f'del /f /q "{remote}"' if win else f"rm -f {remote}", timeout=30)
            except TransportError:
                pass
            if r.rc != 0:
                return {"status": "failed", "output": "\n".join(log) + "\n" + tail, "exit_code": r.rc}
    except TransportError as exc:
        return {"status": "failed", "output": "\n".join(log) + f"\nFalha de ligação ({kind.upper()}): {exc}"}
    except DeployError as exc:
        return {"status": "failed", "output": "\n".join(log) + f"\n{exc}"}
    db.session.commit()                                  # o registo do agente corre noutra sessão: ver o contador atualizado
    deadline = time.time() + wait
    while True:
        db.session.refresh(tok)
        if tok.uses:
            break
        if time.time() > deadline:
            return {"status": "failed", "output": "\n".join(log) + "\nO script correu, mas o agente não se registou no servidor (porta 4444 acessível a partir do ativo?)."}
        time.sleep(2)
    log.append("Agente registado no servidor.")
    return {"status": "succeeded", "output": "\n".join(log) + "\n" + tail, "agent_installed": True}


def run(task: Task) -> dict:
    from ..extensions import db
    asset, tenant = task.asset, db.session.get(Tenant, task.tenant_id)
    from . import ansible_engine as eng
    if eng.agent_for(asset):
        return {"status": "succeeded", "output": "O ativo já tem um agente ativo; nada a fazer."}
    return install(tenant, asset, wait=int(current_app.config.get("AGENT_INSTALL_WAIT", 90)))

