"""Articulação com o Ansible.

O Ansible é a espinha dorsal operacional da solução:

* **instalação** — ``ansible/site.yml`` instala o centro de comando; ``deploy_agent.yml`` instala o agente
  em Windows, Linux e macOS (e regista-o com um token de registo);
* **modo sem agente** — ativos com ``connection = ansible`` recebem inventário, patches, validações e controlos
  compensatórios executados pelo próprio centro de comando via ``ansible-playbook`` (SSH / WinRM);
* **resultado estruturado** — cada playbook termina com ``OMXPATCH_RESULT=<json>``, lido por este módulo.

Os segredos nunca seguem na linha de comandos: as variáveis vão num ficheiro temporário com permissões 600.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path

from flask import current_app

from ..models import Asset, Task

MARKER = "OMXPATCH_RESULT="
PLAYBOOKS = {
    ("patch", "windows"): "patch_windows.yml", ("patch", "linux"): "patch_linux.yml", ("patch", "macos"): "patch_macos.yml",
    ("validate", "windows"): "validate_windows.yml", ("validate", "linux"): "validate_linux.yml",
    ("validate", "macos"): "validate_macos.yml",
    ("inventory", "windows"): "inventory_windows.yml", ("inventory", "linux"): "inventory_linux.yml",
    ("inventory", "macos"): "inventory_macos.yml",
    ("control", "windows"): "mitigate_firewall_windows.yml", ("control", "linux"): "mitigate_firewall_linux.yml",
    ("control", "macos"): "mitigate_firewall_macos.yml",
}


class AnsibleUnavailable(RuntimeError):
    pass


def ansible_dir() -> Path:
    return Path(current_app.config["ANSIBLE_DIR"])


def binary() -> str | None:
    return shutil.which(str(current_app.config["ANSIBLE_PLAYBOOK"]))


def available() -> bool:
    return bool(current_app.config["ANSIBLE_ENABLED"]) and binary() is not None


def playbook_for(task_type: str, os_family: str) -> str | None:
    return PLAYBOOKS.get((task_type, os_family))


def inventory_for(assets: list[Asset]) -> dict:
    """Inventário dinâmico (JSON) com grupos windows/linux/macos."""
    hosts: dict[str, dict] = {}
    groups: dict[str, list[str]] = {"windows": [], "linux": [], "macos": []}
    for a in assets:
        key = f"asset{a.id}"
        vars_: dict = {"ansible_host": a.fqdn or a.ip or a.name, "omxpatch_asset_id": a.id}
        if a.ansible_user:
            vars_["ansible_user"] = a.ansible_user
        if a.ansible_port:
            vars_["ansible_port"] = a.ansible_port
        if a.os_family == "windows":
            vars_.update({"ansible_connection": "winrm", "ansible_winrm_server_cert_validation": "validate"})
        hosts[key] = vars_
        if a.os_family in groups:
            groups[a.os_family].append(key)
    inv = {"all": {"hosts": hosts}}
    for g, members in groups.items():
        if members:
            inv[g] = {"hosts": {m: {} for m in members}}
    return inv


def parse_result(output: str) -> dict | None:
    """Lê o último ``OMXPATCH_RESULT=<json>`` da saída do Ansible, em formato json (preferido) ou yaml (linhas dobradas)."""
    found = None
    for m in re.finditer(r'"msg":\s*("(?:[^"\\]|\\.)*")', output):          # callback com result_format=json
        try:
            text = json.loads(m.group(1))
        except ValueError:
            continue
        if isinstance(text, str) and MARKER in text:
            try:
                found = json.loads(text.split(MARKER, 1)[1])
            except ValueError:
                continue
    if found is not None:
        return found
    joined = re.sub(r"\n\s+", " ", output)                                       # yaml: o Ansible dobra linhas longas nos espaços
    idx = joined.rfind(MARKER)
    if idx >= 0:
        try:
            obj, _ = json.JSONDecoder().raw_decode(joined[idx + len(MARKER):])
            return obj if isinstance(obj, dict) else None
        except ValueError:
            return None
    return None


def _materialize_keys(inventory: dict, tmp: Path) -> dict:
    """Chaves SSH privadas vindas das credenciais: ficheiro 0600 na pasta temporária (apagada no fim) em vez de seguirem na linha de comandos."""
    hosts = (inventory.get("all") or {}).get("hosts") or {}
    for name, v in hosts.items():
        key = v.pop("__ssh_key__", None)
        if key:
            kdir = tmp / "keys"
            kdir.mkdir(mode=0o700, exist_ok=True)
            path = kdir / re.sub(r"[^A-Za-z0-9_.-]", "_", name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(key.rstrip("\n") + "\n")
            v["ansible_ssh_private_key_file"] = str(path)
    return inventory


def run_playbook(playbook: str, inventory: dict, extra_vars: dict | None = None, limit: str = "",
                 timeout_minutes: int | None = None, check: bool = False) -> dict:
    """Executa ``ansible/<playbook>``; devolve {rc, output, result}."""
    exe = binary()
    if not current_app.config["ANSIBLE_ENABLED"] or exe is None:
        raise AnsibleUnavailable("ansible-playbook não está instalado ou o Ansible está desativado ([ansible] enabled)")
    base = ansible_dir()
    pb = (base / playbook).resolve()
    if base.resolve() not in pb.parents or not pb.is_file():
        raise AnsibleUnavailable(f"Playbook inexistente: {playbook}")
    timeout = int(timeout_minutes or current_app.config["ANSIBLE_TIMEOUT_MINUTES"]) * 60
    with tempfile.TemporaryDirectory(prefix="omxpatch-ansible-") as tmp:
        inv_path, vars_path = Path(tmp) / "inventory.json", Path(tmp) / "vars.json"
        inventory = _materialize_keys(inventory, Path(tmp))
        for path, data in ((inv_path, inventory), (vars_path, extra_vars or {})):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        cmd = [exe, "-i", str(inv_path), "-e", f"@{vars_path}", str(pb)]
        if limit:
            cmd += ["--limit", limit]
        if check:
            cmd.append("--check")
        env = dict(os.environ, ANSIBLE_FORCE_COLOR="0", ANSIBLE_NOCOLOR="1", ANSIBLE_CALLBACK_RESULT_FORMAT="json", ANSIBLE_HOST_KEY_CHECKING="True",
                   ANSIBLE_CONFIG=str(base / "ansible.cfg") if (base / "ansible.cfg").is_file() else "")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(base), env=env)  # nosec B603
        except subprocess.TimeoutExpired as exc:
            return {"rc": 124, "output": f"Tempo excedido ({timeout // 60} min)\n{exc.stdout or ''}", "result": None}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"rc": proc.returncode, "output": out[-60000:], "result": parse_result(out)}


def run_task(task: Task) -> dict:
    """Executa uma tarefa em modo sem agente. Devolve o relatório normalizado (como o enviado por um agente)."""
    from . import ansible_engine
    if task.type in ansible_engine.TASK_TYPES:                    # atualização completa, CyberArk, rede
        return ansible_engine.run_task(task)
    asset = task.asset
    pb = playbook_for(task.type, asset.os_family)
    if pb is None:
        return {"status": "failed", "output": f"Sem playbook para {task.type}/{asset.os_family or 'SO desconhecido'}"}
    payload = dict(task.payload_data)
    payload["task_id"] = task.id
    if task.patch is not None:
        from . import patches
        from ..models import Tenant
        from ..extensions import db
        path = patches.local_path(task.patch, db.session.get(Tenant, task.tenant_id))
        if path is not None:                                   # ficheiro do repositório: o Ansible copia-o a partir do controlador
            payload["local_file"] = str(path)
    res = run_playbook(pb, inventory_for([asset]), payload, limit=f"asset{asset.id}")
    data = res["result"] or {}
    status = data.get("status") or ("succeeded" if res["rc"] == 0 else "failed")
    return {**data, "status": status, "exit_code": res["rc"], "output": res["output"]}
