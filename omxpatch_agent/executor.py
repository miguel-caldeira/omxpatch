"""Execução das tarefas recebidas do centro de comando."""
from __future__ import annotations

import logging
import os
import socket
import tempfile
import time
from datetime import datetime

from . import bas, collectors, firewall, health, preflight, staging
from .client import Client
from .config import platform_family
from .patchers import PatchError, apply as apply_patch
from .runner import powershell, run

log = logging.getLogger("omxpatch.agent")


def _patch(client: Client, task: dict) -> dict:
    p = task["payload"]
    start = time.time()
    before = health.failed_units()
    tmp: list[str] = []

    def download(suffix: str) -> str:
        if not p.get("has_file"):
            raise PatchError("O patch não tem ficheiro no repositório do servidor")
        staged = staging.valid_staged(p, suffix)          # já verificado na simulação prévia: não volta a descarregar
        if staged:
            return str(staged)
        fd, path = tempfile.mkstemp(prefix="omxpatch-", suffix=suffix)
        os.close(fd)
        tmp.append(path)
        client.download(p["patch_id"], path, p.get("sha256", ""), int(p.get("bandwidth_kbps") or 0))
        return path

    try:
        rep = apply_patch(p, download)
    except Exception as exc:  # noqa: BLE001 - qualquer falha é reportada ao servidor
        rep = {"status": "failed", "output": f"{exc.__class__.__name__}: {exc}"}
    finally:
        for f in tmp:
            try:
                os.remove(f)
            except OSError:
                pass
    duration = int(time.time() - start)
    crashed = health.failed_units() > before
    rebooted = p.get("reboot_policy") == "force" or rep.get("reboot_pending", False)
    rep.update({"duration_s": duration, "crashed": crashed,
                "ux_score": health.ux_score(duration, rebooted and p.get("reboot_policy") == "force", crashed, rep["status"] != "succeeded")})
    return rep


def _process_started_before(name: str, since: datetime) -> bool | None:
    """True se algum processo do software foi (re)iniciado depois de ``since``; None se não há processos."""
    token = (name or "").split(" ")[0].lower()
    if not token:
        return None
    fam = platform_family()
    started: list[float] = []
    if fam == "windows":
        r = powershell(f"Get-Process | Where-Object {{$_.ProcessName -like '*{token.replace(chr(39), '')}*'}} | "
                       "ForEach-Object {{ $_.StartTime.ToUniversalTime().ToString('o') }}", 120)
        for l in r.out.splitlines():
            try:
                started.append(datetime.fromisoformat(l.strip().replace("Z", "")[:26]).timestamp())
            except ValueError:
                continue
    else:
        r = run(["ps", "-eo", "etimes=,comm="], 30)
        for l in r.out.splitlines():
            parts = l.split(None, 1)
            if len(parts) == 2 and token in parts[1].lower() and parts[0].isdigit():
                started.append(time.time() - int(parts[0]))
    if not started:
        return None
    return all(s >= since.timestamp() for s in started)


def _validate(client: Client, task: dict) -> dict:
    p = task["payload"]
    info = collectors.collect()                                    # inventário completo recente
    patch = p.get("patch") or {}
    sw = info["software"]
    checks: dict = {}
    fixed = (patch.get("version_fixed") or p.get("fixed_version") or "")
    uid = (patch.get("uid") or p.get("fixed_version") or "").upper()
    if uid.startswith("KB"):
        checks["patch_installed"] = uid in {k.upper() for k in info.get("hotfixes", [])}
    elif fixed:
        from .versioning import compare
        name = (p.get("software") or patch.get("package") or "").lower()
        hits = [s for s in sw if name and name.split(" ")[0] in s["name"].lower()]
        checks["patch_installed"] = bool(hits) and all(compare(s["version"], fixed) >= 0 for s in hits)
    else:
        checks["patch_installed"] = None
    try:
        since = datetime.fromisoformat(p.get("patched_at", "").replace("Z", ""))
    except ValueError:
        since = datetime.utcnow()
    checks["service_restarted"] = _process_started_before(p.get("software", ""), since)
    return {"status": "succeeded", "checks": checks, "software": sw, "full_inventory": True,
            "hotfixes": info.get("hotfixes"), "ports_open": info.get("open_ports", []), "output": f"{len(sw)} itens de software"}


def _bas(client: Client, task: dict) -> dict:
    p = task["payload"]
    steps = []
    for sid in p.get("steps", []):
        r = bas.run_step(sid, p)
        steps.append({"id": sid, **r})
    return {"status": "succeeded", "steps": steps, "output": f"{len(steps)} passos executados"}


def _control(client: Client, task: dict) -> dict:
    p = task["payload"]
    try:
        res = firewall.remove(p) if p.get("op") == "firewall_remove" else firewall.block(p)
        return {"status": "succeeded", **res}
    except (firewall.FirewallError, KeyError, ValueError) as exc:
        return {"status": "failed", "output": f"{exc.__class__.__name__}: {exc}"}


def _wake(client: Client, task: dict) -> dict:
    p = task["payload"]
    raw = bytes.fromhex(str(p["mac"]).replace(":", "").replace("-", ""))
    pkt = b"\xff" * 6 + raw * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(pkt, (p.get("broadcast", "255.255.255.255"), 9))
    return {"status": "succeeded", "output": f"Magic packet enviado para {p['mac']}"}


def _inventory(client: Client, task: dict) -> dict:
    info = collectors.collect()
    return {"status": "succeeded", **{k: info[k] for k in ("software", "hardware", "open_ports", "reboot_pending", "os_name", "os_version", "primary_user", "ip", "mac", "fqdn", "capabilities") if k in info},
            "hotfixes": info.get("hotfixes"), "output": f"{len(info['software'])} itens"}


def _simulate(client: Client, task: dict) -> dict:
    return preflight.run_simulation(client, task["payload"])


HANDLERS = {"simulate": _simulate, "patch": _patch, "validate": _validate, "bas": _bas, "control": _control, "wake": _wake, "inventory": _inventory,
            "rollback": lambda c, t: {"status": "failed", "output": "Reversão automática não suportada neste agente"}}


def execute(client: Client, task: dict) -> dict:
    h = HANDLERS.get(task["type"])
    if h is None:
        return {"status": "failed", "output": f"Tipo de tarefa desconhecido: {task['type']}"}
    try:
        client.task_start(task["id"])
    except Exception:  # noqa: BLE001 - o início é informativo
        pass
    try:
        return h(client, task)
    except Exception as exc:  # noqa: BLE001
        log.exception("Tarefa %s falhou", task["id"])
        return {"status": "failed", "output": f"{exc.__class__.__name__}: {exc}"}
