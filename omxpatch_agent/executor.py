"""Execução das tarefas recebidas do centro de comando."""
from __future__ import annotations

import logging
import os
import re
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
        if p.get("op") in ("isolate", "isolate_release"):
            from . import isolation
            res = isolation.isolate(p) if p["op"] == "isolate" else isolation.release(p)
        else:
            res = firewall.remove(p) if p.get("op") == "firewall_remove" else firewall.block(p)
        return {"status": "succeeded", **res}
    except Exception as exc:  # noqa: BLE001 - FirewallError, IsolationError, KeyError, ValueError
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
    return {"status": "succeeded", **{k: info[k] for k in ("software", "hardware", "open_ports", "reboot_pending", "os_name", "os_version", "primary_user", "ip", "mac", "fqdn", "capabilities", "webservers") if k in info},
            "hotfixes": info.get("hotfixes"), "output": f"{len(info['software'])} itens"}


def _simulate(client: Client, task: dict) -> dict:
    return preflight.run_simulation(client, task["payload"])


def _practice_sim(client: Client, task: dict) -> dict:
    from . import practices
    p = task["payload"]
    res = practices.simulate(p["practice"], p.get("params") or {})
    return {"status": "succeeded", **res, "output": res.get("predicted", {}).get("summary", "")}


def _practice_apply(client: Client, task: dict) -> dict:
    from . import practices
    p = task["payload"]
    return practices.apply(p["practice"], p.get("params") or {}, f"item-{p['item_id']}")


def _practice_rollback(client: Client, task: dict) -> dict:
    from . import practices
    p = task["payload"]
    return practices.rollback(f"item-{p['item_id']}", {**(p.get("params") or {}), "practice": p.get("practice", "")})


MAX_EXEC_SECONDS = 1800
MAX_RESULT_BYTES = 8 * 1024 * 1024
HOT_UNTIL = 0.0                        # depois de executar um comando, o agente consulta a consola a cada segundo durante 2 min (o Ansible faz muitos pedidos seguidos)


def _cap(data: bytes) -> tuple[str, bool]:
    import base64
    cut = len(data) > MAX_RESULT_BYTES
    return base64.b64encode(data[:MAX_RESULT_BYTES]).decode("ascii"), cut


def _exec(client: Client, task: dict) -> dict:
    """Procuração (proxy) de comandos do Ansible e do PowerShell: executa no próprio equipamento o que a consola pede, quando o acesso sem agente
    (WinRM/SSH) não é possível. Só funciona se a consola o ativar (AGENT_EXEC_ENABLED) **e** o administrador do equipamento o permitir
    localmente (``omxpatch-agent config allow-exec on``); a tarefa tem de estar assinada pela consola. Cada comando fica na auditoria do agente
    (só o resumo SHA-256 e o tamanho, nunca o conteúdo)."""
    import base64
    import hashlib
    import subprocess  # nosec B404 - função própria deste módulo: executar comandos pedidos pela consola
    from . import config as agent_config, telemetry
    global HOT_UNTIL
    p = task["payload"]
    if not agent_config.load().get("allow_exec"):
        return {"status": "failed", "rc": 126, "output": "Execução remota desativada neste equipamento (administrador local: omxpatch-agent config allow-exec on)."}
    if not telemetry.runtime().get("exec_enabled"):
        return {"status": "failed", "rc": 126, "output": "Execução remota desativada na consola (Sistema → Configuração → AGENT_EXEC_ENABLED)."}
    op = str(p.get("op") or "run")
    HOT_UNTIL = time.time() + 120
    if op == "run":
        cmd = str(p.get("cmd") or "")
        stdin = base64.b64decode(p["stdin_b64"]) if p.get("stdin_b64") else None
        timeout = max(1, min(int(p.get("timeout") or 300), MAX_EXEC_SECONDS))
        telemetry.audit("exec", f"comando de {len(cmd)} caracteres, stdin {len(stdin or b'')} bytes", cmd_sha256=hashlib.sha256(cmd.encode()).hexdigest(), task_id=task["id"])
        kw = {"executable": "/bin/sh"} if platform_family() != "windows" else {}
        try:
            r = subprocess.run(cmd, shell=True, input=stdin, capture_output=True, timeout=timeout, **kw)  # nosec B602 - é a função deste proxy; ver docstring
        except subprocess.TimeoutExpired as exc:
            out, cut = _cap(exc.stdout or b"")
            err, _ = _cap((exc.stderr or b"") + f"\nTempo excedido ({timeout}s)".encode())
            return {"status": "succeeded", "rc": 124, "stdout_b64": out, "stderr_b64": err, "output": "tempo excedido"}
        out, cut = _cap(r.stdout)
        err, cut2 = _cap(r.stderr)
        return {"status": "succeeded", "rc": r.returncode, "stdout_b64": out, "stderr_b64": err, "truncated": cut or cut2, "output": f"rc={r.returncode}"}
    if op == "put":
        import tempfile
        sha, dest = str(p.get("sha256") or ""), str(p.get("dest") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or not dest:
            return {"status": "failed", "rc": 1, "output": "pedido inválido"}
        telemetry.audit("exec_put", f"ficheiro de {int(p.get('size') or 0)} bytes", sha256=sha, task_id=task["id"])
        fd, tmp = tempfile.mkstemp(prefix="omx-put-")
        os.close(fd)
        try:
            client.blob(sha, tmp)
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            os.replace(tmp, dest)
            if p.get("mode") and platform_family() != "windows":
                os.chmod(dest, int(str(p["mode"]), 8))
            return {"status": "succeeded", "rc": 0, "output": "ficheiro copiado"}
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    if op == "get":
        path = str(p.get("src") or "")
        telemetry.audit("exec_get", "leitura de ficheiro", task_id=task["id"])
        try:
            if os.path.getsize(path) > 16 * 1024 * 1024:
                return {"status": "succeeded", "rc": 1, "output": "ficheiro maior que 16 MB"}
            return {"status": "succeeded", "rc": 0, "content_b64": base64.b64encode(open(path, "rb").read()).decode("ascii"), "output": "ficheiro lido"}
        except OSError as exc:
            return {"status": "succeeded", "rc": 1, "output": f"{exc.__class__.__name__}: {exc}"}
    return {"status": "failed", "rc": 1, "output": f"operação desconhecida: {op}"}


PENDING_ACTION: dict = {}              # ação a executar depois de o resultado da tarefa ser enviado (reiniciar / atualizar)
LAST_TRUST: dict = {}                  # confiança publicada no último contacto (oferta de atualização assinada)


def _agent_ctl(client: Client, task: dict) -> dict:
    """Comandos da consola ao próprio agente: reiniciar, atualizar, depuração, enviar registos."""
    from . import telemetry, update, config as agent_config
    p = task["payload"]
    action = str(p.get("action", ""))
    telemetry.audit("console_command", action, task_id=task["id"], requested_by=str(p.get("requested_by", ""))[:120])
    if action == "restart":
        PENDING_ACTION["restart"] = True
        return {"status": "succeeded", "output": "Reinício pedido: o agente reinicia-se depois de enviar este resultado."}
    if action == "update":
        offer = update.check(agent_config.load(), LAST_TRUST, manual=True)
        if offer:
            try:                                                   # descarrega, verifica, faz o autoteste e troca a pasta: o resultado é verdadeiro
                new = update.apply(client, offer)
            except Exception as exc:  # noqa: BLE001
                telemetry.event("operation", "error", f"Atualização pedida pela consola falhou: {exc}")
                return {"status": "failed", "output": f"Atualização para {offer['version']} falhou (mantém a versão atual): {exc}"[:2000]}
            telemetry.audit("agent_update", f"atualizado para {new} (pedido pela consola)")
            PENDING_ACTION["restart"] = True
            return {"status": "succeeded", "output": f"Agente atualizado para {new}; reinicia-se a seguir a enviar este resultado."}
        ok, why = update.can_update()
        from . import __version__
        if not LAST_TRUST.get("bundle_sig"):
            return {"status": "failed", "output": "A consola não publicou nenhum pacote de agente assinado (chave de assinatura ou pacote em falta)."}
        if not ok:
            return {"status": "failed", "output": f"Atualização não aplicável: {why}"}
        return {"status": "succeeded", "output": f"O agente já está na versão mais recente publicada pela consola ({__version__})."}
    if action in ("debug_on", "debug_off"):
        secs = int(p.get("minutes") or 60) * 60 if action == "debug_on" else 0
        telemetry.set_debug(secs)
        return {"status": "succeeded", "output": "Depuração " + (f"ativada por {secs // 60} min" if secs else "desativada")}
    if action == "logs":
        n = telemetry.flush(client)
        return {"status": "succeeded", "output": f"{n} evento(s) enviado(s) à consola"}
    return {"status": "failed", "output": f"Ação desconhecida: {action}"}


def _update_scan(client: Client, task: dict) -> dict:
    """Descobre as atualizações instaláveis e envia-as à consola (a pedido do servidor)."""
    from .updates import sync
    res = sync.run_and_upload(client, force=True)
    if not res.get("sent"):
        return {"status": "failed", "output": f"Descoberta feita ({res.get('total', 0)}), mas a consola não confirmou a receção: {res.get('error', '')}"}
    return {"status": "succeeded", "output": f"{res['total']} atualização(ões) enviada(s) e confirmadas pela consola", "total": res["total"],
            "sources": {k: {kk: vv for kk, vv in v.items() if kk in ("ok", "count")} for k, v in res.get("sources", {}).items()}}


HANDLERS = {"exec": _exec, "agent_ctl": _agent_ctl, "update_scan": _update_scan, "practice_sim": _practice_sim, "practice_apply": _practice_apply, "practice_rollback": _practice_rollback, "simulate": _simulate, "patch": _patch, "validate": _validate, "bas": _bas, "control": _control, "wake": _wake, "inventory": _inventory,
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
