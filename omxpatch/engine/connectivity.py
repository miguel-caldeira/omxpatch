"""Teste de ligação sem agente a um ativo: nome, portas, autenticação e um comando real — passo a passo, com a causa e o remédio de cada falha."""
from __future__ import annotations

import socket
import time

from flask import current_app

from ..models import Asset
from ..transports import AuthError, ConnectError, TransportError
from . import ansible_engine as eng, ansible_runner


def _step(steps: list, name: str, ok: bool, detail: str = "", hint: str = "") -> bool:
    steps.append({"name": name, "ok": ok, "detail": detail, "hint": hint})
    return ok


def _tcp(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str]:
    t0 = time.time()
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True, f"aberta ({int((time.time() - t0) * 1000)} ms)"
    except socket.timeout:
        return False, "sem resposta (tempo excedido: firewall a descartar?)"
    except ConnectionRefusedError:
        return False, "recusada (serviço parado ou porta errada)"
    except OSError as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def _ports_for(conn: str, v: dict) -> list[tuple[int, str]]:
    if conn == "omx_wmi":
        return [(135, "RPC/DCOM (WMI)"), (445, "SMB (partilha administrativa)")]
    if conn == "winrm":
        return [(int(v.get("ansible_port") or 5986), "WinRM HTTPS")]
    if conn == "omx_agent":
        return []
    if conn == "local":
        return [(443, "API HTTPS")] if v.get("omx_api_token") else []
    return [(int(v.get("ansible_port") or 22), "SSH")]


def check(asset: Asset) -> dict:
    """Executa o teste (até ~1 min). Não altera nada no equipamento."""
    steps: list[dict] = []
    cfg = current_app.config
    try:
        inv = eng.build_inventory([asset])
    except Exception as exc:  # noqa: BLE001
        _step(steps, "Configuração do ativo", False, str(exc), "Corrija a credencial do ativo.")
        return {"ok": False, "transport": "?", "steps": steps}
    v = inv["all"]["hosts"][f"asset{asset.id}"]
    conn = v.get("ansible_connection") or "ssh"
    host = v.get("ansible_host") or asset.fqdn or asset.ip or asset.name
    transport = {"omx_wmi": "WMI/DCOM + SMB", "winrm": "WinRM", "ssh": "SSH", "omx_agent": "agente (procuração)", "local": "API HTTPS",
                 "ansible.netcommon.network_cli": "SSH (equipamento de rede)"}.get(conn, conn)
    problems = eng.connection_problems(asset)
    _step(steps, "Dados de ligação", not problems, f"transporte: {transport}; destino: {host}", "; ".join(problems) if problems else "")
    if problems:
        return {"ok": False, "transport": transport, "steps": steps}
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
        _step(steps, "Resolução do nome", True, ", ".join(addrs[:3]))
    except OSError as exc:
        _step(steps, "Resolução do nome", False, str(exc), "O servidor OMXPatch não resolve este nome: use o IP ou corrija o DNS/ficheiro hosts.")
        return {"ok": False, "transport": transport, "steps": steps}
    all_open = True
    for port, label in _ports_for(conn, v):
        ok, d = _tcp(host, port)
        all_open &= _step(steps, f"Porta {port} — {label}", ok, d, "" if ok else "Abra a porta na firewall do equipamento e da rede entre o servidor OMXPatch e o ativo.")
    if not all_open:
        return {"ok": False, "transport": transport, "steps": steps}
    if conn == "omx_agent":
        ok, why = eng.agent_usable(asset)
        _step(steps, "Agente como procuração", ok, "agente ativo e com permissão" if ok else why, "" if ok else why)
    elif conn == "omx_wmi":
        _wmi(steps, host, v)
    elif conn in ("ssh", "ansible.netcommon.network_cli"):
        _ssh(steps, host, v, cfg, conn)
    elif conn == "local":
        _api(steps, host, v, asset)
    else:
        _step(steps, "Autenticação", True, "WinRM: portas abertas. A autenticação é validada na primeira tarefa (use o SSH ou o WMI para um teste completo).")
    return {"ok": all(s["ok"] for s in steps), "transport": transport, "steps": steps}


def _wmi(steps, host, v):
    from ..transports.wmi import WMITransport
    t = WMITransport(host, v.get("ansible_user", ""), v.get("ansible_password", ""), domain=v.get("omx_domain", ""), timeout=20)
    try:
        t.connect()
        _step(steps, "Autenticação SMB + DCOM/WMI", True, f"conta {t.domain + chr(92) if t.domain else ''}{t.user}")
        r = t.run("ver", timeout=60)
        _step(steps, "Executar comando (WMI + partilha C$)", r.rc == 0, r.out.strip()[:160] or r.err.strip()[:160], "" if r.rc == 0 else "O processo correu mas devolveu erro.")
        try:
            rows = t.query("SELECT Caption, Version FROM Win32_OperatingSystem")
            if rows:
                _step(steps, "Consulta WMI (Win32_OperatingSystem)", True, f"{rows[0].get('Caption', '')} {rows[0].get('Version', '')}".strip())
        except TransportError as exc:
            _step(steps, "Consulta WMI (Win32_OperatingSystem)", False, str(exc), "O comando correu, mas a consulta WMI falhou (permissões WMI).")
    except (AuthError, ConnectError, TransportError) as exc:
        _step(steps, "Autenticação SMB + DCOM/WMI", False, str(exc), _wmi_hint(exc))
    finally:
        t.close()


def _wmi_hint(exc: Exception) -> str:
    low = str(exc).lower()
    if isinstance(exc, AuthError):
        return ("Use uma conta de administrador (DOMINIO\\utilizador para contas de domínio). Conta local: "
                "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f")
    if "impacket" in low:
        return "sudo /opt/omxpatch/venv/bin/omxpatch ansible-doctor --fix"
    return ("No Windows: Enable-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)','File and Printer Sharing' e confirme os serviços "
            "«Windows Management Instrumentation» e «Remote Procedure Call».")


def _ssh(steps, host, v, cfg, conn):
    from pathlib import Path

    from ..transports.ssh import SSHTransport
    user = v.get("ansible_user", "")
    key = v.get("__ssh_key__", "")
    kh = str(ansible_runner.ansible_home() / "known_hosts")
    accept = "accept-new" in str(v.get("ansible_ssh_common_args", ""))
    t = SSHTransport(host, user, password=v.get("ansible_password", ""), key_pem=key, passphrase=v.get("ansible_ssh_private_key_passphrase", ""),
                     port=int(v.get("ansible_port") or 22), known_hosts=kh, accept_new=accept, timeout=15)
    try:
        t.connect()
        _step(steps, "Autenticação SSH", True, f"{user}@{host} ({'chave' if key else 'palavra-passe'}); chaves em {Path(kh)}")
        if conn == "ssh":
            r = t.run("uname -sr; id -u", timeout=30)
            lines = r.out.strip().splitlines()
            _step(steps, "Executar comando", r.rc == 0, " · ".join(lines)[:160] or r.err.strip()[:160])
            uid0 = bool(lines) and lines[-1].strip() == "0"
            if not uid0:
                s = t.run("sudo -n true", timeout=20)
                _step(steps, "sudo sem palavra-passe", s.rc == 0, "disponível" if s.rc == 0 else "o utilizador não é root e o sudo pede palavra-passe",
                      "" if s.rc == 0 else "As atualizações precisam de root: adicione «NOPASSWD» ao sudoers do utilizador ou marque na credencial «usar a palavra-passe também para sudo».")
    except (AuthError, ConnectError, TransportError) as exc:
        _step(steps, "Autenticação SSH", False, str(exc), "Confirme o utilizador e a palavra-passe/chave; a chave do equipamento é aceite na 1.ª ligação (Sistema → Configuração).")
    finally:
        t.close()


def _api(steps, host, v, asset):
    import requests
    tok = v.get("omx_api_token", "")
    verify = bool(v.get("omx_validate_certs", True))
    if asset.platform == "fortios":
        url, hdr = f"https://{host}:{int(v.get('ansible_port') or 443)}/api/v2/monitor/system/status", {"Authorization": f"Bearer {tok}"}
    else:
        url, hdr = f"https://{host}:{int(v.get('ansible_port') or 443)}/api/?type=op&cmd=%3Cshow%3E%3Csystem%3E%3Cinfo%3E%3C%2Finfo%3E%3C%2Fsystem%3E%3C%2Fshow%3E", {"X-PAN-KEY": tok}
    try:
        r = requests.get(url, headers=hdr, timeout=15, verify=verify)
        ok = r.status_code == 200
        _step(steps, "API do equipamento", ok, f"HTTP {r.status_code}", "" if ok else "Token inválido ou sem permissão de leitura (e confirme o IP de origem permitido para o administrador da API).")
    except requests.exceptions.SSLError:
        _step(steps, "API do equipamento", False, "certificado HTTPS não confiável", "Instale a CA do equipamento no servidor OMXPatch ou, em laboratório, desative a validação do certificado.")
    except requests.RequestException as exc:
        _step(steps, "API do equipamento", False, str(exc)[:200], "Sem acesso à API: confirme o IP, a porta e o acesso administrativo HTTPS do equipamento.")
