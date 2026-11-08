"""Isolamento preventivo do ativo: corta o tráfego, mantendo **apenas** a ligação do agente à consola (e, se pedido, o SSH de IPs de gestão).

Salvaguardas: (1) a lista permitida (IPs/portas da consola) vem da configuração do próprio agente; (2) depois de aplicar, o agente testa a
ligação à consola e **desfaz tudo** se falhar (nunca se corta a si próprio); (3) tem validade (``ttl_minutes``, máx. 24 h): expirado, o
agente liberta sozinho (também se a consola ficar inacessível); (4) o estado anterior da firewall é guardado e reposto."""
from __future__ import annotations

import ipaddress
import json
import shutil
import socket
import time
from urllib.parse import urlsplit

from . import config
from .config import platform_family
from .runner import run

TABLE = "omxpatch_isolate"
WIN_RULE = "OMXPatch-isolate"
MAX_TTL = 24 * 60


class IsolationError(RuntimeError):
    pass


def _state_path():
    return config.config_dir() / "isolation.json"


def state() -> dict:
    try:
        return json.loads(_state_path().read_text())
    except (OSError, ValueError):
        return {}


def _save(st: dict) -> None:
    config.config_dir().mkdir(parents=True, exist_ok=True)
    _state_path().write_text(json.dumps(st))


def console_endpoints() -> list[tuple[str, int]]:
    """(IP, porta) da consola, resolvidos a partir do ``server_url`` do agente."""
    out = []
    for url in str(config.load().get("server_url", "")).split(","):
        u = urlsplit(url.strip())
        if not u.hostname:
            continue
        port = u.port or (443 if u.scheme == "https" else 80)
        try:
            ips = {ipaddress.ip_address(u.hostname).compressed}
        except ValueError:
            try:
                ips = {i[4][0] for i in socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)}
            except OSError:
                ips = set()
        out += [(ip, port) for ip in sorted(ips)]
    return out


def reachable(endpoints, timeout: float = 4.0) -> bool:
    for ip, port in endpoints:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _ips(values) -> list[str]:
    out = []
    for v in values or []:
        try:
            out.append(str(ipaddress.ip_address(str(v).strip())))
        except ValueError:
            raise IsolationError(f"Endereço IP inválido: {v!r}")
    return out


# --------------------------------------------------------------------------- regras por plataforma


def nft_ruleset(endpoints, keep_ssh_from) -> str:
    """Conjunto nftables: só loopback, ligações já estabelecidas, consola e (opcional) SSH de IPs de gestão."""
    def fam(ip):
        return "ip6" if ":" in ip else "ip"
    lines = [f"table inet {TABLE} {{", "  chain input { type filter hook input priority -100; policy drop;", "    iif lo accept", "    ct state established,related accept"]
    for ip in keep_ssh_from:
        lines.append(f"    {fam(ip)} saddr {ip} tcp dport 22 accept")
    lines += ["  }", "  chain output { type filter hook output priority -100; policy drop;", "    oif lo accept", "    ct state established,related accept"]
    for ip, port in endpoints:
        lines.append(f"    {fam(ip)} daddr {ip} tcp dport {port} accept")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def _linux_apply(endpoints, keep_ssh_from) -> str:
    if shutil.which("nft"):
        r = run(["nft", "-f", "-"], 30, input_text=nft_ruleset(endpoints, keep_ssh_from))
        if not r.ok:
            raise IsolationError("nft: " + r.out.strip()[-200:])
        return "nftables"
    if shutil.which("iptables"):
        cmds = [["iptables", "-N", "OMXPATCH-ISOLATE"], ["iptables", "-A", "OMXPATCH-ISOLATE", "-o", "lo", "-j", "ACCEPT"], ["iptables", "-A", "OMXPATCH-ISOLATE", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "OMXPATCH-ISOLATE", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]]
        for ip, port in endpoints:
            if ":" not in ip:
                cmds.append(["iptables", "-A", "OMXPATCH-ISOLATE", "-d", ip, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
        for ip in keep_ssh_from:
            if ":" not in ip:
                cmds.append(["iptables", "-A", "OMXPATCH-ISOLATE", "-s", ip, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])
        cmds += [["iptables", "-A", "OMXPATCH-ISOLATE", "-j", "DROP"], ["iptables", "-I", "INPUT", "1", "-j", "OMXPATCH-ISOLATE"], ["iptables", "-I", "OUTPUT", "1", "-j", "OMXPATCH-ISOLATE"]]
        for c in cmds:
            r = run(c, 30)
            if not r.ok:
                _linux_release()
                raise IsolationError("iptables: " + r.out.strip()[-200:])
        return "iptables"
    raise IsolationError("Sem nftables nem iptables neste Linux")


def _linux_release() -> None:
    if shutil.which("nft"):
        run(["nft", "delete", "table", "inet", TABLE], 30)
    if shutil.which("iptables"):
        run(["iptables", "-D", "INPUT", "-j", "OMXPATCH-ISOLATE"], 30)
        run(["iptables", "-D", "OUTPUT", "-j", "OMXPATCH-ISOLATE"], 30)
        run(["iptables", "-F", "OMXPATCH-ISOLATE"], 30)
        run(["iptables", "-X", "OMXPATCH-ISOLATE"], 30)


def _win_apply(endpoints, keep_ssh_from) -> dict:
    ips = ",".join(ip for ip, _ in endpoints)
    ports = ",".join(sorted({str(p) for _, p in endpoints}))
    ps = f"""
$ErrorActionPreference='Stop'
$saved = Get-NetFirewallProfile | ForEach-Object {{ @{{ n = "$($_.Name)"; i = "$($_.DefaultInboundAction)"; o = "$($_.DefaultOutboundAction)"; e = [bool]$_.Enabled }} }}
New-NetFirewallRule -DisplayName '{WIN_RULE}-out' -Direction Outbound -Action Allow -RemoteAddress {ips} -RemotePort {ports} -Protocol TCP | Out-Null
New-NetFirewallRule -DisplayName '{WIN_RULE}-in' -Direction Inbound -Action Allow -RemoteAddress {ips} -Protocol TCP | Out-Null
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
$saved | ConvertTo-Json -Compress
"""
    from .runner import powershell
    r = powershell(ps, 120)
    if not r.ok:
        _win_release({})
        raise IsolationError("Windows Firewall: " + r.out.strip()[-200:])
    try:
        saved = json.loads(r.out[r.out.index("["):] if "[" in r.out else r.out[r.out.index("{"):])
    except (ValueError, IndexError):
        saved = []
    return {"backend": "windows", "saved": saved if isinstance(saved, list) else [saved]}


def _win_release(st: dict) -> None:
    from .runner import powershell
    restore = ""
    for p in st.get("saved") or []:
        restore += f"Set-NetFirewallProfile -Name '{str(p.get('n', ''))[:20]}' -Enabled {'True' if p.get('e', True) else 'False'} -DefaultInboundAction {str(p.get('i', 'NotConfigured'))} -DefaultOutboundAction {str(p.get('o', 'NotConfigured'))}\n"
    powershell((restore or "Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured\n") +
               f"Remove-NetFirewallRule -DisplayName '{WIN_RULE}-out','{WIN_RULE}-in' -ErrorAction SilentlyContinue", 120)


def _mac_apply(endpoints, keep_ssh_from) -> str:
    rules = ["pass quick on lo0 all", "pass out quick proto tcp to { " + ", ".join(ip for ip, _ in endpoints) + " }"]
    rules += [f"pass in quick proto tcp from {ip} to any port 22" for ip in keep_ssh_from]
    rules += ["block drop quick all"]
    from pathlib import Path
    Path("/etc/pf.anchors/omxpatch-isolate").write_text("\n".join(rules) + "\n")
    run(["pfctl", "-E"], 30)
    r = run(["pfctl", "-a", "omxpatch-isolate", "-f", "/etc/pf.anchors/omxpatch-isolate"], 30)
    if not r.ok and "already enabled" not in r.out.lower():
        raise IsolationError("pfctl: " + r.out.strip()[-200:])
    return "pf"


def _mac_release() -> None:
    run(["pfctl", "-a", "omxpatch-isolate", "-F", "all"], 30)


# --------------------------------------------------------------------------- API


def isolate(op: dict) -> dict:
    ttl = max(5, min(int(op.get("ttl_minutes") or 120), MAX_TTL))
    keep = _ips(op.get("keep_ssh_from"))
    endpoints = [(str(ip), int(port)) for ip, port in (op.get("endpoints") or [])] or console_endpoints()      # «endpoints» só é usado pela validação em laboratório
    if not endpoints:
        raise IsolationError("Não foi possível determinar os endereços da consola: recusado (o agente cortar-se-ia a si próprio)")
    if state().get("active"):
        return {"detail": "O ativo já está isolado", "verified": True, "expires_at": state().get("expires_at")}
    fam = platform_family()
    st: dict = {"active": True, "since": time.time(), "expires_at": time.time() + ttl * 60, "ttl_minutes": ttl, "endpoints": endpoints, "keep_ssh_from": keep}
    if fam == "windows":
        st.update(_win_apply(endpoints, keep))
    elif fam == "macos":
        st["backend"] = _mac_apply(endpoints, keep)
    else:
        st["backend"] = _linux_apply(endpoints, keep)
    _save(st)
    if not reachable(endpoints):                 # a consola tem de continuar acessível: senão desfaz já
        release({})
        raise IsolationError("A consola ficou inacessível depois de isolar: isolamento desfeito automaticamente")
    return {"detail": f"Ativo isolado ({st['backend']}); só a consola está acessível. Libertação automática em {ttl} min.", "verified": True, "expires_at": st["expires_at"]}


def release(op: dict | None = None) -> dict:
    st = state()
    fam = platform_family()
    if fam == "windows":
        _win_release(st)
    elif fam == "macos":
        _mac_release()
    else:
        _linux_release()
    _save({"active": False, "released_at": time.time()})
    return {"detail": "Isolamento removido: regras anteriores repostas" if st.get("active") else "Não havia isolamento ativo (regras limpas)", "verified": True}


def expired(now: float | None = None) -> bool:
    st = state()
    return bool(st.get("active") and (now or time.time()) >= float(st.get("expires_at", 0)))


def release_if_expired() -> bool:
    """Chamado em cada ciclo do agente: o isolamento tem sempre prazo."""
    if expired():
        release({})
        return True
    return False
