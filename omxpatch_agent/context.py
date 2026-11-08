"""Contexto do ativo para a simulação de exposição — recolha **leve e só de leitura** (o processamento pesado é no servidor).

Recolhe o que é preciso para saber se uma vulnerabilidade é realmente alcançável: processos ativos, quem escuta em que porta e a
partir de que endereço (loopback / rede), serviços, estado da firewall (motor, política por omissão, portas permitidas), controlos de
acesso (administradores locais, SSH, RDP/UAC) e controlos de segurança (SELinux/AppArmor, Defender). Corre com prioridade baixa, com
limite de tempo e de itens; uma sonda que falha não impede as outras."""
from __future__ import annotations

import json
import os
import re
import shutil
import time

from .config import platform_family
from .runner import powershell, run

MAX_PROCESSES, MAX_LISTENERS, MAX_SERVICES = 300, 200, 300


def _lower_priority() -> None:
    try:
        if hasattr(os, "nice"):
            os.nice(10)
    except OSError:
        pass


def scope_of(address: str) -> str:
    """loopback | all (0.0.0.0/::) | lan (qualquer outro endereço)."""
    a = (address or "").strip("[]").lower()
    if a in ("127.0.0.1", "::1") or a.startswith("127."):
        return "loopback"
    if a in ("0.0.0.0", "::", "*", ""):  # nosec B104 - classificação de endereços de escuta, não há bind
        return "all"
    return "lan"


# --------------------------------------------------------------------------- Linux


def parse_proc_net(text: str, v6: bool = False) -> list[dict]:
    """``/proc/net/tcp[6]``: sockets em LISTEN (estado 0A) com endereço, porta e inode."""
    out = []
    for line in text.splitlines()[1:]:
        c = line.split()
        if len(c) < 10 or c[3] != "0A":
            continue
        addr_hex, port_hex = c[1].rsplit(":", 1)
        if v6:
            addr = "::" if set(addr_hex) == {"0"} else ("::1" if addr_hex == "0" * 31 + "1" or addr_hex.endswith("01000000") and set(addr_hex[:24]) == {"0"} else "lan6")
        else:
            raw = bytes.fromhex(addr_hex)[::-1]
            addr = ".".join(str(b) for b in raw)
        out.append({"port": int(port_hex, 16), "address": addr, "scope": scope_of(addr) if addr != "lan6" else "lan", "inode": c[9], "proto": "tcp6" if v6 else "tcp"})
    return out


def _proc_info(pid: str) -> dict:
    d = f"/proc/{pid}"
    try:
        name = open(f"{d}/comm").read().strip()
    except OSError:
        return {}
    uid = ""
    try:
        for line in open(f"{d}/status"):
            if line.startswith("Uid:"):
                uid = line.split()[1]
                break
    except OSError:
        pass
    try:
        exe = os.readlink(f"{d}/exe")
    except OSError:
        exe = ""
    return {"pid": int(pid), "name": name, "uid": uid, "exe": exe[:200]}


def _linux_processes_and_listeners(deadline: float) -> tuple[list, list]:
    procs, inode_pid = [], {}
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        if time.time() > deadline:
            break
        info = _proc_info(pid)
        if not info:
            continue
        procs.append(info)
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                t = os.readlink(f"/proc/{pid}/fd/{fd}")
                if t.startswith("socket:["):
                    inode_pid[t[8:-1]] = pid
        except OSError:
            continue
    names = {str(p["pid"]): p for p in procs}
    listeners = []
    for f, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            for s in parse_proc_net(open(f).read(), v6):
                p = names.get(inode_pid.get(s["inode"], ""), {})
                listeners.append({"port": s["port"], "address": s["address"], "scope": s["scope"], "proto": s["proto"], "process": p.get("name", ""), "pid": p.get("pid"),
                                  "exe": p.get("exe", "")})
        except OSError:
            continue
    return procs, listeners


def parse_ufw(text: str) -> dict:
    """``ufw status verbose``."""
    t = text.lower()
    enabled = "status: active" in t
    m = re.search(r"default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\)", t)
    allows = sorted({int(p) for p in re.findall(r"^(\d{1,5})(?:/tcp)?\s+allow\s+in", text, re.M | re.I)})
    return {"engine": "ufw", "enabled": enabled, "default_in": (m.group(1) if m else ""), "default_out": (m.group(2) if m else ""), "allow_in_ports": allows}


def parse_iptables_s(text: str) -> dict:
    """``iptables -S``: política de INPUT/OUTPUT e portas aceites."""
    pol = dict(re.findall(r"^-P (\w+) (\w+)", text, re.M))
    allows = sorted({int(p) for p in re.findall(r"-A INPUT .*?-p tcp .*?--dport (\d{1,5}) .*?-j ACCEPT", text)})
    rules = sum(1 for l in text.splitlines() if l.startswith("-A"))
    return {"engine": "iptables", "enabled": bool(rules or pol.get("INPUT", "ACCEPT") != "ACCEPT"), "default_in": pol.get("INPUT", "accept").lower(), "default_out": pol.get("OUTPUT", "accept").lower(),
            "allow_in_ports": allows, "rules": rules}


def parse_firewalld(text: str) -> dict:
    ports = sorted({int(p) for p in re.findall(r"(\d{1,5})/tcp", text)})
    return {"engine": "firewalld", "enabled": True, "default_in": "deny", "default_out": "allow", "allow_in_ports": ports,
            "services": sorted(set(re.findall(r"services:\s*(.*)", text)[0].split())) if re.findall(r"services:\s*(.*)", text) else []}


def _linux_firewall() -> dict:
    if shutil.which("ufw"):
        r = run(["ufw", "status", "verbose"], 15)
        if r.ok and "status:" in r.out.lower():
            return parse_ufw(r.out)
    if shutil.which("firewall-cmd"):
        st = run(["firewall-cmd", "--state"], 15)
        if st.ok and "running" in st.out:
            return parse_firewalld(run(["firewall-cmd", "--list-all"], 15).out)
    if shutil.which("iptables"):
        r = run(["iptables", "-S"], 15)
        if r.ok:
            return parse_iptables_s(r.out)
    if shutil.which("nft"):
        r = run(["nft", "list", "ruleset"], 15)
        if r.ok:
            return {"engine": "nftables", "enabled": bool(r.out.strip()), "default_in": "drop" if "policy drop" in r.out else "accept", "default_out": "accept",
                    "allow_in_ports": sorted({int(p) for p in re.findall(r"tcp dport (\d{1,5}) accept", r.out)})}
    return {"engine": "", "enabled": False, "default_in": "accept", "default_out": "accept", "allow_in_ports": []}


def parse_sshd(text: str) -> dict:
    d = {}
    for line in text.splitlines():
        p = line.strip().split(None, 1)
        if len(p) == 2:
            d[p[0].lower()] = p[1].strip().lower()
    return {"permit_root_login": d.get("permitrootlogin", ""), "password_auth": d.get("passwordauthentication", ""), "port": int(d["port"]) if d.get("port", "").isdigit() else 22,
            "pubkey_auth": d.get("pubkeyauthentication", ""), "permit_empty": d.get("permitemptypasswords", "")}


def _linux_access() -> dict:
    out: dict = {"admins": [], "ssh": {}}
    for grp in ("sudo", "wheel", "admin"):
        r = run(["getent", "group", grp], 10)
        if r.ok and r.out.count(":") >= 3:
            out["admins"] += [u for u in r.out.strip().split(":")[-1].split(",") if u]
    out["admins"] = sorted(set(out["admins"]))[:100]
    txt = ""
    if shutil.which("sshd") and os.geteuid() == 0:
        txt = run(["sshd", "-T"], 15).out
    elif os.path.exists("/etc/ssh/sshd_config"):
        try:
            txt = open("/etc/ssh/sshd_config", encoding="utf-8", errors="replace").read()
        except OSError:
            pass
    if txt:
        out["ssh"] = parse_sshd(txt)
    return out


def _linux_security() -> dict:
    s = {}
    if shutil.which("getenforce"):
        s["selinux"] = run(["getenforce"], 10).out.strip().lower()
    if shutil.which("aa-status"):
        s["apparmor"] = "enabled" if run(["aa-status", "--enabled"], 10).ok else "disabled"
    s["edr_processes"] = []
    return s


def _linux_services(deadline: float) -> list:
    if not shutil.which("systemctl"):
        return []
    r = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"], 30)
    return [{"name": l.split()[0].replace(".service", ""), "state": "running"} for l in r.out.splitlines() if l.split()][:MAX_SERVICES]


# --------------------------------------------------------------------------- Windows

WIN_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$procs = @{}; Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
$ls = @(Get-NetTCPConnection -State Listen | Select-Object -First 200 | ForEach-Object { [pscustomobject]@{ port = $_.LocalPort; address = $_.LocalAddress; pid = $_.OwningProcess; process = $procs[[int]$_.OwningProcess] } })
$fw = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ name = "$($_.Name)"; enabled = [bool]$_.Enabled; inbound = "$($_.DefaultInboundAction)"; outbound = "$($_.DefaultOutboundAction)" } })
$admins = @(Get-LocalGroupMember -Group Administrators | ForEach-Object { "$($_.Name)" })
$rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
$mp = Get-MpComputerStatus
$svc = @(Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 300 | ForEach-Object { $_.Name })
[pscustomobject]@{ processes = @($procs.Values | Sort-Object -Unique | Select-Object -First 300); listeners = $ls; firewall = $fw; admins = $admins; rdp_enabled = ($rdp -eq 0); uac = [bool]$uac;
  rdp_nla = ($nla -eq 1); smb1 = [bool]$smb1; defender = [pscustomobject]@{ realtime = [bool]$mp.RealTimeProtectionEnabled; av = [bool]$mp.AntivirusEnabled }; services = $svc } | ConvertTo-Json -Compress -Depth 5
"""


def parse_windows(text: str) -> dict:
    d = json.loads(text[text.index("{"):]) if "{" in text else {}
    fw = d.get("firewall") or []
    fw = fw if isinstance(fw, list) else [fw]
    enabled = any(p.get("enabled") for p in fw)
    block_in = all(str(p.get("inbound", "")).lower() in ("block", "2") for p in fw if p.get("enabled")) if enabled else False
    listeners = [{"port": int(l["port"]), "address": str(l.get("address", "")), "scope": scope_of(str(l.get("address", ""))), "proto": "tcp", "process": l.get("process") or "", "pid": l.get("pid")}
                 for l in (d.get("listeners") or []) if str(l.get("port", "")).isdigit()]
    return {"processes": [{"name": p} for p in (d.get("processes") or [])][:MAX_PROCESSES], "listeners": listeners[:MAX_LISTENERS],
            "firewall": {"engine": "windows", "enabled": enabled, "default_in": "block" if block_in else "allow", "default_out": "allow", "profiles": fw, "allow_in_ports": []},
            "access": {"admins": [a for a in (d.get("admins") or [])][:100], "rdp_enabled": bool(d.get("rdp_enabled")), "rdp_nla": bool(d.get("rdp_nla")), "uac": bool(d.get("uac")), "smb1": bool(d.get("smb1"))},
            "security": {"defender_realtime": bool((d.get("defender") or {}).get("realtime")), "defender_av": bool((d.get("defender") or {}).get("av"))},
            "services": [{"name": s, "state": "running"} for s in (d.get("services") or [])][:MAX_SERVICES]}


# --------------------------------------------------------------------------- macOS


def parse_lsof_listen(text: str) -> list[dict]:
    """``lsof -nP -iTCP -sTCP:LISTEN``: ``COMMAND PID USER … NAME`` com ``*:22`` ou ``127.0.0.1:631``."""
    out = []
    for l in text.splitlines()[1:]:
        c = l.split()
        if len(c) >= 9:
            m = re.match(r"^(.+):(\d+)$", c[8])
            if m:
                out.append({"port": int(m.group(2)), "address": m.group(1), "scope": scope_of(m.group(1).replace("*", "0.0.0.0")), "proto": "tcp", "process": c[0], "pid": int(c[1]) if c[1].isdigit() else None})  # nosec B104
    return out


def _macos() -> dict:
    ls = parse_lsof_listen(run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], 30).out)
    fw = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], 10).out.lower()
    admins = run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], 10).out.split(":")[-1].split()
    sip = "enabled" in run(["csrutil", "status"], 10).out.lower()
    return {"listeners": ls[:MAX_LISTENERS], "firewall": {"engine": "alf", "enabled": "enabled" in fw or "state = 1" in fw or "state = 2" in fw, "default_in": "block" if "block all" in fw else "allow", "default_out": "allow", "allow_in_ports": []},
            "access": {"admins": admins[:100], "ssh": {}}, "security": {"sip": sip}, "processes": [], "services": []}


# --------------------------------------------------------------------------- recolha


def collect_context(budget_s: float = 25.0) -> dict:
    """Contexto do ativo. Nunca levanta: cada parte falha isoladamente e fica registada em ``errors``."""
    _lower_priority()
    t0 = time.time()
    deadline = t0 + budget_s
    fam = platform_family()
    ctx: dict = {"platform": fam, "processes": [], "listeners": [], "services": [], "firewall": {}, "access": {}, "security": {}, "errors": []}

    def part(name, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            ctx["errors"].append(f"{name}: {type(exc).__name__}: {exc}"[:200])
            return None
    if fam == "linux":
        res = part("processos", lambda: _linux_processes_and_listeners(deadline))
        if res:
            ctx["processes"], ctx["listeners"] = res[0][:MAX_PROCESSES], res[1][:MAX_LISTENERS]
        ctx["firewall"] = part("firewall", _linux_firewall) or {}
        ctx["access"] = part("acessos", _linux_access) or {}
        ctx["security"] = part("segurança", _linux_security) or {}
        ctx["services"] = part("serviços", lambda: _linux_services(deadline)) or []
    elif fam == "windows":
        r = powershell(WIN_SCRIPT, int(budget_s) + 30)
        if r.ok:
            ctx.update(part("windows", lambda: parse_windows(r.out)) or {})
        else:
            ctx["errors"].append("windows: " + r.out.strip()[-200:])
    else:
        ctx.update(part("macos", _macos) or {})
    ctx["processes"] = [{k: p.get(k) for k in ("pid", "name", "uid", "exe") if p.get(k) not in (None, "")} for p in ctx["processes"]]
    ctx["collect_ms"] = int((time.time() - t0) * 1000)
    ctx["collected_at"] = int(t0)
    return ctx
