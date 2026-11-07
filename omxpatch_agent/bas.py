"""Simulação segura de ataques (BAS): verificações benignas, sem malware nem exploração.

Cada passo devolve ``passed`` = **a defesa resistiu** (True), falhou (False) ou não é aplicável (None)."""
from __future__ import annotations

import os
import shutil
import socket
import stat
import tempfile
from pathlib import Path

from .config import platform_family
from .runner import powershell, run

EDR_SERVICES = {"windows": ["WinDefend", "Sense", "CSFalconService", "SentinelAgent", "SentinelStaticEngine", "CylanceSvc",
                            "CbDefense", "xagt", "TaniumClient", "SophosED"],
                "linux": ["falcon-sensor", "sentinelone", "mdatp", "cbagentd", "sophos-spl", "ds_agent", "wazuh-agent"],
                "macos": ["falcond", "SentinelAgent", "wdavdaemon", "com.crowdstrike", "com.sentinelone", "CylanceSvc"]}


def _r(passed, detail=""):
    return {"passed": passed, "detail": detail}


def edr_service() -> dict:
    fam = platform_family()
    names = EDR_SERVICES[fam]
    if fam == "windows":
        r = powershell("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name", 60)
        running = {l.strip().lower() for l in r.out.splitlines()}
    else:
        r = run(["ps", "-A", "-o", "comm="], 30)
        running = {l.strip().lower() for l in r.out.splitlines()}
        if fam == "linux" and shutil.which("systemctl"):
            running |= {l.split()[0].replace(".service", "").lower() for l in run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"], 30).out.splitlines() if l.split()}
    found = [n for n in names if n.lower() in running or any(n.lower() in x for x in running)]
    return _r(bool(found), ", ".join(found) if found else "nenhum serviço EDR/antivírus conhecido em execução")


def canary_encrypt() -> dict:
    """Cifra ficheiros canário num diretório temporário e verifica se foi bloqueado, revertido ou removido."""
    d = Path(tempfile.mkdtemp(prefix="omxpatch-bas-"))
    try:
        files = []
        for i in range(10):
            f = d / f"canary-{i}.txt"
            f.write_text("OMXPatch BAS canary " * 50)
            files.append(f)
        renamed = 0
        try:
            for f in files:
                data = f.read_bytes()
                f.write_bytes(bytes(b ^ 0x5A for b in data))        # transformação trivial, reversível
                f.rename(f.with_suffix(".omxbas"))
                renamed += 1
        except OSError as exc:
            return _r(True, f"operação bloqueada após {renamed} ficheiro(s): {exc.__class__.__name__}")
        remaining = len(list(d.glob("*.omxbas")))
        if remaining < len(files):
            return _r(True, f"{len(files) - remaining} ficheiro(s) removido(s)/quarentenados pelo EDR")
        return _r(False, "10 ficheiros canário cifrados e renomeados sem bloqueio nem deteção")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def shadow_copy_protection() -> dict:
    fam = platform_family()
    if fam == "windows":
        r = run(["vssadmin", "list", "shadowstorage"], 60)
        return _r(r.ok and "Used Shadow Copy Storage" in r.out, "cópias de sombra configuradas" if r.ok and "Used Shadow" in r.out else "sem armazenamento de cópias de sombra")
    if fam == "macos":
        r = run(["tmutil", "destinationinfo"], 30)
        return _r(r.ok and "Name" in r.out, "Time Machine configurado" if r.ok and "Name" in r.out else "Time Machine sem destino")
    return _r(None, "não aplicável")


def controlled_folders() -> dict:
    fam = platform_family()
    if fam == "windows":
        r = powershell("(Get-MpPreference).EnableControlledFolderAccess", 60)
        on = r.out.strip().splitlines()[-1:] == ["1"]
        return _r(on, "Controlled Folder Access " + ("ativo" if on else "desligado"))
    if fam == "linux":
        if shutil.which("getenforce"):
            mode = run(["getenforce"], 10).out.strip()
            return _r(mode == "Enforcing", f"SELinux: {mode}")
        if shutil.which("aa-status"):
            return _r(run(["aa-status", "--enabled"], 10).ok, "AppArmor")
    return _r(None, "não aplicável")


def _reach(peers: list[str], port: int, label: str) -> dict:
    if not peers:
        return _r(None, "sem pares na mesma sub-rede para testar")
    open_to = []
    for ip in peers[:8]:
        try:
            with socket.create_connection((ip, port), timeout=1.5):
                open_to.append(ip)
        except OSError:
            continue
    if open_to:
        return _r(False, f"{label} acessível a {', '.join(open_to)}")
    return _r(True, f"{label} bloqueado para os {len(peers[:8])} pares testados")


def credential_checks(step: str) -> dict:
    fam = platform_family()
    if fam == "windows":
        if step == "lsa_protection":
            r = powershell("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL", 60)
            v = r.out.strip().splitlines()[-1:] or [""]
            return _r(v[0] in ("1", "2"), f"RunAsPPL={v[0] or 'não definido'}")
        if step == "credential_guard":
            r = powershell("(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).SecurityServicesRunning -join ','", 60)
            return _r("1" in r.out.split(","), f"SecurityServicesRunning={r.out.strip()}")
        if step == "wdigest_disabled":
            r = powershell("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential", 60)
            return _r(r.out.strip() != "1", f"UseLogonCredential={r.out.strip() or 'não definido (seguro)'}")
    if fam == "linux":
        if step == "shadow_permissions":
            try:
                mode = os.stat("/etc/shadow").st_mode
                return _r(not (mode & (stat.S_IROTH | stat.S_IWOTH)), f"/etc/shadow modo {oct(mode & 0o777)}")
            except OSError as exc:
                return _r(None, str(exc))
        if step == "ptrace_scope":
            try:
                v = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip())
                return _r(v >= 1, f"ptrace_scope={v}")
            except (OSError, ValueError):
                return _r(None, "Yama não disponível")
    if step == "ssh_keys_perms" and fam in ("linux", "macos"):
        bad = []
        homes = [Path(p) for p in ("/root",)] + [p for p in Path("/home" if fam == "linux" else "/Users").glob("*")]
        for h in homes:
            for k in (h / ".ssh").glob("id_*") if (h / ".ssh").is_dir() else []:
                if not k.name.endswith(".pub") and k.stat().st_mode & 0o077:
                    bad.append(str(k))
        return _r(not bad, ("chaves com permissões abertas: " + ", ".join(bad[:3])) if bad else "chaves SSH com permissões seguras")
    if step == "sip_enabled" and fam == "macos":
        r = run(["csrutil", "status"], 30)
        return _r("enabled" in r.out.lower() and "disabled" not in r.out.lower(), r.out.strip()[:80])
    if step == "disk_encryption":
        if fam == "macos":
            r = run(["fdesetup", "status"], 30)
            return _r("On" in r.out, r.out.strip()[:80])
        if fam == "windows":
            r = run(["manage-bde", "-status", "C:"], 60)
            return _r("Protection On" in r.out, "BitLocker " + ("ativo" if "Protection On" in r.out else "inativo"))
        if fam == "linux":
            r = run(["lsblk", "-o", "TYPE", "-n"], 30)
            return _r("crypt" in r.out, "LUKS " + ("ativo" if "crypt" in r.out else "não detetado"))
    return _r(None, "não aplicável neste sistema operativo")


def service_reachable(port) -> dict:
    if not port:
        return _r(None, "sem porta associada à exposição")
    fam = platform_family()
    listening_all = False
    if fam == "linux":
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                for line in Path(f).read_text().splitlines()[1:]:
                    c = line.split()
                    if c[3] == "0A" and int(c[1].split(":")[1], 16) == int(port) and not c[1].startswith(("0100007F", "00000000000000000000000001000000")):
                        listening_all = True
            except OSError:
                continue
    else:
        r = run(["netstat", "-an"], 60)
        listening_all = any(f":{port}" in l and ("LISTEN" in l.upper()) and "127.0.0.1" not in l and "[::1]" not in l for l in r.out.splitlines())
    return _r(not listening_all, f"porta {port} " + ("em escuta em interface não-loopback" if listening_all else "sem escuta externa"))


def run_step(step: str, payload: dict) -> dict:
    peers = payload.get("peers", [])
    table = {
        "canary_encrypt": canary_encrypt, "shadow_copy_protection": shadow_copy_protection, "edr_service": edr_service,
        "controlled_folders": controlled_folders, "edr_visibility": edr_service,
        "smb_reach": lambda: _reach(peers, 445, "SMB (445)"), "rdp_reach": lambda: _reach(peers, 3389, "RDP (3389)"),
        "winrm_reach": lambda: _reach(peers, 5985, "WinRM (5985)"), "ssh_reach": lambda: _reach(peers, 22, "SSH (22)"),
        "service_reachable": lambda: service_reachable(payload.get("port")),
    }
    try:
        if step in table:
            return table[step]()
        if step in ("lsa_protection", "credential_guard", "wdigest_disabled", "shadow_permissions", "ptrace_scope",
                    "ssh_keys_perms", "sip_enabled", "disk_encryption"):
            return credential_checks(step)
    except Exception as exc:  # noqa: BLE001 - um passo com erro nunca derruba a simulação
        return _r(None, f"erro: {exc.__class__.__name__}")
    return _r(None, "passo decidido pelo servidor ou desconhecido")
