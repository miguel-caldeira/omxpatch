"""Origens de atualização utilizáveis neste equipamento (deteção de capacidades).

O agente sonda o que realmente existe e funciona no contexto em que corre (normalmente SYSTEM) e envia o resultado no
inventário; o servidor só encaminha um patch para um ativo cujo instalador seja suportado (``omxpatch/engine/sources.py``).

Windows: Windows Update / WSUS (API WUA), winget, Chocolatey, MSI/MSP (msiexec), EXE silencioso, MSU (wusa), CAB (DISM) e
Office Click-to-Run. Linux: apt, dnf/yum, zypper. macOS: softwareupdate, Homebrew, installer (.pkg)."""
from __future__ import annotations

import json
import os
import shutil

from .config import platform_family
from .runner import powershell, run

WINDOWS_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$wu = Get-Service wuauserv
$wsus = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer).WUServer
$useWsus = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name UseWUServer).UseWUServer
$wg = (Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe\winget.exe" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
if (-not $wg) { $c = Get-Command winget.exe; if ($c) { $wg = $c.Source } }
$choco = "$env:ProgramData\chocolatey\bin\choco.exe"; if (-not (Test-Path $choco)) { $choco = $null }
$c2r = "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"; if (-not (Test-Path $c2r)) { $c2r = $null }
$c2rv = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -Name VersionToReport).VersionToReport
$sys32 = "$env:SystemRoot\System32"
[pscustomobject]@{
  system = $id.IsSystem; admin = $admin; ps = $PSVersionTable.PSVersion.ToString(); user = $id.Name
  wuauserv = @{ exists = [bool]$wu; status = "$($wu.Status)"; start = "$($wu.StartType)" }
  wsus = $wsus; use_wsus = $useWsus; winget = $wg; choco = $choco; c2r = $c2r; c2r_version = $c2rv
  msiexec = (Test-Path "$sys32\msiexec.exe"); wusa = (Test-Path "$sys32\wusa.exe"); dism = (Test-Path "$sys32\dism.exe")
  free_gb = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
} | ConvertTo-Json -Compress
"""


def build_windows(data: dict) -> dict:
    """Interpreta o JSON da sonda do Windows → {context, sources{id:{available, detail}}}."""
    wu = data.get("wuauserv") or {}
    wu_ok = bool(wu.get("exists")) and str(wu.get("start", "")).lower() != "disabled"
    using_wsus = bool(data.get("use_wsus")) and bool(data.get("wsus"))
    admin = bool(data.get("admin") or data.get("system"))
    src = {
        "wua": {"available": wu_ok and admin, "detail": (f"WSUS: {data['wsus']}" if using_wsus else "Microsoft Update") +
                (f"; serviço {wu.get('status', '?')}" if wu.get("exists") else "; serviço wuauserv em falta")},
        "winget": {"available": bool(data.get("winget")) and admin,
                   "detail": data.get("winget") or "winget não encontrado (App Installer ausente ou sem acesso no contexto SYSTEM)"},
        "choco": {"available": bool(data.get("choco")), "detail": data.get("choco") or "Chocolatey não instalado"},
        "msi": {"available": bool(data.get("msiexec")) and admin, "detail": "msiexec"},
        "exe": {"available": admin, "detail": "instalador EXE com argumentos silenciosos"},
        "msu": {"available": bool(data.get("wusa")) and admin, "detail": "wusa.exe"},
        "cab": {"available": bool(data.get("dism")) and admin, "detail": "dism.exe"},
        "office_c2r": {"available": bool(data.get("c2r")) and admin,
                       "detail": (f"Office Click-to-Run {data.get('c2r_version')}" if data.get("c2r") else "Office Click-to-Run não instalado")},
    }
    return {"context": {"system": bool(data.get("system")), "admin": admin, "powershell": data.get("ps"), "user": data.get("user"),
                        "free_gb": data.get("free_gb"), "wsus": data.get("wsus") if using_wsus else None},
            "sources": src}


def _which(name: str) -> str | None:
    return shutil.which(name)


def build_posix(fam: str) -> dict:
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    if fam == "linux":
        s = {"apt": ("apt-get", "apt-get"), "dnf": ("dnf", "dnf"), "yum": ("yum", "yum"), "zypper": ("zypper", "zypper"),
             "snap": ("snap", "snap")}
    else:
        s = {"softwareupdate": ("softwareupdate", "softwareupdate"), "brew": ("brew", "Homebrew"), "pkg": ("installer", "installer (.pkg)")}
    src = {k: {"available": bool(_which(b)) and root, "detail": _which(b) or f"{label} não encontrado"} for k, (b, label) in s.items()}
    if fam == "macos" and not _which("brew") and os.path.exists("/opt/homebrew/bin/brew"):
        src["brew"] = {"available": root, "detail": "/opt/homebrew/bin/brew"}
    return {"context": {"root": root}, "sources": src}


def capabilities() -> dict:
    fam = platform_family()
    if fam == "windows":
        r = powershell(WINDOWS_PROBE, 120)
        try:
            data = json.loads(r.out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"os": fam, "error": "A sonda de capacidades falhou", "context": {}, "sources": {}}
        return {"os": fam, **build_windows(data)}
    return {"os": fam, **build_posix(fam)}


def find_winget() -> str:
    """Caminho do winget (no contexto SYSTEM não está no PATH: procura em WindowsApps)."""
    import glob
    hits = sorted(glob.glob(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WindowsApps",
                                         "Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe", "winget.exe")))
    return hits[-1] if hits else (shutil.which("winget") or "winget")


def find_choco() -> str:
    p = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "chocolatey", "bin", "choco.exe")
    return p if os.path.exists(p) else (shutil.which("choco") or "choco")


def office_c2r_path() -> str:
    return os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Common Files", "Microsoft Shared", "ClickToRun", "OfficeC2RClient.exe")


__all__ = ["run"]
