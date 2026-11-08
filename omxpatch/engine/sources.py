"""Origens de atualização utilizáveis: o que o instalador de um patch exige e o que cada ativo realmente suporta.

O agente sonda as capacidades do equipamento (Windows Update/WSUS, winget, Chocolatey, MSI, EXE, MSU, CAB, Office C2R;
apt/dnf/zypper; softwareupdate/brew/pkg) e envia-as no inventário (``hardware.capabilities``). Um patch só é encaminhado para
um ativo cujo instalador seja suportado; sem agente (Ansible) assume-se apenas o que os playbooks cobrem."""
from __future__ import annotations

from ..models import Asset, jloads

#: instalador → origem sondada pelo agente
INSTALLER_SOURCE = {"wua": "wua", "winget": "winget", "choco": "choco", "msi": "msi", "msp": "msi", "exe": "exe", "msu": "msu",
                    "cab": "cab", "office_c2r": "office_c2r", "apt": "apt", "dnf": "dnf", "zypper": "zypper",
                    "softwareupdate": "softwareupdate", "brew": "brew", "pkg": "pkg"}
FILE_INSTALLERS = ("msi", "msp", "exe", "msu", "cab", "pkg")
OS_INSTALLERS = {"windows": ("wua", "winget", "choco", "msi", "msp", "exe", "msu", "cab", "office_c2r"),
                 "linux": ("apt", "dnf", "zypper"), "macos": ("softwareupdate", "brew", "pkg")}

#: matriz das origens (para a página «Origens de atualização»)
WINDOWS_SOURCES = [
    {"id": "wua", "label": "Windows Update / WSUS / Microsoft Update", "installers": ["wua"], "file": False,
     "notes": "API WUA (COM) por KB; respeita a política WSUS do equipamento. Exige administrador/SYSTEM. Simulação: pesquisa sem descarregar."},
    {"id": "winget", "label": "winget (Windows Package Manager)", "installers": ["winget"], "file": False,
     "notes": "Aplicações (Chrome, Edge, Firefox, Java, Zoom, Teams, Acrobat…). No contexto SYSTEM o winget não está no PATH: o agente "
              "localiza-o em WindowsApps; alguns pacotes só instalam por utilizador. Simulação: winget list --upgrade-available."},
    {"id": "choco", "label": "Chocolatey", "installers": ["choco"], "file": False,
     "notes": "Só se o Chocolatey estiver instalado. Simulação: choco outdated."},
    {"id": "msi", "label": "MSI / MSP (msiexec)", "installers": ["msi", "msp"], "file": True,
     "notes": "Ficheiro do repositório com SHA-256. Códigos 0/3010/1641 tratados. Simulação: assinatura, propriedades do MSI, staging."},
    {"id": "exe", "label": "EXE com argumentos silenciosos", "installers": ["exe"], "file": True,
     "notes": "Requer os argumentos silenciosos do fabricante (ex.: /S, /quiet). Simulação: assinatura e staging (não há dry-run)."},
    {"id": "msu", "label": "MSU (wusa)", "installers": ["msu"], "file": True, "notes": "Atualizações descarregadas do Microsoft Update Catalog."},
    {"id": "cab", "label": "CAB (DISM)", "installers": ["cab"], "file": True, "notes": "Pacotes CAB aplicados com DISM /add-package."},
    {"id": "office_c2r", "label": "Microsoft 365 / Office Click-to-Run", "installers": ["office_c2r"], "file": False,
     "notes": "OfficeC2RClient.exe /update; o canal de atualização é o configurado no Office."},
]

#: aplicações habituais → identificadores por origem (ponto de partida; confirme sempre no seu ambiente)
APP_CATALOG = [
    {"app": "Google Chrome", "winget": "Google.Chrome", "choco": "googlechrome", "note": "MSI empresarial também disponível"},
    {"app": "Microsoft Edge", "winget": "Microsoft.Edge", "choco": "microsoft-edge", "note": "Atualiza também por Windows Update/Edge Update"},
    {"app": "Mozilla Firefox", "winget": "Mozilla.Firefox", "choco": "firefox", "note": ""},
    {"app": "Java (Temurin JRE 17)", "winget": "EclipseAdoptium.Temurin.17.JRE", "choco": "temurin17jre", "note": "Oracle Java: MSI no repositório"},
    {"app": "Zoom", "winget": "Zoom.Zoom", "choco": "zoom", "note": ""},
    {"app": "Microsoft Teams", "winget": "Microsoft.Teams", "choco": "microsoft-teams", "note": "Novo Teams é MSIX: sujeito ao contexto SYSTEM"},
    {"app": "Adobe Acrobat Reader", "winget": "Adobe.Acrobat.Reader.64-bit", "choco": "adobereader", "note": "Ou MSP do fabricante (installer msp)"},
    {"app": "OpenSSL (Win64)", "winget": "ShiningLight.OpenSSL.Light", "choco": "openssl", "note": ""},
    {"app": "Microsoft Office / 365 Apps", "winget": "", "choco": "", "note": "Instalador office_c2r"},
    {"app": "SAP GUI", "winget": "", "choco": "", "note": "Sem pacote público: MSI/EXE do fabricante no repositório (silent_args)"},
]


def capabilities_of(asset: Asset) -> dict:
    return asset.hw.get("capabilities") or {}


def check(asset: Asset, installer: str) -> tuple[bool, str]:
    """(utilizável, motivo). Ativos sem agente: aceita o que os playbooks Ansible cobrem; sem capacidades conhecidas: aceita
    (avisa na simulação) para não bloquear agentes antigos."""
    fam = asset.os_family
    if fam and installer in INSTALLER_SOURCE and installer not in OS_INSTALLERS.get(fam, ()) and installer != "ansible":
        return False, f"O instalador «{installer}» não existe em {fam}"
    caps = capabilities_of(asset)
    if not caps or not caps.get("sources"):
        return True, "capacidades do equipamento ainda desconhecidas"
    src = INSTALLER_SOURCE.get(installer)
    info = caps["sources"].get(src) if src else None
    if info is None:
        return True, ""
    if not info.get("available"):
        return False, f"Origem «{src}» indisponível neste equipamento: {info.get('detail', '')}"
    return True, ""


def matrix(assets: list[Asset]) -> list[dict]:
    """Para cada origem Windows, quantos ativos a suportam (a partir das capacidades reportadas)."""
    wins = [a for a in assets if a.os_family == "windows"]
    out = []
    for s in WINDOWS_SOURCES:
        known = [a for a in wins if capabilities_of(a).get("sources")]
        ok = [a for a in known if (capabilities_of(a)["sources"].get(s["id"]) or {}).get("available")]
        out.append({**s, "assets": len(wins), "known": len(known), "available": len(ok)})
    return out


__all__ = ["jloads"]
