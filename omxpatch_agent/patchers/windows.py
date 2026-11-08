"""Instalação de atualizações no Windows a partir de várias origens, e a sua simulação (dry-run).

Instaladores (``p["installer"]``): ``wua`` (Windows Update / WSUS / Microsoft Update, por KB), ``winget``, ``choco``,
``msi``, ``msp`` (patch MSI), ``exe`` (argumentos silenciosos), ``msu`` (wusa), ``cab`` (DISM) e ``office_c2r``
(Office Click-to-Run). Os de ficheiro (msi, msp, exe, msu, cab) usam o pacote do repositório do servidor, com SHA-256.
Nunca se usa shell: os argumentos são validados e passados em lista."""
from __future__ import annotations

import json
import re
import shlex

from .. import sources
from ..runner import powershell, run
from . import SAFE_ARGS, KB_RE, PatchError, check_pkg

FILE_INSTALLERS = {"msi": ".msi", "msp": ".msp", "exe": ".exe", "msu": ".msu", "cab": ".cab"}
OK_CODES = {"msi": (0, 3010, 1641, 1638), "msp": (0, 3010, 1641), "exe": (0, 3010), "msu": (0, 3010, 2359302), "cab": (0, 3010)}
REBOOT_CODES = (3010, 1641)
WINGET_NO_UPGRADE = (-1979842517, 0x8A15002B)      # 0x8A15002B: «sem atualização aplicável»

_WUA_COMMON = r"""
$ErrorActionPreference = 'Stop'
$kb = '{kb}'
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$res = $searcher.Search("IsInstalled=0 and Type='Software'")
$list = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $res.Updates) {{ if ($u.KBArticleIDs -contains $kb.Replace('KB','')) {{ $list.Add($u) | Out-Null }} }}
"""
WUA_INSTALL = _WUA_COMMON + r"""
if ($list.Count -eq 0) {{ Write-Output "NOT_APPLICABLE: $kb não aplicável ou já instalada"; exit 0 }}
$dl = $session.CreateUpdateDownloader(); $dl.Updates = $list; $dl.Download() | Out-Null
$inst = $session.CreateUpdateInstaller(); $inst.Updates = $list
$r = $inst.Install()
Write-Output "RESULT_CODE=$($r.ResultCode) REBOOT=$($r.RebootRequired)"
if ($r.ResultCode -ne 2 -and $r.ResultCode -ne 3) {{ exit 1 }}
"""
# Simulação: pesquisa sem descarregar nem instalar
WUA_SIMULATE = _WUA_COMMON + r"""
$hot = (Get-HotFix -Id $kb -ErrorAction SilentlyContinue)
$o = @{{ applicable = ($list.Count -gt 0); installed = [bool]$hot; count = $list.Count }}
if ($list.Count -gt 0) {{
  $u = $list.Item(0)
  $o.title = $u.Title; $o.size_mb = [math]::Round($u.MaxDownloadSize / 1MB, 1); $o.downloaded = [bool]$u.IsDownloaded
  $o.reboot = ($u.InstallationBehavior.RebootBehavior -ne 0); $o.eula = [bool]$u.EulaAccepted; $o.mandatory = [bool]$u.IsMandatory
}}
Write-Output ("OMXPATCH_SIM=" + ($o | ConvertTo-Json -Compress))
"""
MSI_PROPS = r"""
$ErrorActionPreference = 'Stop'
$path = '{path}'
$wi = New-Object -ComObject WindowsInstaller.Installer
$db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($path, 0))
$o = @{{}}
foreach ($p in 'ProductName', 'ProductVersion', 'Manufacturer', 'UpgradeCode') {{
  $v = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property='$p'"))
  $v.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $v, $null) | Out-Null
  $r = $v.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $v, $null)
  if ($r) {{ $o[$p] = $r.GetType().InvokeMember('StringData', 'GetProperty', $null, $r, 1) }}
}}
Write-Output ("OMXPATCH_SIM=" + ($o | ConvertTo-Json -Compress))
"""
SIGNATURE = r"""
$s = Get-AuthenticodeSignature -FilePath '{path}'
Write-Output ("OMXPATCH_SIM=" + (@{{ status = "$($s.Status)"; signer = "$($s.SignerCertificate.Subject)" }} | ConvertTo-Json -Compress))
"""


def parse_marker(text: str) -> dict | None:
    """Lê o último ``OMXPATCH_SIM={json}`` da saída de um script PowerShell."""
    found = None
    for line in text.splitlines():
        if line.startswith("OMXPATCH_SIM="):
            try:
                found = json.loads(line[len("OMXPATCH_SIM="):])
            except ValueError:
                continue
    return found


def _kb(p: dict) -> str:
    kb = (p.get("uid") or p.get("package") or "").upper()
    if not KB_RE.match(kb):
        raise PatchError(f"Identificador KB inválido: {kb!r}")
    return kb


def _args(p: dict, default: str) -> list[str]:
    args = p.get("silent_args") or default
    if not SAFE_ARGS.match(args):
        raise PatchError("Argumentos silenciosos com caracteres não permitidos")
    return shlex.split(args, posix=False)


def file_command(installer: str, path: str, p: dict) -> list[str]:
    """Linha de comandos de um instalador de ficheiro (sem shell)."""
    if installer == "msi":
        return ["msiexec", "/i", path, *_args(p, "/qn /norestart")]
    if installer == "msp":
        return ["msiexec", "/p", path, *_args(p, "/qn /norestart")]
    if installer == "exe":
        return [path, *_args(p, "/S")]
    if installer == "msu":
        return ["wusa.exe", path, "/quiet", "/norestart"]
    if installer == "cab":
        return ["dism.exe", "/online", "/add-package", f"/packagepath:{path}", "/quiet", "/norestart"]
    raise PatchError(f"Instalador de ficheiro desconhecido: {installer}")


def apply(p: dict, download) -> dict:
    installer = p.get("installer", "wua")
    if installer == "ansible" and p.get("package"):
        installer = "winget"
    out, ok, reboot = "", False, False
    if installer == "wua":
        r = powershell(WUA_INSTALL.format(kb=_kb(p)), 7200)
        out, ok = r.out, r.ok
        reboot = "REBOOT=True" in r.out
        if "NOT_APPLICABLE" in r.out:
            ok = True                      # já instalada: a validação confirma
    elif installer == "winget":
        pkg = check_pkg(p.get("package") or "")
        r = run([sources.find_winget(), "upgrade", "--id", pkg, "--silent", "--scope", "machine", "--accept-source-agreements",
                 "--accept-package-agreements", "--disable-interactivity"], 3600)
        out, ok = r.out, r.rc in (0, *WINGET_NO_UPGRADE)
    elif installer == "choco":
        pkg = check_pkg(p.get("package") or "")
        r = run([sources.find_choco(), "upgrade", pkg, "-y", "--no-progress", "--limit-output"], 3600)
        out, ok, reboot = r.out, r.rc in (0, 1641, 3010), r.rc in REBOOT_CODES
    elif installer == "office_c2r":
        r = run([sources.office_c2r_path(), "/update", "user", "displaylevel=false", "forceappshutdown=false"], 3600)
        out, ok = r.out, r.rc == 0
    elif installer in FILE_INSTALLERS:
        path = download(FILE_INSTALLERS[installer])
        r = run(file_command(installer, path, p), 7200)
        out, ok = r.out, r.rc in OK_CODES[installer]
        reboot = r.rc in REBOOT_CODES
    else:
        raise PatchError(f"Instalador não suportado no Windows: {installer}")
    policy = p.get("reboot_policy", "if_needed")
    if ok and (policy == "force" or (policy == "if_needed" and reboot)):
        run(["shutdown", "/r", "/t", "120", "/c", "OMXPatch: reinício após a atualização"], 30)
        out += "\nReinício agendado para daqui a 2 minutos.\n"
    return {"status": "succeeded" if ok else "failed", "output": out, "reboot_pending": reboot}


# --------------------------------------------------------------------------- simulação (sem instalar)


def parse_winget_upgrade(text: str, pkg: str) -> dict:
    """Saída de ``winget list --id X --upgrade-available``: {installed, available} ou {} se não houver linha do pacote.
    Independente do idioma: procura a linha com o id e lê as colunas versão / disponível / origem."""
    for line in text.splitlines():
        if pkg.lower() in line.lower():
            cols = line.split()
            idx = next((i for i, c in enumerate(cols) if c.lower() == pkg.lower()), None)
            if idx is not None and len(cols) >= idx + 3:
                rest = cols[idx + 1:]
                versions = [c for c in rest if re.match(r"^[<>~]?\d[\w.\-+]*$", c)]
                if len(versions) >= 2:
                    return {"installed": versions[0].lstrip("<>~"), "available": versions[1]}
                if versions:
                    return {"installed": versions[0].lstrip("<>~"), "available": None}
    return {}


def parse_choco_outdated(text: str, pkg: str) -> dict:
    """``choco outdated --limit-output`` → linhas ``id|atual|disponível|fixado``."""
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 3 and parts[0].lower() == pkg.lower():
            return {"installed": parts[1], "available": parts[2], "pinned": len(parts) > 3 and parts[3].lower() == "true"}
    return {}


def simulate(p: dict, stage) -> dict:
    """Dry-run do instalador: aplicabilidade, versões e reinício previstos, assinatura. Não altera o sistema.
    ``stage(suffix)`` descarrega para o *staging* (e verifica o SHA-256) os instaladores de ficheiro."""
    installer = p.get("installer", "wua")
    if installer == "ansible" and p.get("package"):
        installer = "winget"
    checks: list[dict] = []
    pred: dict = {"installer": installer}

    def add(cid, label, status, detail=""):
        checks.append({"id": cid, "label": label, "status": status, "detail": detail})

    if installer == "wua":
        kb = _kb(p)
        r = powershell(WUA_SIMULATE.format(kb=kb), 600)
        d = parse_marker(r.out)
        if d is None:
            add("applicability", "Aplicabilidade (Windows Update)", "block", "A pesquisa WUA falhou: " + r.out.strip()[-200:])
        elif d.get("installed"):
            pred["noop"] = True
            add("applicability", "Aplicabilidade (Windows Update)", "info", f"{kb} já está instalada")
        elif not d.get("applicable"):
            pred["noop"] = True
            add("applicability", "Aplicabilidade (Windows Update)", "warn", f"{kb} não é oferecida a este equipamento (não aplicável, "
                "substituída ou não aprovada no WSUS)")
        else:
            add("applicability", "Aplicabilidade (Windows Update)", "ok", d.get("title", kb))
            pred.update({"download_mb": d.get("size_mb"), "reboot": bool(d.get("reboot")), "already_downloaded": bool(d.get("downloaded"))})
            if not d.get("eula", True):
                add("eula", "Licença (EULA)", "warn", "A licença será aceite automaticamente pelo agente")
    elif installer == "winget":
        pkg = check_pkg(p.get("package") or "")
        r = run([sources.find_winget(), "list", "--id", pkg, "--exact", "--upgrade-available", "--accept-source-agreements",
                 "--disable-interactivity"], 300)
        d = parse_winget_upgrade(r.out, pkg)
        if not d:
            pred["noop"] = True
            add("applicability", "Aplicabilidade (winget)", "info", "Sem atualização disponível ou pacote não instalado")
        else:
            add("applicability", "Aplicabilidade (winget)", "ok", f"{d.get('installed')} → {d.get('available') or '?'}")
            pred.update({"version_before": d.get("installed"), "version_after": d.get("available")})
    elif installer == "choco":
        pkg = check_pkg(p.get("package") or "")
        r = run([sources.find_choco(), "outdated", "--limit-output"], 300)
        d = parse_choco_outdated(r.out, pkg)
        if not d:
            pred["noop"] = True
            add("applicability", "Aplicabilidade (Chocolatey)", "info", "Sem atualização disponível ou pacote não instalado")
        elif d.get("pinned"):
            add("applicability", "Aplicabilidade (Chocolatey)", "block", "Pacote fixado (pinned): não será atualizado")
        else:
            add("applicability", "Aplicabilidade (Chocolatey)", "ok", f"{d['installed']} → {d['available']}")
            pred.update({"version_before": d["installed"], "version_after": d["available"]})
    elif installer == "office_c2r":
        from pathlib import Path
        if not Path(sources.office_c2r_path()).exists():
            add("applicability", "Office Click-to-Run", "block", "Office Click-to-Run não instalado")
        else:
            r = powershell("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration').VersionToReport", 60)
            cur = r.out.strip().splitlines()[-1] if r.out.strip() else ""
            pred["version_before"] = cur
            fixed = p.get("version_fixed") or ""
            if fixed and cur:
                from ..versioning import compare
                if compare(cur, fixed) >= 0:
                    pred["noop"] = True
                    add("applicability", "Office Click-to-Run", "info", f"Versão {cur} já cumpre ≥ {fixed}")
                else:
                    add("applicability", "Office Click-to-Run", "ok", f"{cur} → ≥ {fixed} (canal de atualização atual)")
            else:
                add("applicability", "Office Click-to-Run", "ok", f"Versão atual {cur or '?'}")
            pred["reboot"] = False
    elif installer in FILE_INSTALLERS:
        path = stage(FILE_INSTALLERS[installer])
        add("package", "Pacote no staging (SHA-256 verificado)", "ok", path)
        s = parse_marker(powershell(SIGNATURE.format(path=path.replace("'", "''")), 120).out) or {}
        st = s.get("status", "?")
        add("signature", "Assinatura digital (Authenticode)",
            "ok" if st == "Valid" else "warn" if st in ("NotSigned", "UnknownError") else "block", f"{st} {s.get('signer', '')}".strip())
        if installer in ("msi", "msp"):
            props = parse_marker(powershell(MSI_PROPS.format(path=path.replace("'", "''")), 120).out) or {}
            if props.get("ProductVersion"):
                pred["version_after"] = props["ProductVersion"]
                add("msi_properties", "Propriedades do MSI", "info", f"{props.get('ProductName', '?')} {props['ProductVersion']} ({props.get('Manufacturer', '')})")
        if installer in ("msu", "cab"):
            kb = (p.get("uid") or "").upper()
            if KB_RE.match(kb) and kb in powershell("Get-HotFix | Select-Object -ExpandProperty HotFixID", 120).out.upper():
                pred["noop"] = True
                add("applicability", "Já instalada", "info", f"{kb} já consta nos hotfixes")
        pred["reboot"] = bool(p.get("reboot_required", installer in ("msu", "cab")))
        file_command(installer, path, p)               # valida os argumentos agora, não durante a instalação
    else:
        add("applicability", "Instalador suportado", "block", f"Instalador não suportado no Windows: {installer}")
    return {"checks": checks, "predicted": pred}
