from __future__ import annotations

import shlex

from ..runner import powershell, run
from . import SAFE_ARGS, KB_RE, PatchError, check_pkg

WUA_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$kb = '{kb}'
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$res = $searcher.Search("IsInstalled=0 and Type='Software'")
$list = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $res.Updates) {{ if ($u.KBArticleIDs -contains $kb.Replace('KB','')) {{ $list.Add($u) | Out-Null }} }}
if ($list.Count -eq 0) {{ Write-Output "NOT_APPLICABLE: $kb não aplicável ou já instalada"; exit 0 }}
$dl = $session.CreateUpdateDownloader(); $dl.Updates = $list; $dl.Download() | Out-Null
$inst = $session.CreateUpdateInstaller(); $inst.Updates = $list
$r = $inst.Install()
Write-Output "RESULT_CODE=$($r.ResultCode) REBOOT=$($r.RebootRequired)"
if ($r.ResultCode -ne 2 -and $r.ResultCode -ne 3) {{ exit 1 }}
"""


def apply(p: dict, download) -> dict:
    installer = p.get("installer", "wua")
    out, ok, reboot = "", False, False
    if installer == "wua":
        kb = (p.get("uid") or p.get("package") or "").upper()
        if not KB_RE.match(kb):
            raise PatchError(f"Identificador KB inválido: {kb!r}")
        r = powershell(WUA_SCRIPT.format(kb=kb), 7200)
        out, ok = r.out, r.ok
        reboot = "REBOOT=True" in r.out
        if "NOT_APPLICABLE" in r.out:
            ok = True                      # já instalada: a validação confirma
    elif installer == "winget" or (installer == "ansible" and p.get("package")):
        pkg = check_pkg(p.get("package") or "")
        r = run(["winget", "upgrade", "--id", pkg, "--silent", "--accept-source-agreements", "--accept-package-agreements",
                 "--disable-interactivity"], 3600)
        # 0x8A15002B (-1979842517): «sem atualização aplicável» = já está na versão corrigida
        out, ok = r.out, r.rc in (0, -1979842517, 0x8A15002B)
    elif installer in ("msi", "exe"):
        path = download(".msi" if installer == "msi" else ".exe")
        args = p.get("silent_args") or ("/qn /norestart" if installer == "msi" else "/S")
        if not SAFE_ARGS.match(args):
            raise PatchError("Argumentos silenciosos com caracteres não permitidos")
        cmd = ["msiexec", "/i", path, *shlex.split(args, posix=False)] if installer == "msi" else [path, *shlex.split(args, posix=False)]
        r = run(cmd, 7200)
        out, ok = r.out, r.rc in (0, 3010)
        reboot = r.rc == 3010
    else:
        raise PatchError(f"Instalador não suportado no Windows: {installer}")
    policy = p.get("reboot_policy", "if_needed")
    if ok and (policy == "force" or (policy == "if_needed" and reboot)):
        run(["shutdown", "/r", "/t", "120", "/c", "OMXPatch: reinício após a atualização"], 30)
        out += "\nReinício agendado para daqui a 2 minutos.\n"
    return {"status": "succeeded" if ok else "failed", "output": out, "reboot_pending": reboot}

