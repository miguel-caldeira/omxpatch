"""Windows: Windows Update (WUA/WSUS), winget e Chocolatey."""
from __future__ import annotations

import json
import re

from ..runner import powershell, run

WUA_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $se = $s.CreateUpdateSearcher()
  $r = $se.Search("IsInstalled=0 and IsHidden=0")
} catch {
  $hr = if ($_.Exception.HResult) { '0x{0:X8}' -f $_.Exception.HResult } else { '?' }
  Write-Output "WUA_ERROR $hr $($_.Exception.Message)"
  exit 3
}
$out = New-Object System.Collections.ArrayList
foreach ($u in $r.Updates) {
  try {
    [void]$out.Add([pscustomobject]@{ id = [string]$u.Identity.UpdateID; rev = [int]$u.Identity.RevisionNumber; title = [string]$u.Title; kb = (@($u.KBArticleIDs) -join ',');
      severity = "$($u.MsrcSeverity)"; cves = @($u.CveIDs | ForEach-Object { [string]$_ }); size = [int64]$u.MaxDownloadSize;
      reboot = ($u.InstallationBehavior.RebootBehavior -ne 0); eula = [bool]$u.EulaAccepted; categories = @($u.Categories | ForEach-Object { [string]$_.Name }) })
  } catch { }
}
$json = ConvertTo-Json -InputObject @($out.ToArray()) -Compress -Depth 4
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Output 'OMXJSON_DONE'
"""
SEV = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low", "": "medium", "unspecified": "medium"}


def _extract_json(text: str) -> str:
    """Isola o JSON entre marcadores, ignorando o ruído do PowerShell (CLIXML de progresso/erros, avisos, BOM)."""
    m = re.search(r"OMXJSON_BEGIN\s*(.*?)\s*OMXJSON_END", text, re.S)
    if m:
        return m.group(1).strip().lstrip("\ufeff")
    t = text.strip().lstrip("\ufeff")
    if t.startswith("#< CLIXML") or "<Objs" in t[:200]:
        raise RuntimeError("Windows Update: o PowerShell devolveu um erro em vez do resultado: " + re.sub(r"<[^>]+>", " ", t)[:250].strip())
    if not t:
        return ""
    i = min([k for k in (t.find("["), t.find("{")) if k >= 0], default=-1)
    if i < 0:
        raise RuntimeError("Windows Update: resposta inesperada: " + t[:200])
    return t[i:]


def parse_wua_json(text: str) -> list[dict]:
    text = _extract_json(text)
    if not text:
        return []
    data = json.loads(text)
    out = []
    for u in data if isinstance(data, list) else [data]:
        kb = (u.get("kb") or "").split(",")[0].strip()
        urls = [x for x in (u.get("urls") or []) if isinstance(x, str) and x.lower().startswith(("https://", "http://")) and len(x) <= 1000]
        cats = u.get("categories") or []
        out.append({"uid": (f"KB{kb}" if kb else u.get("id", ""))[:190], "name": u.get("title", "")[:255], "title": u.get("title", "")[:500], "kb": f"KB{kb}" if kb else "",
                    "current_version": "", "new_version": f"rev{u.get('rev', '')}", "severity": SEV.get(str(u.get("severity") or "").lower(), "medium"),
                    "category": "security" if any("security" in c.lower() for c in cats) else "update", "cves": [c for c in (u.get("cves") or []) if re.match(r"^CVE-\d{4}-\d{4,}$", c)],
                    "size_bytes": int(u.get("size") or 0), "reboot": bool(u.get("reboot")), "installer": "wua", "package": f"KB{kb}" if kb else "",
                    "download_url": urls[0] if urls else "", "sha256": "", "eula_pending": not u.get("eula", True), "origin": ", ".join(cats)[:200]})
    return out


HINTS = {"0x8024402C": "sem acesso ao Windows Update/WSUS (rede, proxy ou DNS)", "0x80244022": "serviço Windows Update/WSUS indisponível (HTTP 503)",
         "0x80240437": "chamada fora de uma sessão local", "0x80070005": "acesso negado: o agente tem de correr como SYSTEM/administrador",
         "0x8024001E": "serviço Windows Update parado", "0x80072EE2": "tempo excedido na ligação ao Windows Update/WSUS",
         "0x80072EE7": "nome do servidor Windows Update/WSUS não resolvido (DNS)", "0x8024401C": "tempo excedido na ligação ao WSUS"}


def _wua_hint(out: str) -> str:
    m = re.search(r"WUA_ERROR\s+(0x[0-9A-Fa-f]{8}|\?)\s*(.*)", out)
    if not m:
        return out.strip()[-250:]
    code = m.group(1).upper().replace("0X", "0x")
    return f"{code} — {HINTS.get(code, m.group(2).strip()[:180])}"


def scan_wua(refresh: bool = True):
    """O JSON volta por um ficheiro temporário (UTF-8): imune ao ruído do PowerShell na saída padrão (CLIXML, avisos, codificação)."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(prefix="omxwua-", suffix=".json")
    os.close(fd)
    try:
        r = powershell(f"$OutFile = '{path}'\n" + WUA_SCRIPT, 1800)
        if not r.ok:
            raise RuntimeError("Windows Update: " + _wua_hint(r.out))
        try:
            with open(path, "rb") as fh:
                raw = fh.read().decode("utf-8-sig", "replace")
        except OSError:
            raw = ""
        if not raw.strip():
            raise RuntimeError("Windows Update: o PowerShell não devolveu resultado. Saída: " + repr(r.out.strip()[:300]))
        try:
            items = parse_wua_json(raw)
        except ValueError as exc:
            raise RuntimeError(f"Windows Update: JSON inválido ({exc}). Início: {raw[:200]!r}") from exc
        return items, f"{len(items)} atualização(ões) do Windows Update"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# --------------------------------------------------------------------------- winget


def parse_winget_upgrade(text: str) -> list[dict]:
    """Tabela de ``winget upgrade``: Nome  Id  Versão  Disponível  Origem (colunas por posição do cabeçalho)."""
    lines = [l.rstrip() for l in text.splitlines()]
    hdr = next((i for i, l in enumerate(lines) if re.search(r"\bId\b", l) and re.search(r"\b(Version|Vers[aã]o)\b", l)), None)
    if hdr is None:
        return []
    h = lines[hdr]
    cols = {k: h.find(k) for k in ("Id",) if h.find(k) >= 0}
    ver = re.search(r"\b(Version|Vers[aã]o)\b", h)
    avail = re.search(r"\b(Available|Dispon[ií]vel)\b", h)
    if not ver or not avail:
        return []
    out = []
    for l in lines[hdr + 2:]:
        if not l.strip() or l.lower().startswith(("os seguintes", "the following", "pacotes", "package", "  ", "- ", "\\")) and not re.match(r"^\S", l):
            continue
        if re.match(r"^\d+ (upgrades|atualiza)", l.strip().lower()):
            break
        name, pid = l[:cols["Id"]].strip(), l[cols["Id"]:ver.start()].strip()
        cur, new = l[ver.start():avail.start()].strip(), l[avail.start():].split()[0] if l[avail.start():].split() else ""
        if pid and new and re.match(r"^[\w.+-]+$", pid):
            out.append({"name": name, "id": pid, "current": cur, "new": new})
    return out


def parse_winget_show(text: str) -> dict:
    """``winget show --id X``: URL, SHA-256 e tipo do instalador (para o servidor descarregar e verificar)."""
    g = lambda pat: (re.search(pat, text, re.I | re.M) or [None, ""])[1].strip()  # noqa: E731
    t = g(r"^\s*(?:Installer Type|Tipo de instalador)\s*:\s*(.+)$").lower()
    kind = {"msi": "msi", "wix": "msi", "exe": "exe", "inno": "exe", "nullsoft": "exe", "burn": "exe", "portable": "", "msix": "", "appx": ""}.get(t, "")
    args = {"msi": "/qn /norestart", "wix": "/qn /norestart", "inno": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART", "nullsoft": "/S", "burn": "/quiet /norestart", "exe": ""}.get(t, "")
    return {"url": g(r"^\s*(?:Installer Url|URL do instalador)\s*:\s*(\S+)"), "sha256": g(r"^\s*(?:Installer SHA256|SHA256 do instalador)\s*:\s*([0-9A-Fa-f]{64})").lower(),
            "installer": kind, "silent_args": args}


def find_winget() -> str:
    from ..sources import find_winget as fw
    return fw()


def scan_winget(refresh: bool = True):
    exe = find_winget()
    if not exe:
        return None
    r = run([exe, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"], 600)
    items = []
    for u in parse_winget_upgrade(r.out)[:60]:
        det = parse_winget_show(run([exe, "show", "--id", u["id"], "--exact", "--accept-source-agreements", "--disable-interactivity"], 120).out)
        installer = det["installer"] or "winget"
        items.append({"uid": f"{u['id']}={u['new']}", "name": u["name"] or u["id"], "title": f"{u['name']} {u['new']}", "current_version": u["current"], "new_version": u["new"],
                      "severity": "medium", "category": "application", "installer": installer, "package": u["id"], "origin": "winget",
                      "download_url": det["url"] if installer in ("msi", "exe") else "", "sha256": det["sha256"] if installer in ("msi", "exe") else "",
                      "silent_args": det["silent_args"] if installer == "exe" else "", "reboot": False})
    return items, f"{len(items)} aplicação(ões)"


# --------------------------------------------------------------------------- Chocolatey


def parse_choco_outdated(text: str) -> list[dict]:
    """``choco outdated -r``: ``nome|atual|disponível|fixado``."""
    out = []
    for l in text.splitlines():
        p = l.strip().split("|")
        if len(p) >= 3 and p[0] and re.match(r"^\d", p[1]) and (len(p) < 4 or p[3].lower() != "true"):
            out.append({"name": p[0], "current": p[1], "new": p[2]})
    return out


def find_choco() -> str:
    from ..sources import find_choco as fc
    return fc()


def scan_choco(refresh: bool = True):
    exe = find_choco()
    if not exe:
        return None
    r = run([exe, "outdated", "-r", "--no-progress"], 900)
    items = [{"uid": f"{u['name']}={u['new']}", "name": u["name"], "title": f"{u['name']} {u['new']}", "current_version": u["current"], "new_version": u["new"], "severity": "medium",
              "category": "application", "installer": "choco", "package": u["name"], "origin": "chocolatey", "download_url": "", "sha256": "", "reboot": False}
             for u in parse_choco_outdated(r.out)]
    return items, f"{len(items)} pacote(s)"


SCANNERS = [("wua", scan_wua), ("winget", scan_winget), ("choco", scan_choco)]
