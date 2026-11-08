"""Windows: Windows Update (WUA/WSUS), winget e Chocolatey."""
from __future__ import annotations

import json
import re
import shutil

from ..runner import powershell, run

WUA_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$s = New-Object -ComObject Microsoft.Update.Session
$se = $s.CreateUpdateSearcher()
$r = $se.Search("IsInstalled=0 and IsHidden=0")
$out = @()
foreach ($u in $r.Updates) {
  $urls = @(); try { foreach ($c in $u.DownloadContents) { if ($c.DownloadUrl) { $urls += $c.DownloadUrl } } } catch {}
  $out += [pscustomobject]@{ id = $u.Identity.UpdateID; rev = $u.Identity.RevisionNumber; title = $u.Title; kb = (@($u.KBArticleIDs) -join ','); severity = "$($u.MsrcSeverity)";
    cves = @($u.CveIDs); size = [int64]$u.MaxDownloadSize; reboot = ($u.InstallationBehavior.RebootBehavior -ne 0); eula = [bool]$u.EulaAccepted;
    categories = @($u.Categories | ForEach-Object { $_.Name }); urls = $urls; released = "$($u.LastDeploymentChangeTime)" }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 5
"""
SEV = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low", "": "medium", "unspecified": "medium"}


def parse_wua_json(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    data = json.loads(text[text.index("["):] if "[" in text else text)
    out = []
    for u in data if isinstance(data, list) else [data]:
        kb = (u.get("kb") or "").split(",")[0].strip()
        urls = [x for x in (u.get("urls") or []) if isinstance(x, str) and x.lower().startswith(("https://", "http://"))]
        cats = u.get("categories") or []
        out.append({"uid": (f"KB{kb}" if kb else u.get("id", ""))[:190], "name": u.get("title", "")[:255], "title": u.get("title", "")[:500], "kb": f"KB{kb}" if kb else "",
                    "current_version": "", "new_version": f"rev{u.get('rev', '')}", "severity": SEV.get(str(u.get("severity") or "").lower(), "medium"),
                    "category": "security" if any("security" in c.lower() for c in cats) else "update", "cves": [c for c in (u.get("cves") or []) if re.match(r"^CVE-\d{4}-\d{4,}$", c)],
                    "size_bytes": int(u.get("size") or 0), "reboot": bool(u.get("reboot")), "installer": "wua", "package": f"KB{kb}" if kb else "",
                    "download_url": urls[0] if urls else "", "sha256": "", "eula_pending": not u.get("eula", True), "origin": ", ".join(cats)[:200]})
    return out


def scan_wua(refresh: bool = True):
    r = powershell(WUA_SCRIPT, 1800)
    if not r.ok:
        raise RuntimeError("Windows Update: " + r.out.strip()[-250:])
    items = parse_wua_json(r.out)
    return items, f"{len(items)} atualização(ões) do Windows Update"


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
