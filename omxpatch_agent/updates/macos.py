"""macOS: softwareupdate e Homebrew."""
from __future__ import annotations

import json
import os
import shutil

from ..runner import run


def parse_softwareupdate(text: str) -> list[dict]:
    """``softwareupdate -l``: ``* Label: macOS Sonoma 14.5-23F79`` seguido de ``Title: …, Version: …, Size: …K, Recommended: YES, Action: restart``."""
    out, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("* Label:"):
            cur = {"label": s.split(":", 1)[1].strip(), "title": "", "version": "", "size_kb": 0, "restart": False, "recommended": False}
            out.append(cur)
        elif cur and s.startswith("Title:"):
            for part in s.split(","):
                k, _, v = part.partition(":")
                k, v = k.strip().lower(), v.strip()
                if k == "title":
                    cur["title"] = v
                elif k == "version":
                    cur["version"] = v
                elif k == "size":
                    cur["size_kb"] = int("".join(c for c in v if c.isdigit()) or 0)
                elif k == "recommended":
                    cur["recommended"] = v.upper() == "YES"
                elif k == "action":
                    cur["restart"] = "restart" in v.lower()
    return out


def scan_softwareupdate(refresh: bool = True):
    if not shutil.which("softwareupdate"):
        return None
    r = run(["softwareupdate", "-l"], 900)
    if not r.ok:
        raise RuntimeError("softwareupdate -l: " + r.out.strip()[-200:])
    items = [{"uid": u["label"], "name": u["title"] or u["label"], "title": u["label"], "current_version": "", "new_version": u["version"], "severity": "high" if u["recommended"] else "medium",
              "category": "security" if "security" in u["label"].lower() else "update", "size_bytes": u["size_kb"] * 1024, "reboot": u["restart"], "installer": "softwareupdate",
              "package": u["label"], "origin": "Apple", "download_url": "", "sha256": ""} for u in parse_softwareupdate(r.out)]
    return items, f"{len(items)} atualização(ões) do sistema"


def parse_brew_outdated(text: str) -> list[dict]:
    """``brew outdated --json=v2``."""
    data = json.loads(text[text.index("{"):]) if "{" in text else {}
    out = []
    for kind in ("formulae", "casks"):
        for p in data.get(kind, []):
            cur = p.get("installed_versions") or p.get("installed") or [""]
            out.append({"name": p.get("name", ""), "current": cur[0] if isinstance(cur, list) else str(cur), "new": p.get("current_version", ""), "cask": kind == "casks"})
    return out


def scan_brew(refresh: bool = True):
    brew = shutil.which("brew") or next((c for c in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if os.path.exists(c)), None)
    if not brew:
        return None
    r = run([brew, "outdated", "--json=v2"], 900)
    if not r.ok:
        raise RuntimeError("brew outdated: " + r.out.strip()[-200:])
    items = [{"uid": f"{p['name']}={p['new']}", "name": p["name"], "title": f"{p['name']} {p['new']}", "current_version": p["current"], "new_version": p["new"], "severity": "medium",
              "category": "application", "installer": "brew", "package": p["name"], "origin": "homebrew", "download_url": "", "sha256": "", "reboot": False}
             for p in parse_brew_outdated(r.out)]
    return items, f"{len(items)} pacote(s)"


SCANNERS = [("softwareupdate", scan_softwareupdate), ("brew", scan_brew)]
