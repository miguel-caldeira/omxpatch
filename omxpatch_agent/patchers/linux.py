from __future__ import annotations

import shutil
from pathlib import Path

from ..runner import run
from . import PatchError, check_pkg

APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}


def _manager() -> str:
    for m in ("apt-get", "dnf", "yum", "zypper"):
        if shutil.which(m):
            return m
    raise PatchError("Gestor de pacotes não suportado (apt, dnf, yum, zypper)")


def installed_version(pkg: str) -> str:
    if shutil.which("dpkg-query"):
        r = run(["dpkg-query", "-W", "-f", "${Version}", pkg], 60)
        return r.out.strip() if r.ok else ""
    if shutil.which("rpm"):
        r = run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg], 60)
        return r.out.strip() if r.ok else ""
    return ""


def reboot_required() -> bool:
    if Path("/var/run/reboot-required").exists():
        return True
    return bool(shutil.which("needs-restarting")) and run(["needs-restarting", "-r"], 60).rc == 1


def apply(p: dict, download) -> dict:
    pkg = check_pkg(p.get("package") or "")
    mgr = _manager()
    before = installed_version(pkg)
    out = ""
    if mgr == "apt-get":
        run(["apt-get", "update", "-q"], 900, env=APT_ENV)
        r = run(["apt-get", "install", "-y", "-q", "--only-upgrade", pkg], 3600, env=APT_ENV)
    elif mgr in ("dnf", "yum"):
        r = run([mgr, "upgrade", "-y", pkg], 3600)
    else:
        r = run(["zypper", "--non-interactive", "update", pkg], 3600)
    out += r.out
    after = installed_version(pkg)
    ok = r.ok and bool(after)
    reboot = reboot_required()
    policy = p.get("reboot_policy", "if_needed")
    if ok and ((policy == "force") or (policy == "if_needed" and reboot)):
        run(["shutdown", "-r", "+2", "OMXPatch: reinício após a atualização"], 30)
        out += "\nReinício agendado para daqui a 2 minutos.\n"
    return {"status": "succeeded" if ok else "failed", "output": out, "installed_version": after, "previous_version": before,
            "reboot_pending": reboot}
