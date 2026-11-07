from __future__ import annotations

import os
import shutil

from ..runner import run
from . import PatchError, check_pkg


def _console_user() -> str:
    return run(["stat", "-f%Su", "/dev/console"], 10).out.strip() or os.environ.get("SUDO_USER", "")


def _brew() -> str:
    for c in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew", shutil.which("brew") or ""):
        if c and os.path.exists(c):
            return c
    raise PatchError("Homebrew não encontrado")


def apply(p: dict, download) -> dict:
    installer = p.get("installer", "softwareupdate")
    out, ok, reboot = "", False, False
    if installer == "pkg":
        path = download(".pkg")
        r = run(["installer", "-pkg", path, "-target", "/"], 3600)
        out, ok = r.out, r.ok
    elif installer == "brew" or (installer == "ansible" and p.get("package")):
        pkg = check_pkg(p.get("package") or "")
        user = _console_user()
        if not user or user == "root":
            raise PatchError("Homebrew não corre como root e não há utilizador de consola")
        r = run(["sudo", "-u", user, _brew(), "upgrade", pkg], 3600)
        out, ok = r.out, r.ok
    else:
        label = check_pkg(p.get("package") or p.get("uid") or "")
        r = run(["softwareupdate", "-i", label, "--agree-to-license"], 7200)
        out, ok = r.out, r.ok
        reboot = "restart" in r.out.lower()
    if ok and (p.get("reboot_policy") == "force" or (p.get("reboot_policy", "if_needed") == "if_needed" and reboot)):
        run(["shutdown", "-r", "+2"], 30)
        out += "\nReinício agendado para daqui a 2 minutos.\n"
    return {"status": "succeeded" if ok else "failed", "output": out, "reboot_pending": reboot}
