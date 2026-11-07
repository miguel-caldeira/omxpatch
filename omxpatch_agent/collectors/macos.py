from __future__ import annotations

import json
import os
import platform
import shutil

from ..runner import run


def details() -> dict:
    ver = run(["sw_vers", "-productVersion"], 20).out.strip() or platform.mac_ver()[0]
    name = run(["sw_vers", "-productName"], 20).out.strip() or "macOS"
    return {"os_name": name, "os_version": ver, "primary_user": os.environ.get("SUDO_USER") or os.environ.get("USER", ""),
            "reboot_pending": False, "open_ports": []}


def software() -> list[dict]:
    items: list[dict] = []
    r = run(["system_profiler", "SPApplicationsDataType", "-json"], 300)
    try:
        for app in json.loads(r.out).get("SPApplicationsDataType", []):
            if app.get("_name"):
                items.append({"name": app["_name"], "version": str(app.get("version", "")), "vendor": str(app.get("obtained_from", "")), "source": "app"})
    except ValueError:
        pass
    brew = shutil.which("brew") or ("/opt/homebrew/bin/brew" if os.path.exists("/opt/homebrew/bin/brew") else None)
    if brew:
        for line in run([brew, "list", "--versions"], 120).out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                items.append({"name": parts[0], "version": parts[-1], "source": "brew"})
    return items
