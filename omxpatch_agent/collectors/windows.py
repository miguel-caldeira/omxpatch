from __future__ import annotations

import os
import platform

from ..runner import powershell, run


def _reg_software() -> list[dict]:
    import winreg  # type: ignore
    items, seen = [], set()
    roots = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")]
    for hive, path in roots:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        with winreg.OpenKey(key, winreg.EnumKey(key, i)) as sub:
                            def val(n):
                                try:
                                    return str(winreg.QueryValueEx(sub, n)[0])
                                except OSError:
                                    return ""
                            name, ver = val("DisplayName"), val("DisplayVersion")
                            if name and (name, ver) not in seen and not val("SystemComponent") == "1":
                                seen.add((name, ver))
                                items.append({"name": name, "version": ver, "vendor": val("Publisher"), "source": "registry"})
                    except OSError:
                        continue
        except OSError:
            continue
    return items


def _hotfixes() -> list[str]:
    r = powershell("Get-HotFix | Select-Object -ExpandProperty HotFixID", 300)
    return sorted({l.strip().upper() for l in r.out.splitlines() if l.strip().upper().startswith("KB")})


def _reboot_pending() -> bool:
    import winreg  # type: ignore
    keys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"]
    for k in keys:
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k))
            return True
        except OSError:
            continue
    return False


def details() -> dict:
    r = powershell("(Get-CimInstance Win32_OperatingSystem).Caption", 60)
    name = r.out.strip() or f"Windows {platform.release()}"
    ports = []
    ns = run(["netstat", "-an", "-p", "tcp"], 60).out
    for line in ns.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "TCP" and parts[3] == "LISTENING":
            try:
                ports.append(int(parts[1].rsplit(":", 1)[1]))
            except ValueError:
                pass
    return {"os_name": name, "os_version": platform.version(), "hotfixes": _hotfixes(), "reboot_pending": _reboot_pending(),
            "open_ports": sorted(set(ports)), "primary_user": os.environ.get("USERNAME", "")}


def software() -> list[dict]:
    return _reg_software()
