"""Recolha de inventário por sistema operativo."""
from __future__ import annotations

import platform
import socket
import uuid

from ..config import platform_family


def mac_address() -> str:
    n = uuid.getnode()
    return ":".join(f"{(n >> s) & 0xff:02x}" for s in range(40, -1, -8))


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))          # não envia tráfego: só escolhe a interface de saída
            return s.getsockname()[0]
    except OSError:
        return ""


def machine_id() -> str:
    """Identificador estável do equipamento: impede que o mesmo posto reporte a duas organizações."""
    fam = platform_family()
    try:
        if fam == "linux":
            from pathlib import Path
            for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                if Path(f).is_file():
                    return Path(f).read_text().strip()
        elif fam == "macos":
            from ..runner import run
            for line in run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], 30).out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        else:
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return str(winreg.QueryValueEx(k, "MachineGuid")[0])
    except Exception:  # noqa: BLE001 - recorre ao nome e ao MAC
        pass
    return f"{socket.gethostname().lower()}-{mac_address()}"


def base_info() -> dict:
    host = socket.gethostname()
    return {"hostname": host, "fqdn": socket.getfqdn(), "ip": primary_ip(), "mac": mac_address(),
            "os_family": platform_family(), "os_name": platform.system(), "os_version": platform.release(),
            "machine_id": machine_id()}


def hardware() -> dict:
    hw = {"cpu_count": __import__("os").cpu_count(), "arch": platform.machine(), "cpu": platform.processor() or platform.machine()}
    try:
        import shutil
        hw["disk_gb"] = round(shutil.disk_usage("/").total / 2**30, 1)
    except OSError:
        pass
    try:
        import psutil  # type: ignore
        hw["ram_gb"] = round(psutil.virtual_memory().total / 2**30, 1)
    except ImportError:
        pass
    return hw


def collect() -> dict:
    fam = platform_family()
    if fam == "windows":
        from . import windows as mod
    elif fam == "macos":
        from . import macos as mod
    else:
        from . import linux as mod
    info = base_info()
    info.update(mod.details())
    info["hardware"] = {**hardware(), **info.get("hardware", {})}
    info["software"] = mod.software()
    return info
