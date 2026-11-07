from __future__ import annotations

import os
import platform
import re
import shutil
from pathlib import Path

from ..runner import run


def _os_release() -> dict:
    out = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v.strip('"')
    except OSError:
        pass
    return out


def listening_ports() -> list[int]:
    ports = set()
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in Path(f).read_text().splitlines()[1:]:
                cols = line.split()
                if len(cols) > 3 and cols[3] == "0A":                 # LISTEN
                    ports.add(int(cols[1].split(":")[1], 16))
        except OSError:
            continue
    return sorted(ports)


def reboot_pending() -> bool:
    if Path("/var/run/reboot-required").exists():
        return True
    if shutil.which("needs-restarting"):
        return run(["needs-restarting", "-r"], 60).rc == 1
    return False


def details() -> dict:
    rel = _os_release()
    return {"os_name": rel.get("PRETTY_NAME") or rel.get("NAME") or "Linux", "os_version": rel.get("VERSION_ID") or platform.release(),
            "open_ports": listening_ports(), "reboot_pending": reboot_pending(),
            "primary_user": os.environ.get("SUDO_USER") or os.environ.get("USER", "")}


def _dpkg() -> list[dict]:
    r = run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"], 120)
    out = []
    for line in r.out.splitlines():
        if "\t" in line:
            n, v = line.split("\t", 1)
            out.append({"name": n, "version": re.sub(r"^\d+:", "", v).split("-")[0] if v else v, "source": "dpkg", "full_version": v})
    return out


def _rpm() -> list[dict]:
    r = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"], 120)
    out = []
    for line in r.out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            out.append({"name": parts[0], "version": parts[1].split("-")[0], "vendor": parts[2] if len(parts) > 2 and parts[2] != "(none)" else ""})
    return out


def _containers() -> list[dict]:
    out = []
    for engine in ("docker", "podman"):
        if shutil.which(engine):
            r = run([engine, "ps", "--format", "{{.Image}}"], 30)
            for image in sorted(set(r.out.split())):
                name, _, tag = image.rpartition(":") if ":" in image.split("/")[-1] else (image, "", "latest")
                out.append({"name": name.split("/")[-1], "version": tag.lstrip("v"), "vendor": engine, "source": "container"})
    return out


def software() -> list[dict]:
    items = _dpkg() if shutil.which("dpkg-query") else _rpm() if shutil.which("rpm") else []
    if shutil.which("snap"):
        r = run(["snap", "list"], 30)
        items += [{"name": c[0], "version": c[1], "source": "snap"} for c in (l.split() for l in r.out.splitlines()[1:]) if len(c) >= 2]
    return items + _containers()
