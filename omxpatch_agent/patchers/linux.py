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
    local = None
    if p.get("has_file") and mgr in ("apt-get", "dnf", "yum"):
        local = download(".deb" if mgr == "apt-get" else ".rpm")       # ficheiro do repositório do servidor (SHA-256 verificado)
    if local and mgr == "apt-get":
        # a partir do servidor: dpkg não valida assinaturas, por isso o SHA-256 do índice assinado do repositório é a garantia
        r = run(["apt-get", "install", "-y", "-q", "--no-install-recommends", "--allow-downgrades", local], 3600, env=APT_ENV)
    elif local:
        r = run([mgr, "install", "-y", local], 3600)                   # o rpm valida a assinatura GPG do pacote
    elif mgr == "apt-get":
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


# --------------------------------------------------------------------------- simulação (sem instalar)
REBOOT_HINT = ("linux-image", "kernel", "glibc", "libc6", "systemd", "openssl", "libssl", "dbus", "linux-firmware")


def parse_apt_sim(text: str, pkg: str) -> dict:
    """Saída de ``apt-get -s install --only-upgrade``: linhas ``Inst nome [antiga] (nova origem…)`` e ``Remv``."""
    import re
    out = {"target": None, "others": [], "removed": []}
    for line in text.splitlines():
        m = re.match(r"^Inst (\S+)(?: \[([^\]]+)\])? \(([^ )]+)", line)
        if m:
            name, old, new = m.groups()
            if name == pkg:
                out["target"] = {"old": old, "new": new}
            else:
                out["others"].append(name)
        elif line.startswith("Remv "):
            out["removed"].append(line.split()[1])
    return out


def simulate(p: dict, stage) -> dict:
    pkg = check_pkg(p.get("package") or "")
    mgr = _manager()
    checks, pred = [], {"installer": p.get("installer"), "version_before": installed_version(pkg) or None}

    def add(cid, label, status, detail=""):
        checks.append({"id": cid, "label": label, "status": status, "detail": detail})

    if not pred["version_before"]:
        pred["noop"] = True
        add("applicability", "Pacote instalado", "info", f"{pkg} não está instalado neste equipamento")
    elif p.get("has_file") and mgr == "apt-get":
        path = stage(".deb")                                                   # descarrega do servidor e confere o SHA-256
        add("package", "Pacote do servidor (SHA-256 verificado)", "ok", path)
        r = run(["apt-get", "-s", "install", "--no-install-recommends", "--allow-downgrades", path], 300, env=APT_ENV)
        d = parse_apt_sim(r.out, pkg)
        if not r.ok:
            add("applicability", "Simulação (apt-get -s do ficheiro)", "block", r.out.strip()[-200:])
        else:
            pred["version_after"] = (d["target"] or {}).get("new") or p.get("version_fixed")
            pred["changes"] = d["others"]
            add("applicability", "Simulação (apt-get -s do ficheiro)", "ok", f"{pred['version_before']} → {pred['version_after']}")
            if d["others"]:
                add("dependencies", "Outros pacotes afetados", "info", f"{len(d['others'])}: " + ", ".join(d["others"][:8]))
            if d["removed"]:
                add("removals", "Remoção de pacotes", "block", "A atualização removeria: " + ", ".join(d["removed"][:8]))
    elif mgr == "apt-get":
        r = run(["apt-get", "-s", "install", "--only-upgrade", pkg], 300, env=APT_ENV)
        d = parse_apt_sim(r.out, pkg)
        if not r.ok:
            add("applicability", "Simulação (apt-get -s)", "block", r.out.strip()[-200:])
        elif d["target"] is None:
            pred["noop"] = True
            add("applicability", "Simulação (apt-get -s)", "info", "Já está na versão mais recente disponível nos repositórios configurados")
        else:
            pred["version_after"] = d["target"]["new"]
            pred["changes"] = d["others"]
            add("applicability", "Simulação (apt-get -s)", "ok", f"{d['target']['old']} → {d['target']['new']}")
            if d["others"]:
                add("dependencies", "Outros pacotes afetados", "info", f"{len(d['others'])}: " + ", ".join(d["others"][:8]))
            if d["removed"]:
                add("removals", "Remoção de pacotes", "block", "A atualização removeria: " + ", ".join(d["removed"][:8]))
    elif mgr in ("dnf", "yum"):
        r = run([mgr, "-q", "check-update", pkg], 300)
        if r.rc == 100:
            line = next((l.split() for l in r.out.splitlines() if l.split() and l.split()[0].split(".")[0] == pkg), [])
            pred["version_after"] = line[1] if len(line) > 1 else None
            add("applicability", f"Simulação ({mgr} check-update)", "ok", f"{pred['version_before']} → {pred['version_after'] or '?'}")
        elif r.rc == 0:
            pred["noop"] = True
            add("applicability", f"Simulação ({mgr} check-update)", "info", "Já está na versão mais recente")
        else:
            add("applicability", f"Simulação ({mgr} check-update)", "block", r.out.strip()[-200:])
    else:
        r = run(["zypper", "--non-interactive", "--quiet", "update", "--dry-run", pkg], 300)
        if not r.ok:
            add("applicability", "Simulação (zypper --dry-run)", "block", r.out.strip()[-200:])
        elif "nothing to do" in r.out.lower() or not r.out.strip():
            pred["noop"] = True
            add("applicability", "Simulação (zypper --dry-run)", "info", "Nada a atualizar")
        else:
            add("applicability", "Simulação (zypper --dry-run)", "ok", r.out.strip().splitlines()[-1][:160])
    pred["reboot"] = any(h in pkg.lower() for h in REBOOT_HINT)
    return {"checks": checks, "predicted": pred}
