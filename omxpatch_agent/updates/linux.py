"""Linux: apt, dnf/yum e zypper."""
from __future__ import annotations

import re
import shutil
from urllib.parse import unquote

from ..runner import run

APT_ENV = {"DEBIAN_FRONTEND": "noninteractive"}
REBOOT_HINT = ("linux-image", "linux-modules", "kernel", "glibc", "libc6", "systemd", "dbus", "linux-firmware", "microcode")


# --------------------------------------------------------------------------- apt


def parse_apt_inst(text: str) -> list[dict]:
    """``apt-get -s dist-upgrade``: ``Inst nome [antiga] (nova origem1, origem2 [arq])``."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) ([^\[)]*)", line)
        if m:
            name, old, new, origin = m.groups()
            out.append({"name": name, "old": old or "", "new": new, "origin": origin.strip().rstrip(",")})
    return out


def parse_print_uris(text: str) -> dict[str, dict]:
    """``apt-get --print-uris``: ``'url' ficheiro tamanho HASH:valor`` → {ficheiro: {url, size, hash_type, hash}}."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^'([^']+)'\s+(\S+)\s+(\d+)\s*(?:(\w+):(\w+))?", line)
        if m:
            url, fname, size, ht, hv = m.groups()
            out[unquote(fname)] = {"url": url, "size": int(size), "hash_type": (ht or "").lower(), "hash": (hv or "").lower()}
    return out


def parse_apt_show(text: str) -> dict[tuple, dict]:
    """``apt-cache show nome=versão …``: {(nome, versão): {sha256, size, filename}} (hashes do índice assinado do repositório)."""
    out = {}
    for block in re.split(r"\n\n+", text):
        f = dict(re.findall(r"^([A-Za-z0-9-]+): (.*)$", block, re.M))
        if f.get("Package") and f.get("Version"):
            out[(f["Package"], f["Version"])] = {"sha256": f.get("SHA256", "").lower(), "size": int(f.get("Size") or 0), "filename": f.get("Filename", "")}
    return out


def _arch_filename(name: str, version: str, arch: str) -> str:
    return f"{name}_{version}_{arch}.deb"


def scan_apt(refresh: bool = True):
    if not shutil.which("apt-get"):
        return None
    if refresh:
        run(["apt-get", "update", "-q"], 900, env=APT_ENV)
    sim = run(["apt-get", "-s", "dist-upgrade"], 300, env=APT_ENV)
    if sim.rc not in (0, 100):
        raise RuntimeError("apt-get -s dist-upgrade: " + sim.out.strip()[-200:])
    inst = parse_apt_inst(sim.out)
    if not inst:
        return [], "sem atualizações"
    uris = parse_print_uris(run(["apt-get", "-qq", "--print-uris", "-y", "dist-upgrade"], 300, env=APT_ENV).out)
    shown = parse_apt_show(run(["apt-cache", "show"] + [f"{i['name']}={i['new']}" for i in inst[:400]], 300).out) if shutil.which("apt-cache") else {}
    items = []
    for i in inst:
        info = shown.get((i["name"], i["new"]), {})
        uri = next((v for k, v in uris.items() if k.startswith(f"{i['name']}_{i['new'].replace(':', '%3a')}_") or k.startswith(f"{i['name']}_{i['new']}_")), None) \
            or next((v for k, v in uris.items() if k.startswith(i["name"] + "_") and unquote(i["new"]) in k), None)
        security = "-security" in i["origin"]
        sha = info.get("sha256") or (uri["hash"] if uri and uri["hash_type"] == "sha256" else "")
        items.append({"uid": f"{i['name']}={i['new']}", "name": i["name"], "title": f"{i['name']} {i['new']}", "current_version": i["old"], "new_version": i["new"],
                      "severity": "high" if security else "medium", "category": "security" if security else "update", "origin": i["origin"][:200],
                      "size_bytes": (uri or {}).get("size") or info.get("size", 0), "reboot": any(h in i["name"] for h in REBOOT_HINT),
                      "download_url": (uri or {}).get("url", ""), "sha256": sha, "installer": "apt", "package": i["name"]})
    return items, f"{len(items)} pacote(s) ({sum(1 for x in items if x['category'] == 'security')} de segurança)"


# --------------------------------------------------------------------------- dnf / yum


def parse_dnf_check_update(text: str) -> list[dict]:
    """``dnf -q check-update``: ``nome.arq  versão  repositório``."""
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) == 3 and "." in p[0] and re.match(r"^[\w.+-]+\.[\w_]+$", p[0]) and re.match(r"^\d", p[1].split(":")[-1] or "x"):
            name, arch = p[0].rsplit(".", 1)
            out.append({"name": name, "arch": arch, "new": p[1], "repo": p[2]})
    return out


def parse_dnf_updateinfo(text: str) -> dict[str, dict]:
    """``dnf -q updateinfo list --updates``: ``RHSA-2024:1234 Important/Sec. pacote-ver.arq.rpm``."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\.rpm$", line.strip())
        if m:
            adv, sev, nvra = m.groups()
            name = re.sub(r"-\d[^-]*-[^-]+\.[^.]+$", "", nvra)
            out[name] = {"advisory": adv, "severity": {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}.get(sev.split("/")[0].lower(), "medium"),
                         "security": "sec" in sev.lower()}
    return out


def _installed_rpm_versions(names: list[str]) -> dict[str, str]:
    r = run(["rpm", "-q", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"] + names[:400], 120)
    return {l.split()[0]: l.split()[1] for l in r.out.splitlines() if len(l.split()) == 2 and not l.startswith("package")}


def scan_dnf(refresh: bool = True):
    mgr = next((m for m in ("dnf", "yum") if shutil.which(m)), None)
    if not mgr:
        return None
    r = run([mgr, "-q", "check-update"] + (["--refresh"] if refresh and mgr == "dnf" else []), 900)
    if r.rc == 0:
        return [], "sem atualizações"
    if r.rc != 100:
        raise RuntimeError(f"{mgr} check-update: " + r.out.strip()[-200:])
    pk = parse_dnf_check_update(r.out)
    info = parse_dnf_updateinfo(run([mgr, "-q", "updateinfo", "list", "--updates"], 300).out)
    cur = _installed_rpm_versions([p["name"] for p in pk]) if shutil.which("rpm") else {}
    items = []
    for p in pk:
        i = info.get(p["name"], {})
        items.append({"uid": f"{p['name']}.{p['arch']}={p['new']}", "name": p["name"], "title": f"{p['name']} {p['new']}", "current_version": cur.get(p["name"], ""),
                      "new_version": p["new"], "severity": i.get("severity", "medium"), "category": "security" if i.get("security") else "update",
                      "origin": p["repo"], "advisory": i.get("advisory", ""), "reboot": any(h in p["name"] for h in REBOOT_HINT), "installer": mgr, "package": p["name"],
                      "download_url": "", "sha256": ""})
    return items, f"{len(items)} pacote(s)"


# --------------------------------------------------------------------------- zypper


def parse_zypper_lu(text: str) -> list[dict]:
    """``zypper -q lu``: tabela ``S | Repositório | Nome | Versão atual | Versão disponível | Arq``."""
    out = []
    for line in text.splitlines():
        p = [c.strip() for c in line.split("|")]
        if len(p) >= 6 and p[0] in ("v", "") and p[2] and p[2] != "Name":
            out.append({"name": p[2], "old": p[3], "new": p[4], "repo": p[1], "arch": p[5]})
    return out


def scan_zypper(refresh: bool = True):
    if not shutil.which("zypper"):
        return None
    r = run(["zypper", "--non-interactive", "-q", "lu"], 900)
    if not r.ok and r.rc != 100:
        raise RuntimeError("zypper lu: " + r.out.strip()[-200:])
    items = [{"uid": f"{u['name']}={u['new']}", "name": u["name"], "title": f"{u['name']} {u['new']}", "current_version": u["old"], "new_version": u["new"],
              "severity": "medium", "category": "update", "origin": u["repo"], "installer": "zypper", "package": u["name"], "reboot": any(h in u["name"] for h in REBOOT_HINT),
              "download_url": "", "sha256": ""} for u in parse_zypper_lu(r.out)]
    return items, f"{len(items)} pacote(s)"


SCANNERS = [("apt", scan_apt), ("dnf", scan_dnf), ("zypper", scan_zypper)]
